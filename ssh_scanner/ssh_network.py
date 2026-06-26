"""
ssh_network.py
--------------
Network-wide SSH host discovery.

Instead of scanning one domain at a time, this module:
  1. Accepts CIDR ranges, IP ranges, or hostname lists
  2. Discovers which hosts have port 22 (or custom port) open
  3. Fingerprints each discovered host (banner, OS hint, device type)
  4. Returns a prioritised target list for the crypto scanner

Two discovery backends:
  - socket-based (no dependencies, slower, always available)
  - nmap-based   (faster, richer OS fingerprinting, requires nmap binary)

Usage in the pipeline:
  discover_network("192.168.1.0/24") -> [DiscoveredHost, ...]
  then feed each to scan_ssh() in scan_ssh.py
"""

from __future__ import annotations

import ipaddress
import socket
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DiscoveredHost:
    ip: str
    hostname: Optional[str] = None       # reverse DNS if resolvable
    port: int = 22
    ssh_banner: Optional[str] = None     # raw banner line
    ssh_version: Optional[str] = None    # parsed software string
    os_hint: Optional[str] = None        # "Linux", "OpenBSD", "Cisco IOS", …
    device_type: Optional[str] = None    # "server", "router", "embedded", "unknown"
    nmap_os: Optional[str] = None        # nmap OS detection string
    open: bool = True
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Device type heuristics
# ---------------------------------------------------------------------------

# Map substrings in SSH banner → device type + OS hint
_BANNER_SIGNATURES = [
    # (pattern, device_type, os_hint)
    (r"OpenSSH",                    "server",    "Linux/Unix"),
    (r"dropbear",                   "embedded",  "Linux (embedded)"),
    (r"Cisco",                      "router",    "Cisco IOS"),
    (r"RouterOS",                   "router",    "MikroTik RouterOS"),
    (r"ROSSSH",                     "router",    "MikroTik RouterOS"),
    (r"FortiSSH|FortiGate",         "firewall",  "Fortinet FortiOS"),
    (r"Juniper|JUNOS",              "router",    "Juniper JUNOS"),
    (r"Palo ?Alto",                 "firewall",  "PAN-OS"),
    (r"libssh",                     "appliance", "libssh-based device"),
    (r"babeld|github\.com",         "service",   "GitHub SSH gateway"),
    (r"GitLab",                     "service",   "GitLab SSH gateway"),
    (r"conker|bitbucket",           "service",   "Bitbucket SSH gateway"),
    (r"OpenSSH.*Windows",           "server",    "Windows"),
    (r"OpenSSH.*Ubuntu",            "server",    "Ubuntu Linux"),
    (r"OpenSSH.*Debian",            "server",    "Debian Linux"),
    (r"OpenSSH.*FreeBSD",           "server",    "FreeBSD"),
    (r"OpenSSH.*NetBSD",            "server",    "NetBSD"),
    (r"OpenSSH.*OpenBSD",           "server",    "OpenBSD"),
    (r"mod_sftp|ProFTPD",           "server",    "Linux (ProFTPD)"),
    (r"SFTP|sftp",                  "appliance", "SFTP appliance"),
    (r"WinSSHD|Bitvise",            "server",    "Windows (Bitvise)"),
    (r"paramiko",                   "service",   "Python/paramiko service"),
    (r"AsyncSSH",                   "service",   "Python/AsyncSSH service"),
    (r"Sun_SSH|SunSSH",             "server",    "Solaris"),
    (r"HP-UX SSH",                  "server",    "HP-UX"),
    (r"ACOS|A10",                   "loadbalancer","A10 Networks"),
    (r"F5",                         "loadbalancer","F5 BIG-IP"),
    (r"VMware",                     "hypervisor","VMware ESXi/vSphere"),
    (r"QNAP",                       "nas",       "QNAP NAS"),
    (r"Synology",                   "nas",       "Synology DSM"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), dt, oh) for p, dt, oh in _BANNER_SIGNATURES]


def classify_device(banner: Optional[str]) -> tuple[str, str]:
    """Return (device_type, os_hint) from SSH banner string."""
    if not banner:
        return "unknown", "unknown"
    for pattern, dtype, os_h in _COMPILED:
        if pattern.search(banner):
            return dtype, os_h
    return "unknown", "unknown"


# ---------------------------------------------------------------------------
# Single-host probe
# ---------------------------------------------------------------------------

def probe_host(ip: str, port: int = 22, timeout: float = 3.0) -> Optional[DiscoveredHost]:
    """
    Try to connect to ip:port. If successful, grab SSH banner.
    Returns None if port is closed/filtered.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner_bytes = b""
            sock.settimeout(timeout)
            try:
                while b"\n" not in banner_bytes and len(banner_bytes) < 512:
                    chunk = sock.recv(256)
                    if not chunk:
                        break
                    banner_bytes += chunk
            except socket.timeout:
                pass

            raw = banner_bytes.decode("utf-8", errors="replace").strip()
            if not raw.startswith("SSH-"):
                # Port open but not SSH (shouldn't happen on 22, but be safe)
                return None

            # Parse banner
            ssh_version = None
            m = re.match(r"SSH-\d+\.\d+-(.+)", raw)
            if m:
                ssh_version = m.group(1)

            device_type, os_hint = classify_device(raw)

            # Reverse DNS
            hostname = None
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass

            return DiscoveredHost(
                ip=ip,
                hostname=hostname,
                port=port,
                ssh_banner=raw,
                ssh_version=ssh_version,
                os_hint=os_hint,
                device_type=device_type,
                open=True,
            )
    except (ConnectionRefusedError, socket.timeout, OSError):
        return None
    except Exception as exc:
        logger.debug("Probe error %s:%d — %s", ip, port, exc)
        return None


# ---------------------------------------------------------------------------
# CIDR / range expansion
# ---------------------------------------------------------------------------

def expand_targets(target: str) -> list[str]:
    """
    Accept various input formats and return a flat list of IP strings.

    Formats:
      "192.168.1.0/24"           → 254 IPs
      "192.168.1.1-192.168.1.50" → 50 IPs
      "10.0.0.1,10.0.0.5"       → 2 IPs
      "github.com"               → resolved IP
      "192.168.1.1"              → 1 IP
    """
    targets: list[str] = []
    parts = [p.strip() for p in target.split(",") if p.strip()]

    for part in parts:
        # CIDR
        if "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                # Skip network + broadcast for /24 and smaller; include all for /31, /32
                if net.prefixlen >= 31:
                    targets.extend(str(ip) for ip in net.hosts() or list(net))
                else:
                    targets.extend(str(ip) for ip in net.hosts())
                continue
            except ValueError:
                pass

        # IP range a.b.c.d-a.b.c.e
        if "-" in part:
            try:
                start_s, end_s = part.split("-", 1)
                start = ipaddress.ip_address(start_s.strip())
                end = ipaddress.ip_address(end_s.strip())
                current = start
                while current <= end:
                    targets.append(str(current))
                    current += 1
                continue
            except ValueError:
                pass

        # Single IP
        try:
            ipaddress.ip_address(part)
            targets.append(part)
            continue
        except ValueError:
            pass

        # Hostname → resolve to IP
        try:
            ip = socket.gethostbyname(part)
            targets.append(ip)
        except socket.gaierror:
            logger.warning("Cannot resolve: %s", part)

    return targets


# ---------------------------------------------------------------------------
# Main discovery entry point
# ---------------------------------------------------------------------------

def discover_network(
    target: str,
    port: int = 22,
    timeout: float = 3.0,
    max_workers: int = 100,
    max_hosts: int = 65536,
) -> list[DiscoveredHost]:
    """
    Discover SSH-speaking hosts in a network range.

    Args:
        target      : CIDR, IP range, comma-separated IPs, or hostname
        port        : SSH port to probe (default 22)
        timeout     : per-host connection timeout
        max_workers : concurrent probes
        max_hosts   : safety cap — refuse to scan more than this many IPs

    Returns:
        List of DiscoveredHost for every host with port open and SSH banner.
    """
    ips = expand_targets(target)

    if not ips:
        logger.warning("No IPs resolved from target: %s", target)
        return []

    if len(ips) > max_hosts:
        raise ValueError(
            f"Target resolves to {len(ips)} IPs which exceeds the safety cap of {max_hosts}. "
            f"Use a smaller CIDR or increase max_hosts."
        )

    logger.info("Probing %d IPs on port %d (workers=%d)", len(ips), port, max_workers)

    discovered: list[DiscoveredHost] = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(ips))) as executor:
        futures = {executor.submit(probe_host, ip, port, timeout): ip for ip in ips}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                discovered.append(result)

    # Sort by IP for deterministic output
    discovered.sort(key=lambda h: ipaddress.ip_address(h.ip))
    logger.info("Discovery complete: %d SSH hosts found out of %d probed", len(discovered), len(ips))
    return discovered


def discover_network_bulk(
    targets: list[str],
    port: int = 22,
    timeout: float = 3.0,
    max_workers: int = 100,
) -> list[DiscoveredHost]:
    """Discover across multiple independent target specs."""
    all_hosts: list[DiscoveredHost] = []
    seen_ips: set[str] = set()
    for target in targets:
        try:
            hosts = discover_network(target, port, timeout, max_workers)
            for h in hosts:
                if h.ip not in seen_ips:
                    seen_ips.add(h.ip)
                    all_hosts.append(h)
        except Exception as exc:
            logger.error("Discovery failed for %s: %s", target, exc)
    return all_hosts


# ---------------------------------------------------------------------------
# Nmap-enhanced discovery (optional, richer)
# ---------------------------------------------------------------------------

def discover_with_nmap(
    target: str,
    port: int = 22,
    os_detect: bool = False,
) -> list[DiscoveredHost]:
    """
    Use python-nmap for richer discovery.
    Requires nmap binary: `brew install nmap` / `apt install nmap`

    os_detect=True requires nmap to run as root (uses -O flag).
    Falls back to socket discovery if nmap is unavailable.
    """
    try:
        import nmap
    except ImportError:
        logger.warning("python-nmap not installed, falling back to socket discovery")
        return discover_network(target, port)

    try:
        nm = nmap.PortScanner()
        args = f"-p {port} --open -sV"
        if os_detect:
            args += " -O"
        nm.scan(hosts=target, arguments=args)
    except Exception as exc:
        logger.warning("nmap scan failed (%s), falling back to socket discovery", exc)
        return discover_network(target, port)

    discovered: list[DiscoveredHost] = []
    for host_ip in nm.all_hosts():
        try:
            host = nm[host_ip]
            if host.state() != "up":
                continue
            tcp = host.get("tcp", {})
            if port not in tcp:
                continue
            port_info = tcp[port]
            if port_info.get("state") != "open":
                continue

            banner = port_info.get("extrainfo", "") or port_info.get("product", "")
            version = port_info.get("version", "")
            full_banner = f"{port_info.get('product','')} {version}".strip() or banner

            device_type, os_hint = classify_device(full_banner or banner)

            # Try nmap OS detection
            nmap_os = None
            osmatch = host.get("osmatch", [])
            if osmatch:
                nmap_os = osmatch[0].get("name")
                if not os_hint or os_hint == "unknown":
                    os_hint = nmap_os

            hostname = None
            hostnames = host.get("hostnames", [])
            if hostnames:
                hostname = hostnames[0].get("name")

            discovered.append(DiscoveredHost(
                ip=host_ip,
                hostname=hostname,
                port=port,
                ssh_banner=full_banner or None,
                ssh_version=version or None,
                os_hint=os_hint,
                device_type=device_type,
                nmap_os=nmap_os,
                open=True,
            ))
        except Exception as exc:
            logger.debug("Error processing nmap result for %s: %s", host_ip, exc)

    return discovered
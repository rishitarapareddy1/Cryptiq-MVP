"""
scan_ssh.py
-----------
SSH cryptographic asset discovery module.
Connects to SSH endpoints and extracts:
  - SSH banner / server version
  - Host key algorithms + key sizes
  - Supported key exchange algorithms
  - Supported ciphers
  - Supported MACs
  - Compression support

Mirrors the TLS scanner pipeline:
  discover → extract crypto assets → classify → score → CBOM → DB
"""

import socket
import re
import logging
from dataclasses import dataclass, field
from typing import Optional

import paramiko
from paramiko.transport import Transport
from ssh_scanner.ssh_versions import parse_banner, analyse_capability_gap

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SSHHostKey:
    algorithm: str          # e.g. "ssh-rsa", "ssh-ed25519"
    key_size: Optional[int] # bits; None for fixed-size keys (Ed25519)
    fingerprint: Optional[str] = None  # SHA-256 fingerprint


@dataclass
class SSHScanResult:
    host: str
    port: int

    # Server identity
    ssh_version: Optional[str] = None          # e.g. "OpenSSH_9.7"
    ssh_protocol: Optional[str] = None         # e.g. "2.0"
    raw_banner: Optional[str] = None           # full banner string

    # Crypto assets
    host_keys: list[SSHHostKey] = field(default_factory=list)

    # Negotiated algorithms (what was actually selected for this session)
    negotiated_kex: Optional[str] = None
    negotiated_cipher: Optional[str] = None
    negotiated_mac: Optional[str] = None

    # Full advertised lists (server's capability advertisement)
    server_kex_algorithms: list[str] = field(default_factory=list)
    server_ciphers: list[str] = field(default_factory=list)
    server_macs: list[str] = field(default_factory=list)
    server_host_key_algorithms: list[str] = field(default_factory=list)
    server_compression: list[str] = field(default_factory=list)

    # Software version analysis
    software_info: Optional[dict] = None       # SoftwareInfo.to_dict()
    capability_gap: Optional[dict] = None      # analyse_capability_gap() result

    # Scan metadata
    scan_error: Optional[str] = None
    scan_success: bool = False


# ---------------------------------------------------------------------------
# Banner extraction
# ---------------------------------------------------------------------------

def get_ssh_banner(host: str, port: int = 22, timeout: float = 10.0) -> dict:
    """
    Connect to host:port and read the raw SSH banner line.

    Returns dict with:
        raw_banner   : "SSH-2.0-OpenSSH_9.7p1 Ubuntu-3ubuntu0.6"
        ssh_protocol : "2.0"
        ssh_version  : "OpenSSH_9.7p1 Ubuntu-3ubuntu0.6"
    """
    result = {"raw_banner": None, "ssh_protocol": None, "ssh_version": None}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner_bytes = b""
            while b"\n" not in banner_bytes:
                chunk = sock.recv(256)
                if not chunk:
                    break
                banner_bytes += chunk
            raw = banner_bytes.decode("utf-8", errors="replace").strip()
            result["raw_banner"] = raw
            # SSH-<proto>-<software comment>
            m = re.match(r"SSH-(\d+\.\d+)-(.+)", raw)
            if m:
                result["ssh_protocol"] = m.group(1)
                result["ssh_version"] = m.group(2)
    except Exception as exc:
        logger.debug("Banner grab failed for %s:%d — %s", host, port, exc)
    return result


# ---------------------------------------------------------------------------
# Host key extraction
# ---------------------------------------------------------------------------

def _key_size(key) -> Optional[int]:
    """
    Extract bit-length from a paramiko key object.
    Returns None for fixed-size keys (Ed25519, Ed448).
    """
    try:
        if hasattr(key, "key"):
            inner = key.key
            # RSA
            if hasattr(inner, "key_size"):
                return inner.key_size
            # DSA / ECDSA via cryptography primitives
            pub = inner.public_key() if hasattr(inner, "public_key") else None
            if pub is None:
                return None
            from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
            if isinstance(pub, rsa.RSAPublicKey):
                return pub.key_size
            if isinstance(pub, dsa.DSAPublicKey):
                return pub.key_size
            if isinstance(pub, ec.EllipticCurvePublicKey):
                return pub.key_size
    except Exception:
        pass
    return None


def get_host_keys(host: str, port: int = 22, timeout: float = 10.0) -> list[SSHHostKey]:
    """
    Connect and collect all host keys advertised by the server.

    Paramiko's Transport negotiates the session; we inspect which host key
    algorithm was selected and capture the key object for size/fingerprint.
    """
    host_keys: list[SSHHostKey] = []

    # We iterate over the key types paramiko supports to collect everything
    # the server will offer (by re-connecting with each preferred type).
    # This mirrors how ssh-keyscan works.
    key_types = [
        "ssh-rsa",
        "rsa-sha2-256",
        "rsa-sha2-512",
        "ssh-dss",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "ssh-ed25519",
    ]

    seen_fingerprints = set()

    for ktype in key_types:
        transport = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            transport = Transport(sock)
            transport.local_version = "SSH-2.0-CryptiqScanner_1.0"
            # Enable all legacy KEX/cipher so we can handshake with old servers
            transport._preferred_kex = [
                "diffie-hellman-group1-sha1",
                "diffie-hellman-group14-sha1",
                "diffie-hellman-group14-sha256",
                "curve25519-sha256",
                "curve25519-sha256@libssh.org",
                "ecdh-sha2-nistp256",
            ]
            transport._preferred_ciphers = [
                "aes128-ctr", "aes256-ctr", "aes128-cbc",
                "aes256-cbc", "3des-cbc",
                "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
                "chacha20-poly1305@openssh.com",
            ]
            transport._preferred_macs = [
                "hmac-md5", "hmac-sha1",
                "hmac-sha2-256", "hmac-sha2-256-etm@openssh.com",
            ]
            # Request a specific host key type
            transport._preferred_keys = [ktype]
            transport.start_client(timeout=timeout)

            host_key = transport.get_remote_server_key()
            if host_key is None:
                continue

            import base64, hashlib
            key_bytes = host_key.asbytes()
            fp = "SHA256:" + base64.b64encode(
                hashlib.sha256(key_bytes).digest()
            ).decode().rstrip("=")

            if fp in seen_fingerprints:
                continue
            seen_fingerprints.add(fp)

            host_keys.append(SSHHostKey(
                algorithm=host_key.get_name(),
                key_size=_key_size(host_key),
                fingerprint=fp,
            ))

        except Exception as exc:
            logger.debug("Host key fetch (%s) for %s:%d — %s", ktype, host, port, exc)
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass

    return host_keys


# ---------------------------------------------------------------------------
# Algorithm advertisement extraction
# ---------------------------------------------------------------------------

def get_server_algorithms(
    host: str, port: int = 22, timeout: float = 10.0
) -> dict:
    """
    Read the server's SSH KEX_INIT packet directly over a raw socket.

    The KEX_INIT is sent in PLAINTEXT before any encryption is negotiated
    (RFC 4253 §7.1). This means we never need to complete the handshake —
    we just need to:
      1. Connect
      2. Exchange banners (also plaintext)
      3. Read the server's KEX_INIT binary packet
      4. Parse the name-list fields

    This approach is completely immune to algorithm incompatibility errors
    because we never attempt to negotiate — we just read what the server
    advertises and disconnect.
    """
    result = {
        "kex_algorithms": [],
        "server_host_key_algorithms": [],
        "ciphers": [],
        "macs": [],
        "compression": [],
        "negotiated_kex": None,
        "negotiated_cipher": None,
        "negotiated_mac": None,
    }

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)

        # ── Step 1: Read server banner ──────────────────────────────────
        banner_buf = b""
        while b"\n" not in banner_buf and len(banner_buf) < 512:
            chunk = sock.recv(64)
            if not chunk:
                break
            banner_buf += chunk

        # ── Step 2: Send our banner ─────────────────────────────────────
        sock.sendall(b"SSH-2.0-CryptiqScanner_1.0\r\n")

        # ── Step 3: Read SSH binary packets until we get KEX_INIT (20) ──
        # SSH binary packet format (RFC 4253 §6):
        #   uint32   packet_length   (length of payload + padding, not including itself)
        #   byte     padding_length
        #   byte[n]  payload         (n = packet_length - padding_length - 1)
        #   byte[m]  random padding  (m = padding_length)
        # No MAC yet (not yet negotiated)

        SSH_MSG_KEXINIT = 20
        max_attempts = 5  # read up to 5 packets looking for KEX_INIT

        for _ in range(max_attempts):
            # Read 4-byte packet length
            length_bytes = _recv_exact(sock, 4)
            if not length_bytes or len(length_bytes) < 4:
                break
            packet_length = int.from_bytes(length_bytes, "big")

            if packet_length > 65536 or packet_length < 2:
                break  # sanity check

            # Read rest of packet
            rest = _recv_exact(sock, packet_length)
            if not rest or len(rest) < packet_length:
                break

            padding_length = rest[0]
            payload = rest[1: packet_length - padding_length]

            if not payload:
                continue

            msg_type = payload[0]
            if msg_type == SSH_MSG_KEXINIT:
                # Parse KEX_INIT payload
                # Skip: msg_type(1) + cookie(16) = 17 bytes
                offset = 17
                lists = []
                for _ in range(10):  # 10 name-list fields in KEX_INIT
                    if offset + 4 > len(payload):
                        break
                    list_len = int.from_bytes(payload[offset:offset+4], "big")
                    offset += 4
                    if offset + list_len > len(payload):
                        break
                    name_list_bytes = payload[offset:offset+list_len]
                    offset += list_len
                    names = [
                        n.strip().decode("utf-8", errors="replace")
                        for n in name_list_bytes.split(b",")
                        if n.strip()
                    ]
                    lists.append(names)

                if len(lists) >= 6:
                    result["kex_algorithms"]              = lists[0]
                    result["server_host_key_algorithms"]  = lists[1]
                    # Merge client→server and server→client (union)
                    result["ciphers"] = list(dict.fromkeys(lists[2] + lists[3]))
                    result["macs"]    = list(dict.fromkeys(lists[4] + lists[5]))
                if len(lists) >= 8:
                    result["compression"] = list(dict.fromkeys(lists[6] + lists[7]))
                break  # done

        sock.close()

    except Exception as exc:
        logger.debug("Raw KEX_INIT read for %s:%d — %s", host, port, exc)

    return result


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from socket."""
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except Exception:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _estimate_key_size(algorithm: str) -> Optional[int]:
    """
    Estimate key size from algorithm name when we can't complete the handshake.
    Returns None for fixed-size algorithms (Ed25519, Ed448).
    """
    a = algorithm.lower()
    if "rsa" in a:
        return None   # unknown without handshake — caller can leave as None
    if "ecdsa" in a:
        if "nistp256" in a:
            return 256
        if "nistp384" in a:
            return 384
        if "nistp521" in a:
            return 521
    # Ed25519, Ed448, DSA — fixed size, return None
    return None



def scan_ssh(host: str, port: int = 22, timeout: float = 10.0) -> SSHScanResult:
    """
    Full SSH crypto asset discovery for a single host.

    Pipeline:
        1. Banner grab  → server identity
        2. Host key collection  → key algorithms + sizes
        3. Algorithm advertisement extraction  → KEX, cipher, MAC lists
    """
    result = SSHScanResult(host=host, port=port)

    # 1. Banner
    banner_info = get_ssh_banner(host, port, timeout)
    result.raw_banner = banner_info["raw_banner"]
    result.ssh_protocol = banner_info["ssh_protocol"]
    result.ssh_version = banner_info["ssh_version"]

    if result.raw_banner is None:
        result.scan_error = "Could not connect or read SSH banner"
        return result

    # 2. Algorithm advertisement (raw socket — immune to algorithm incompatibility)
    try:
        algo_info = get_server_algorithms(host, port, timeout)
        result.server_kex_algorithms = algo_info["kex_algorithms"]
        result.server_ciphers = algo_info["ciphers"]
        result.server_macs = algo_info["macs"]
        result.server_host_key_algorithms = algo_info["server_host_key_algorithms"]
        result.server_compression = algo_info["compression"]
        result.negotiated_kex = algo_info["negotiated_kex"]
        result.negotiated_cipher = algo_info["negotiated_cipher"]
        result.negotiated_mac = algo_info["negotiated_mac"]
    except Exception as exc:
        logger.warning("Algorithm extraction failed for %s:%d — %s", host, port, exc)

    # 3. Host keys — try paramiko first, fall back to KEX_INIT advertised list
    # Paramiko may fail on legacy servers (group1-sha1 not in _kex_info on
    # Python 3.14 paramiko builds). If it fails, we synthesise SSHHostKey
    # objects from the server_host_key_algorithms we already read from KEX_INIT.
    # Fingerprints will be None in the fallback path.
    try:
        result.host_keys = get_host_keys(host, port, timeout)
    except Exception as exc:
        logger.debug("Host key collection via paramiko failed for %s:%d — %s", host, port, exc)
        result.host_keys = []

    if not result.host_keys and result.server_host_key_algorithms:
        # Synthesise host key objects from the KEX_INIT advertisement.
        # We know the algorithm names but not fingerprints.
        # Key size is estimated from algorithm name.
        seen = set()
        for algo in result.server_host_key_algorithms:
            if algo in seen:
                continue
            seen.add(algo)
            key_size = _estimate_key_size(algo)
            result.host_keys.append(SSHHostKey(
                algorithm=algo,
                key_size=key_size,
                fingerprint=None,  # not available without completing handshake
            ))

    # 4. Software version analysis + capability gap
    try:
        if result.ssh_version:
            software = parse_banner(result.ssh_version)
            result.software_info = software.to_dict()
            result.capability_gap = analyse_capability_gap(
                software,
                configured_kex=result.server_kex_algorithms,
                configured_host_keys=result.server_host_key_algorithms,
            )
    except Exception as exc:
        logger.debug("Software version analysis failed for %s:%d — %s", host, port, exc)

    result.scan_success = True
    return result


def scan_ssh_bulk(
    hosts: list[str],
    port: int = 22,
    timeout: float = 10.0,
    max_workers: int = 20,
) -> list[SSHScanResult]:
    """
    Scan multiple hosts concurrently.
    Returns results in the same order as input.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results = [None] * len(hosts)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_idx = {
            executor.submit(scan_ssh, host, port, timeout): i
            for i, host in enumerate(hosts)
        }
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception as exc:
                h = hosts[idx]
                logger.error("Scan failed for %s — %s", h, exc)
                err = SSHScanResult(host=h, port=port, scan_error=str(exc))
                results[idx] = err

    return results  # type: ignore[return-value]
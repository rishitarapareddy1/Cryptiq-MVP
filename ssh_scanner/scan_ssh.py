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
    Perform an SSH handshake and capture the server's full algorithm lists
    from the KEX_INIT message, plus what was actually negotiated.

    Returns dict with keys:
        kex_algorithms, server_host_key_algorithms, ciphers_client_to_server,
        ciphers_server_to_client, mac_algos_client_to_server,
        mac_algos_server_to_client, compression_algorithms,
        negotiated_kex, negotiated_cipher, negotiated_mac
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

    transport = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        transport = Transport(sock)
        transport.local_version = "SSH-2.0-CryptiqScanner_1.0"

        # Monkey-patch _parse_kex_init to capture advertised lists before
        # negotiation discards them.
        _original_parse_kex = transport._parse_kex_init  # type: ignore[attr-defined]
        captured: dict = {}

        def _capturing_parse_kex_init(m):
            # paramiko Message object; advance past cookie (16 bytes)
            m.get_bytes(16)  # random cookie
            captured["kex_algorithms"] = m.get_list()
            captured["server_host_key_algorithms"] = m.get_list()
            captured["ciphers_c2s"] = m.get_list()
            captured["ciphers_s2c"] = m.get_list()
            captured["macs_c2s"] = m.get_list()
            captured["macs_s2c"] = m.get_list()
            captured["compression_c2s"] = m.get_list()
            captured["compression_s2c"] = m.get_list()
            # rewind so paramiko can do its own parse
            m.rewind()
            _original_parse_kex(m)

        transport._parse_kex_init = _capturing_parse_kex_init  # type: ignore[method-assign]
        transport.start_client(timeout=timeout)

        # Merge c2s / s2c lists (union — we care about what the server supports)
        result["kex_algorithms"] = captured.get("kex_algorithms", [])
        result["server_host_key_algorithms"] = captured.get("server_host_key_algorithms", [])
        result["ciphers"] = list(dict.fromkeys(
            captured.get("ciphers_c2s", []) + captured.get("ciphers_s2c", [])
        ))
        result["macs"] = list(dict.fromkeys(
            captured.get("macs_c2s", []) + captured.get("macs_s2c", [])
        ))
        result["compression"] = list(dict.fromkeys(
            captured.get("compression_c2s", []) + captured.get("compression_s2c", [])
        ))

        # Negotiated values live on the transport after start_client
        result["negotiated_kex"] = getattr(transport, "_agreed_kex_algo", None)  # type: ignore[attr-defined]
        # paramiko stores the agreed cipher name on the _cipher_info dict key
        if hasattr(transport, "local_cipher"):
            result["negotiated_cipher"] = transport.local_cipher  # type: ignore[attr-defined]
        result["negotiated_mac"] = getattr(transport, "local_mac", None)  # type: ignore[attr-defined]

    except Exception as exc:
        logger.debug("Algorithm extraction for %s:%d — %s", host, port, exc)
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass

    return result


# ---------------------------------------------------------------------------
# Main scan entry point
# ---------------------------------------------------------------------------

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

    # 2. Host keys
    try:
        result.host_keys = get_host_keys(host, port, timeout)
    except Exception as exc:
        logger.warning("Host key collection failed for %s:%d — %s", host, port, exc)
        result.host_keys = []

    # 3. Algorithm advertisement
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
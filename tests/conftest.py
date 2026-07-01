"""
tests/conftest.py
------------------
Shared pytest fixtures for the full Cryptiq test suite.
"""

import os
import sys
import tempfile

# ── Force isolated, file-backed temp databases BEFORE any app module is
# imported. NOTE: sqlite:///:memory: creates a SEPARATE in-memory database
# per connection -- since both database.py and ssh_database.py open new
# Session()/get_db() connections per request, ":memory:" silently breaks
# the test suite. A temp file gives every connection the same physical
# database, matching production behavior with a real sqlite file.
_tmp_dir = tempfile.mkdtemp(prefix="cryptiq_test_")
os.environ["SSH_SCANNER_DATABASE_URL"] = f"sqlite:///{_tmp_dir}/ssh_test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp_dir}/cryptiq_test.db"
os.environ.setdefault("ENCRYPTION_KEY", "kx8N1f6r6lU3v6E0nL8Z3Q8m9b1c4d7e9f0a1b2c3d4=")
os.environ.setdefault("GITHUB_TOKEN", "test-token-not-real")

import pytest


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture
def fake_ssh_scan_result():
    """A minimal but realistic SSHScanResult-like object for risk/cbom tests."""
    from ssh_scanner.scan_ssh import SSHScanResult, SSHHostKey

    result = SSHScanResult(host="test.example.com", port=22)
    result.ssh_version = "OpenSSH_8.2p1 Ubuntu-4ubuntu0.13"
    result.ssh_protocol = "2.0"
    result.raw_banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.13"
    result.host_keys = [SSHHostKey(algorithm="ssh-rsa", key_size=2048, fingerprint="SHA256:fake")]
    result.server_kex_algorithms = [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha256",
        "curve25519-sha256",
    ]
    result.server_ciphers = ["3des-cbc", "aes256-ctr"]
    result.server_macs = ["hmac-md5", "hmac-sha2-256"]
    result.server_host_key_algorithms = ["ssh-rsa"]
    result.server_compression = ["none"]
    result.negotiated_kex = "curve25519-sha256"
    result.negotiated_cipher = "aes256-ctr"
    result.negotiated_mac = "hmac-sha2-256"
    result.scan_success = True
    result.scan_error = None
    return result


@pytest.fixture
def fake_hybrid_scan_result():
    """A scan result representing a server with hybrid PQC KEX already enabled."""
    from ssh_scanner.scan_ssh import SSHScanResult, SSHHostKey

    result = SSHScanResult(host="modern.example.com", port=22)
    result.ssh_version = "OpenSSH_9.6"
    result.ssh_protocol = "2.0"
    result.raw_banner = "SSH-2.0-OpenSSH_9.6"
    result.host_keys = [SSHHostKey(algorithm="ssh-ed25519", key_size=None, fingerprint="SHA256:fakehybrid")]
    result.server_kex_algorithms = [
        "sntrup761x25519-sha512@openssh.com",
        "curve25519-sha256",
    ]
    result.server_ciphers = ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"]
    result.server_macs = ["hmac-sha2-256-etm@openssh.com"]
    result.server_host_key_algorithms = ["ssh-ed25519"]
    result.server_compression = ["none"]
    result.negotiated_kex = "sntrup761x25519-sha512@openssh.com"
    result.negotiated_cipher = "chacha20-poly1305@openssh.com"
    result.negotiated_mac = "hmac-sha2-256-etm@openssh.com"
    result.scan_success = True
    result.scan_error = None
    return result


@pytest.fixture
def legacy_sshd_config():
    """A realistic Ubuntu 20.04 sshd_config with weak algorithms, for patching tests."""
    return """Port 22
PermitRootLogin yes
PasswordAuthentication yes
HostKey /etc/ssh/ssh_host_rsa_key
KexAlgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,curve25519-sha256
Ciphers 3des-cbc,aes128-cbc,aes256-cbc,aes128-ctr,aes256-ctr
MACs hmac-md5,hmac-sha1,hmac-sha2-256
Subsystem sftp /usr/lib/openssh/sftp-server
"""


@pytest.fixture
def client(tmp_path):
    """
    FastAPI TestClient with FRESH, ISOLATED data per test function.

    Rather than reloading database modules (which breaks SQLAlchemy's
    declarative mapper registry on re-definition), this fixture truncates
    every table between tests using the SAME engine/Session objects that
    were created once at process start. This keeps the mapper registry
    intact while guaranteeing each test starts with empty tables -- no
    test-ordering pollution, no need to reload modules.
    """
    from fastapi.testclient import TestClient
    from api import app
    import database as db_module
    from ssh_scanner.ssh_database import create_tables, get_engine

    # Ensure all tables exist (idempotent)
    db_module.Base.metadata.create_all(db_module.engine)
    create_tables(get_engine())

    # Truncate every table on both engines before each test runs
    with db_module.engine.begin() as conn:
        for table in reversed(db_module.Base.metadata.sorted_tables):
            conn.execute(table.delete())

    ssh_engine = get_engine()
    from ssh_scanner.ssh_database import Base as SSHBase
    with ssh_engine.begin() as conn:
        for table in reversed(SSHBase.metadata.sorted_tables):
            conn.execute(table.delete())

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
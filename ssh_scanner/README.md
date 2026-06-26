# Cryptiq — SSH Scanner

SSH cryptographic asset discovery, PQC risk scoring, CBOM generation,
and inventory persistence. Part of the Cryptiq suite.

```
ssh_scanner/
├── scan_ssh.py        # Discovery: banner, host keys, algorithm lists
├── ssh_risk.py        # PQC risk classification + scoring
├── ssh_cbom.py        # CycloneDX 1.6 CBOM generation
├── ssh_database.py    # SQLAlchemy ORM models + persistence
├── api.py             # FastAPI REST endpoints
└── requirements.txt
```

---

## Quick start

```bash
pip install -r requirements.txt
python api.py          # starts on :8001
```

Swagger UI: http://localhost:8001/ssh/docs

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/ssh/scan` | Scan a single host |
| POST | `/ssh/scan/bulk` | Scan up to 500 hosts concurrently |
| GET | `/ssh/scans` | Paginated history (filterable by risk/pqc_status) |
| GET | `/ssh/scans/{host}` | History for a specific host |
| GET | `/ssh/latest/{host}` | Latest scan result |
| POST | `/ssh/rescan/{host}` | Force a fresh scan |
| GET | `/ssh/cbom/{host}` | CycloneDX 1.6 CBOM for a host |
| GET | `/ssh/inventory` | Org-wide inventory + readiness summary |
| GET | `/ssh/health` | Health check |

---

## Example: scan single host

```bash
curl -X POST http://localhost:8001/ssh/scan \
  -H "Content-Type: application/json" \
  -d '{"host": "github.com", "port": 22}'
```

Response:
```json
{
  "host": "github.com",
  "port": 22,
  "ssh_version": "babeld-...",
  "host_key_algorithm": "ssh-rsa",
  "host_key_size": 2048,
  "key_exchange": "curve25519-sha256",
  "cipher": "aes256-gcm@openssh.com",
  "mac": "hmac-sha2-256-etm@openssh.com",
  "quantum_vulnerable": true,
  "risk_level": "high",
  "pqc_status": "vulnerable",
  "migration_priority": "high",
  "findings": [
    "RSA host key (2048-bit) — Shor-vulnerable, harvest-now-decrypt-later risk",
    "Curve25519 KEX — better than ECDH/DH but still not PQC-safe"
  ]
}
```

---

## Example: bulk scan + inventory

```bash
curl -X POST http://localhost:8001/ssh/scan/bulk \
  -H "Content-Type: application/json" \
  -d '{"hosts": ["github.com", "gitlab.com", "bitbucket.org"]}'

curl http://localhost:8001/ssh/inventory
```

Inventory response:
```json
{
  "total_hosts": 3,
  "quantum_vulnerable": 3,
  "by_risk_level": {"high": 2, "medium": 1},
  "by_pqc_status": {"vulnerable": 3},
  "by_primary_host_key_algorithm": {"ssh-rsa": 2, "ssh-ed25519": 1},
  "pqc_readiness_percent": 0.0,
  "critical_migration_targets": [],
  "high_priority_targets": ["github.com", "gitlab.com"]
}
```

---

## Data model

### `ssh_scans` — one row per scan
| Column | Description |
|--------|-------------|
| `host` | Scanned hostname/IP |
| `ssh_version` | e.g. `OpenSSH_9.7p1` |
| `host_key_algorithm` | Primary host key type |
| `host_key_size` | Key size in bits |
| `key_exchange` | Negotiated KEX |
| `cipher` | Negotiated cipher |
| `mac` | Negotiated MAC |
| `quantum_vulnerable` | True if Shor-breakable |
| `risk_level` | `critical\|high\|medium\|low\|unknown` |
| `pqc_status` | `vulnerable\|hybrid\|pqc_ready\|unknown` |
| `migration_priority` | `critical\|high\|normal\|low` |

### `ssh_host_keys` — one row per key type per scan
Captures all host key algorithms a server advertises, not just the negotiated one.

### `ssh_algorithm_advertisements` — full KEX_INIT lists
Stores every advertised algorithm list for post-hoc inventory queries.

---

## Risk taxonomy

### Host keys
| Algorithm | Risk | Notes |
|-----------|------|-------|
| `ssh-rsa` < 2048-bit | critical | Classical AND quantum |
| `ssh-rsa` 2048-bit+ | high | Harvest-now-decrypt-later |
| `ecdsa-sha2-nistp*` | high | Shor-vulnerable |
| `ssh-ed25519` | medium | Not immediately Shor-vulnerable |
| `ml-dsa-65` | low | PQC (FIPS 204) |

### KEX algorithms
| Algorithm | Risk | PQC status |
|-----------|------|------------|
| `diffie-hellman-group1-sha1` | critical | vulnerable |
| `diffie-hellman-group14-sha*` | high | vulnerable |
| `ecdh-sha2-nistp*` | high | vulnerable |
| `curve25519-sha256` | medium | vulnerable |
| `sntrup761x25519-sha512` | low | hybrid |
| `mlkem768-sha256` | low | pqc_ready |

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_SCANNER_DATABASE_URL` | `sqlite:///./ssh_scanner.db` | SQLAlchemy DB URL |

For production:
```bash
export SSH_SCANNER_DATABASE_URL="postgresql://user:pass@host/cryptiq"
```

---

## Architecture fit in the Cryptiq suite

```
Cryptiq
│
├── TLS Scanner  ──→ TLS CBOM
├── SSH Scanner  ──→ SSH CBOM  ──→ Inventory DB ──→ Readiness Report
├── PKI Discovery       ...
└── CBOM Generator (aggregator)
```

The SSH scanner feeds the same inventory + readiness layer as TLS.
Every endpoint is a crypto asset. The product value is the inventory.
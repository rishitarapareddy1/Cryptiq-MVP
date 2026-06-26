# Cryptiq — PQC Readiness Platform

Cryptiq discovers every cryptographic asset in your infrastructure, scores its post-quantum risk, and produces a prioritised migration roadmap. Built for security consultants and engineering teams preparing for the post-quantum transition.

```
Cryptiq-MVP/
├── api.py                  # Unified API — runs everything on :8000
├── database.py             # TLS scan SQLite ORM
├── requirements.txt        # Root dependencies
├── .gitignore
├── static/
│   ├── index.html          # Landing page  →  localhost:8000
│   └── tls.html            # TLS scanner UI  →  localhost:8000/tls
├── tls_scanner/
│   ├── __init__.py
│   ├── scan_tls.py         # TLS domain scanner
│   └── scan_aws.py         # AWS ACM + KMS scanner
└── ssh_scanner/
    ├── __init__.py
    ├── scan_ssh.py         # SSH crypto discovery
    ├── ssh_risk.py         # PQC risk classification
    ├── ssh_cbom.py         # CycloneDX 1.6 CBOM generation
    ├── ssh_database.py     # SSH scan ORM + persistence
    ├── ssh_network.py      # Network-wide host discovery (CIDR)
    ├── ssh_assets.py       # Asset metadata, tagging, trend snapshots
    ├── ssh_report.py       # Consulting PDF report generator
    ├── requirements.txt
    └── static/
        └── index.html      # SSH scanner UI  →  localhost:8000/ssh
```

---

## Quick start

```bash
# 1. Clone and enter the repo
git clone https://github.com/your-org/cryptiq-mvp.git
cd cryptiq-mvp

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
pip install -r ssh_scanner/requirements.txt

# 4. Run
python api.py
```

Open **http://localhost:8000** — the landing page lets you navigate to each tool.

| URL | What |
|-----|------|
| http://localhost:8000 | Home / landing page |
| http://localhost:8000/tls | TLS scanner UI |
| http://localhost:8000/ssh | SSH scanner UI |
| http://localhost:8000/docs | Swagger API docs |

---

## Tools

### TLS Scanner
Scan HTTPS endpoints for certificate algorithms, TLS version, key exchange, and quantum vulnerability. Also scans AWS ACM certificates and KMS keys.

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com"}'
```

### SSH Scanner
Discover SSH hosts on a network. Extract host keys, KEX algorithms, ciphers, and MACs. Network-wide CIDR scanning, asset tagging, and PDF report generation.

```bash
# Single host
curl -X POST http://localhost:8000/ssh/scan \
  -H "Content-Type: application/json" \
  -d '{"host": "github.com"}'

# Network discovery
curl -X POST http://localhost:8000/ssh/discover \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.0/24", "auto_scan": true}'

# Generate PDF report
curl -X POST "http://localhost:8000/ssh/report?org_name=Acme+Corp" \
  --output report.pdf
```

---

## API reference

### TLS
| Method | Path | Description |
|--------|------|-------------|
| POST | `/scan` | Scan a single domain |
| POST | `/scan/bulk` | Scan multiple domains |
| GET | `/scans` | All TLS scan history |
| GET | `/scans/{domain}` | History for a domain |
| GET | `/aws/certificates` | AWS ACM certificates |
| GET | `/aws/keys` | AWS KMS keys |
| GET | `/aws/cbom` | CycloneDX CBOM for AWS assets |

### SSH
| Method | Path | Description |
|--------|------|-------------|
| POST | `/ssh/scan` | Scan a single host |
| POST | `/ssh/scan/bulk` | Scan up to 500 hosts |
| POST | `/ssh/discover` | Network discovery (CIDR / IP range) |
| GET | `/ssh/scans` | SSH scan history (filterable) |
| GET | `/ssh/latest/{host}` | Latest scan for a host |
| POST | `/ssh/rescan/{host}` | Force fresh scan |
| GET | `/ssh/cbom/{host}` | CycloneDX 1.6 CBOM |
| GET | `/ssh/inventory` | Fleet-wide inventory + readiness |
| POST | `/ssh/assets/tag` | Tag asset with business context |
| GET | `/ssh/assets/enriched` | Scan results + metadata joined |
| POST | `/ssh/snapshot` | Save fleet posture snapshot |
| GET | `/ssh/trend` | Historical snapshots for trend charts |
| POST | `/ssh/report` | Generate consulting PDF report |

### Meta
| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/docs` | Swagger UI |

---

## SSH data model

### `ssh_scans`
| Column | Description |
|--------|-------------|
| `host` | Hostname or IP |
| `ssh_version` | e.g. `OpenSSH_9.7p1 Ubuntu-3` |
| `host_key_algorithm` | Primary host key type |
| `host_key_size` | Bits (null for Ed25519) |
| `key_exchange` | Negotiated KEX |
| `cipher` | Negotiated cipher |
| `mac` | Negotiated MAC |
| `quantum_vulnerable` | Shor-breakable |
| `risk_level` | `critical\|high\|medium\|low\|unknown` |
| `pqc_status` | `vulnerable\|hybrid\|pqc_ready\|unknown` |
| `migration_priority` | `critical\|high\|normal\|low` |

### `ssh_host_keys` — one row per advertised key type per scan
Captures every key type a server offers, not just the negotiated one.

### `ssh_algorithm_advertisements` — full KEX_INIT lists
Every advertised algorithm stored as JSON for post-hoc inventory queries.

### `ssh_asset_metadata` — business context per host
Fields: `asset_name`, `asset_owner`, `environment`, `business_unit`, `location`, `can_upgrade`, `upgrade_blocker`, `remediation_status`, `tags`.

### `ssh_fleet_snapshots` — point-in-time posture for trend tracking

---

## Risk taxonomy

### SSH host keys
| Algorithm | Risk | Notes |
|-----------|------|-------|
| `ssh-rsa` < 2048-bit | critical | Classical AND quantum-broken |
| `ssh-rsa` 2048+ | high | Harvest-now-decrypt-later |
| `ecdsa-sha2-nistp*` | high | Shor-vulnerable |
| `ssh-dss` | critical | DSA classically broken |
| `ssh-ed25519` | medium | Not immediately Shor-vulnerable |
| `ml-dsa-65` | low | NIST PQC (FIPS 204) |

### SSH KEX
| Algorithm | Risk | PQC status |
|-----------|------|------------|
| `diffie-hellman-group1-sha1` | critical | vulnerable |
| `diffie-hellman-group14-sha1` | critical | vulnerable |
| `diffie-hellman-group14-sha256` | high | vulnerable |
| `ecdh-sha2-nistp*` | high | vulnerable |
| `curve25519-sha256` | medium | vulnerable |
| `sntrup761x25519-sha512` | low | hybrid |
| `mlkem768x25519-sha256` | low | hybrid |
| `mlkem768-sha256` | low | pqc_ready |

---

## Network discovery

`/ssh/discover` accepts:

| Format | Example |
|--------|---------|
| CIDR | `192.168.1.0/24` |
| IP range | `10.0.0.1-10.0.0.50` |
| Comma-separated | `10.0.0.1,10.0.0.5` |
| Hostname | `github.com` |

Device type is classified from the SSH banner: OpenSSH → server, Dropbear → embedded, Cisco/MikroTik → router, Fortinet → firewall, QNAP/Synology → NAS, VMware → hypervisor.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_SCANNER_DATABASE_URL` | `sqlite:///./ssh_scanner/ssh_scanner.db` | SSH scan DB |

For PostgreSQL:
```bash
export SSH_SCANNER_DATABASE_URL="postgresql://user:pass@localhost/cryptiq"
pip install psycopg2-binary
```

---

## Architecture

```
Cryptiq-MVP/
│
├── api.py  (unified entry point)
│     │
│     ├── GET /          → static/index.html    (landing page)
│     ├── GET /tls       → static/tls.html      (TLS scanner UI)
│     ├── GET /ssh       → ssh_scanner/static/  (SSH scanner UI)
│     │
│     ├── POST /scan ...           TLS endpoints
│     ├── GET  /aws/...            AWS endpoints
│     └── POST /ssh/...            SSH endpoints
│
├── tls_scanner/   (scan_tls.py, scan_aws.py)
├── ssh_scanner/   (scan_ssh, risk, cbom, db, network, assets, report)
└── static/        (landing page + TLS UI)
```

The product pipeline for each tool:
```
Discover → Extract crypto assets → Classify risk → CBOM → DB → Inventory → PDF report
```

Every scanned endpoint is a crypto asset. The inventory is the product.
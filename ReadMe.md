# Cryptiq — PQC Readiness Platform

Cryptiq discovers every cryptographic asset in your infrastructure, scores its post-quantum risk, and automates the migration to quantum-safe algorithms. Built for security consultants and engineering teams preparing for the post-quantum transition.

**Live:** https://cryptiq-krh9.onrender.com

---

## What it does

```
Discover → Classify → Inventory → Plan → Migrate → Report
```

1. **Discover** — scan TLS endpoints, SSH hosts (single or entire CIDR ranges), and AWS crypto assets
2. **Classify** — score every cryptographic primitive against NIST PQC standards (FIPS 203/204/205)
3. **Inventory** — build a CBOM (Cryptography Bill of Materials) in CycloneDX 1.6 format
4. **Plan** — generate a phased, prioritised migration plan with concrete shell commands
5. **Migrate** — generate PQC-ready keys, harden `sshd_config`, execute actions remotely
6. **Report** — produce consulting-grade PDF reports for clients

---

## Project structure

```
Cryptiq-MVP/
├── api.py                      # Unified FastAPI app — the only file you run
├── database.py                 # TLS scan SQLite ORM
├── requirements.txt            # Root Python dependencies
├── Dockerfile                  # Container image (multi-stage, arm64 + amd64)
├── docker-compose.yml          # Local dev stack with SSH test servers
├── Procfile                    # Render.com deployment
├── .gitignore
│
├── static/
│   ├── index.html              # → localhost:8000       Landing page
│   ├── tls.html                # → localhost:8000/tls   TLS scanner UI
│   ├── ssh.html                # → localhost:8000/ssh   SSH scanner UI
│   └── migration.html          # → localhost:8000/migrate  Migration UI
│
├── tls_scanner/
│   ├── scan_tls.py             # TLS domain scanner (openssl-based)
│   └── scan_aws.py             # AWS ACM + KMS scanner (boto3)
│
├── ssh_scanner/
│   ├── scan_ssh.py             # SSH crypto discovery (paramiko)
│   ├── ssh_risk.py             # PQC risk classification + scoring
│   ├── ssh_cbom.py             # CycloneDX 1.6 CBOM generation
│   ├── ssh_database.py         # ORM: scans, host keys, advertisements, assets
│   ├── ssh_network.py          # Network-wide host discovery (CIDR / IP ranges)
│   ├── ssh_assets.py           # Asset tagging, metadata, trend snapshots
│   └── ssh_report.py           # Consulting PDF report generator (reportlab)
│
├── ssh_migration/
│   ├── algorithms.py           # PQC algorithm registry + compatibility matrix
│   ├── keygen.py               # Key generation (ssh-keygen + openssl wrappers)
│   ├── config_hardener.py      # sshd_config analysis + patch generation
│   ├── migration_plan.py       # Phased migration plan builder
│   ├── executor.py             # Remote execution via paramiko SSH
│   └── api.py                  # Migration API router (mounted at /migrate/ssh/)
│
└── tests/
    ├── conftest.py
    └── test_cryptiq.py         # 116 tests covering TLS, SSH, API, DB, edge cases
```

---

## Quick start — local (no Docker)

```bash
git clone https://github.com/your-org/cryptiq-mvp.git
cd cryptiq-mvp

python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
pip install -r ssh_scanner/requirements.txt

python api.py
```

Open **http://localhost:8000**

| URL | Tool |
|-----|------|
| http://localhost:8000 | Landing page |
| http://localhost:8000/tls | TLS scanner |
| http://localhost:8000/ssh | SSH scanner |
| http://localhost:8000/migrate | SSH migration |
| http://localhost:8000/docs | Swagger API |

---

## Docker — M1/M2 Mac and Linux

### Build the image

```bash
# Standard build (uses your current platform — arm64 on M1)
docker build -t cryptiq .

# Build for both arm64 and amd64 (for deploying to Linux servers from M1)
docker buildx build --platform linux/amd64,linux/arm64 -t cryptiq .
```

### Run the app only

```bash
docker run -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  cryptiq
```

Open http://localhost:8000

### Run the full dev stack (app + SSH test servers)

```bash
docker compose up
```

This starts:
- `cryptiq_app` on http://localhost:8000 — the main application
- `cryptiq_ssh_target` on port 2222 — a real OpenSSH server to scan and migrate
- `cryptiq_ssh_legacy` on port 2223 — Ubuntu 20.04 with deliberately weak SSH config (group14-sha1, CBC ciphers) for testing the scanner catches weak algorithms

```bash
# Rebuild after code changes
docker compose up --build

# Run in background
docker compose up -d

# See logs
docker compose logs -f cryptiq

# Stop everything
docker compose down

# Stop and delete all data (fresh start)
docker compose down -v
```

---

## Testing against the Docker SSH servers

With `docker compose up` running, you have two real SSH targets:

### Scan the modern SSH server (port 2222)
```bash
curl -X POST http://localhost:8000/ssh/scan \
  -H "Content-Type: application/json" \
  -d '{"host":"localhost","port":2222}'
```

### Scan the legacy weak SSH server (port 2223)
```bash
curl -X POST http://localhost:8000/ssh/scan \
  -H "Content-Type: application/json" \
  -d '{"host":"localhost","port":2223}'
```
Expected: `risk_level: "critical"`, weak KEX flagged, `pqc_status: "vulnerable"`

### Generate a migration plan for the legacy server
```bash
# 1. Get the scan result
SCAN=$(curl -s -X POST http://localhost:8000/ssh/scan \
  -H "Content-Type: application/json" \
  -d '{"host":"localhost","port":2223}')

# 2. Generate a migration plan
echo "{\"scan_result\": $SCAN}" | \
  curl -s -X POST http://localhost:8000/migrate/ssh/plan \
  -H "Content-Type: application/json" \
  -d @- | python3 -m json.tool
```

### Execute a config hardening (dry run)
```bash
# Get the plan
PLAN=$(echo "{\"scan_result\": $SCAN}" | \
  curl -s -X POST http://localhost:8000/migrate/ssh/plan \
  -H "Content-Type: application/json" -d @-)

# Extract the first action
ACTION=$(echo $PLAN | python3 -c "import sys,json; p=json.load(sys.stdin); print(json.dumps(p['phases'][0]['actions'][0]))")

# Execute in dry run (default)
echo "{\"action\": $ACTION, \"dry_run\": true}" | \
  curl -s -X POST http://localhost:8000/migrate/ssh/execute \
  -H "Content-Type: application/json" -d @- | python3 -m json.tool
```

### SSH into the test server and run migration commands manually
```bash
# Connect to the legacy test server
ssh testuser@localhost -p 2223
# password: testpassword

# Check current SSH config
sudo sshd -T | grep -E "kexalgorithms|ciphers|macs"

# Apply the hardening snippet from the migration plan
# (copy from the plan output, paste into the server)
```

---

## Platform compatibility

| Platform | Scanner | Migration | Key gen | Notes |
|----------|---------|-----------|---------|-------|
| macOS (M1/M2/Intel) | ✅ | ✅ | ✅ | Requires `brew install openssh` for keygen |
| macOS (Docker) | ✅ | ✅ | ✅ | Fully supported, ssh-keygen included in image |
| Linux (Ubuntu/Debian) | ✅ | ✅ | ✅ | Native, openssh-client pre-installed |
| Linux (Docker) | ✅ | ✅ | ✅ | Primary production target |
| Windows (native) | ✅ | ⚠️ | ⚠️ | Scanner works; keygen needs Git Bash or WSL |
| Windows (Docker Desktop) | ✅ | ✅ | ✅ | Recommended for Windows users |
| Render.com | ✅ | ✅ | ✅ | Deployed, see Procfile |

**What doesn't work on Windows natively:**
- `ssh-keygen` commands in the executor (use Docker or WSL)
- `openssl` commands (use Docker or install OpenSSL for Windows)
- The scanner itself works fine — it's pure Python

---

## Testing the tools manually

### TLS scanner
```bash
# Scan a domain
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com"}'

# Bulk scan
curl -X POST http://localhost:8000/scan/bulk \
  -H "Content-Type: application/json" \
  -d '{"domains": ["google.com", "github.com", "cloudflare.com"]}'

# View history
curl http://localhost:8000/scans
```

### SSH scanner
```bash
# Single host
curl -X POST http://localhost:8000/ssh/scan \
  -H "Content-Type: application/json" \
  -d '{"host": "github.com"}'

# Bulk
curl -X POST http://localhost:8000/ssh/scan/bulk \
  -H "Content-Type: application/json" \
  -d '{"hosts": ["github.com", "gitlab.com", "bitbucket.org"]}'

# Network discovery (your local network)
curl -X POST http://localhost:8000/ssh/discover \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.0/24", "timeout": 2}'

# Inventory summary
curl http://localhost:8000/ssh/inventory

# Generate PDF report
curl -X POST "http://localhost:8000/ssh/report?org_name=Test+Corp" \
  --output report.pdf && open report.pdf
```

### SSH migration
```bash
# Get all algorithm options
curl http://localhost:8000/migrate/ssh/algorithms | python3 -m json.tool

# Get recommended algorithms only
curl http://localhost:8000/migrate/ssh/algorithms/recommended

# Generate keys locally
curl -X POST http://localhost:8000/migrate/ssh/keygen \
  -H "Content-Type: application/json" \
  -d '{"algorithms": ["ed25519"], "comment": "test-migration"}'

# Check available tools
curl http://localhost:8000/migrate/ssh/tools
```

### Run the test suite
```bash
# All 116 tests
pytest

# Just SSH tests
pytest -k "ssh" -v

# Just TLS tests
pytest -k "tls" -v

# Just API integration tests
pytest -k "api" -v

# With coverage
pip install pytest-cov
pytest --cov=. --cov-report=html
open htmlcov/index.html
```

---

## Render.com deployment

The `Procfile` at the repo root handles Render deployment:

```
web: gunicorn api:app --worker-class uvicorn.workers.UvicornWorker --workers 2 --bind 0.0.0.0:$PORT --timeout 120
```

**How it works:**
- Render detects the `Procfile` automatically when you connect your GitHub repo
- It runs `pip install -r requirements.txt` + `pip install -r ssh_scanner/requirements.txt` in the build step
- The `$PORT` env var is set by Render and passed to gunicorn
- SQLite databases are ephemeral on Render's free tier — they reset on redeploy

**For persistent data on Render:**
- Use a PostgreSQL database (Render provides one free)
- Set `SSH_SCANNER_DATABASE_URL=postgresql://...` in Render's environment variables

**Render environment variables to set:**
```
SSH_SCANNER_DATABASE_URL = postgresql://user:pass@host/dbname
PYTHON_VERSION = 3.12.0
```

---

## API reference

### TLS
| Method | Path | Description |
|--------|------|-------------|
| POST | `/scan` | Scan a single HTTPS domain |
| POST | `/scan/bulk` | Scan multiple domains |
| GET | `/scans` | All TLS scan history |
| GET | `/scans/{domain}` | History for a domain |
| GET | `/aws/certificates` | AWS ACM certificates |
| GET | `/aws/keys` | AWS KMS keys |
| GET | `/aws/cbom` | CycloneDX CBOM for AWS assets |

### SSH Scanner
| Method | Path | Description |
|--------|------|-------------|
| POST | `/ssh/scan` | Scan a single host |
| POST | `/ssh/scan/bulk` | Scan up to 500 hosts concurrently |
| POST | `/ssh/discover` | Network discovery (CIDR / IP range) |
| GET | `/ssh/scans` | Scan history (filter by risk, pqc_status) |
| GET | `/ssh/latest/{host}` | Latest scan for a host |
| POST | `/ssh/rescan/{host}` | Force fresh scan |
| GET | `/ssh/cbom/{host}` | CycloneDX 1.6 CBOM |
| GET | `/ssh/inventory` | Fleet-wide inventory + readiness |
| POST | `/ssh/assets/tag` | Tag asset with business context |
| GET | `/ssh/assets/enriched` | Scan results + metadata |
| POST | `/ssh/snapshot` | Save fleet posture snapshot |
| GET | `/ssh/trend` | Trend data for charting |
| POST | `/ssh/report` | Generate consulting PDF |

### SSH Migration
| Method | Path | Description |
|--------|------|-------------|
| GET | `/migrate/ssh/algorithms` | Full algorithm registry |
| GET | `/migrate/ssh/algorithms/recommended` | Recommended choices only |
| POST | `/migrate/ssh/analyse` | Analyse a scan result for issues |
| POST | `/migrate/ssh/patch` | Generate hardened sshd_config patch |
| POST | `/migrate/ssh/plan` | Generate phased migration plan |
| POST | `/migrate/ssh/plan/fleet` | Fleet-wide migration plan |
| POST | `/migrate/ssh/keygen` | Generate SSH key pairs |
| POST | `/migrate/ssh/execute` | Execute migration action (dry_run=true default) |
| POST | `/migrate/ssh/compatibility` | Check algorithm/OpenSSH version compatibility |
| GET | `/migrate/ssh/tools` | Check ssh-keygen/openssl availability |

### Meta
| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/docs` | Swagger UI |

---

## Risk taxonomy

### SSH host keys
| Algorithm | Risk | Notes |
|-----------|------|-------|
| `ssh-rsa` < 2048-bit | critical | Classical AND quantum-broken |
| `ssh-rsa` 2048+ | high | Harvest-now-decrypt-later |
| `ecdsa-sha2-nistp*` | high | Shor-vulnerable |
| `ssh-dss` | critical | DSA classically broken |
| `ssh-ed25519` | medium | Not Shor-vulnerable but not PQC-safe |
| `ml-dsa-65` (FIPS 204) | low | Post-quantum standard |

### SSH KEX
| Algorithm | Risk | Status |
|-----------|------|--------|
| `diffie-hellman-group1-sha1` | critical | 768-bit + SHA-1 |
| `diffie-hellman-group14-sha1` | critical | SHA-1 |
| `diffie-hellman-group14-sha256` | high | Quantum-vulnerable |
| `ecdh-sha2-nistp*` | high | Shor-vulnerable |
| `curve25519-sha256` | medium | Better but not PQC-safe |
| `sntrup761x25519-sha512` | low | Hybrid — available now |
| `mlkem768x25519-sha256` | low | Hybrid FIPS 203 |
| `mlkem768-sha256` | low | Pure PQC |

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_SCANNER_DATABASE_URL` | `sqlite:///./data/ssh_scanner.db` | SSH scan DB |
| `CRYPTIQ_ENV` | `development` | `production` disables debug features |

---

## Architecture

```
                    http://localhost:8000
                           │
                       api.py (FastAPI)
                    ┌──────┴──────────────┐
                    │                     │
              Static files          API routes
         (index, tls, ssh,      /scan  /ssh/  /migrate/
          migration HTML)        /aws   /health  /docs
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
        tls_scanner/       ssh_scanner/        ssh_migration/
        scan_tls.py        scan_ssh.py         algorithms.py
        scan_aws.py        ssh_risk.py         keygen.py
                           ssh_cbom.py         config_hardener.py
                           ssh_database.py     migration_plan.py
                           ssh_network.py      executor.py
                           ssh_assets.py
                           ssh_report.py
                                 │
                           SQLite / PostgreSQL
                           (ssh_scanner.db, cryptiq.db)
```
# Cryptiq — PQC Readiness & Migration Platform

Cryptiq discovers cryptographic assets across TLS, AWS, and SSH infrastructure,
scores post-quantum risk, and migrates them — either by proposing a reviewable
pull request (cloud/ALB) or by executing safety-railed changes directly (SSH).

**Live:** https://cryptiq-krh9.onrender.com

---

## Two migration models — read this first

Cryptiq has two distinct trust models depending on the asset type. See
`CLAUDE.md` for the full rationale; this is the short version.

| | Cloud / ALB TLS | SSH |
|---|---|---|
| Discovery | Read-only AWS API calls | Raw socket KEX_INIT read (no auth needed) |
| Migration | **Proposes** a GitHub PR with a Terraform diff | **Executes** directly via SSH, with validation + auto-rollback |
| Who applies the change | A human, by merging the PR | Cryptiq, after `sshd -t` validates the config |
| Why the difference | Cryptiq never holds cloud write credentials | The operator explicitly grants SSH credentials for this purpose |

---

## What it does

```
Discover → Classify → Inventory → Plan → Migrate → Report
```

1. **Discover** — TLS endpoints, SSH hosts (single host or CIDR ranges), AWS ACM/KMS, AWS ALB/NLB listeners, and auto-discovered subdomains via CT logs
2. **Classify** — every cryptographic primitive scored against NIST PQC standards (FIPS 203/204/205), with version-aware capability analysis (does this OpenSSH version even support the recommended algorithm?)
3. **Inventory** — CycloneDX 1.6 CBOM for TLS, AWS, and SSH assets
4. **Plan** — phased migration plans with concrete commands (SSH) or Terraform diffs (ALB)
5. **Migrate** — SSH: generate keys, harden sshd_config, execute remotely with rollback. ALB: open a GitHub PR proposing the policy change
6. **Report** — consulting-grade PDF reports; append-only audit log for every migration action

---

## Project structure

```
Cryptiq-MVP/
├── api.py                      # Unified FastAPI app — the only file you run
├── database.py                 # TLS scans, multi-tenant Workspace/ScanJob models
├── discovery.py                # CT log / Route53 / EC2 subdomain auto-discovery
├── requirements.txt
├── Dockerfile                  # Container image (arm64 + amd64)
├── docker-compose.yml          # Local dev stack
├── docker-compose.fleet.yml    # 4 SSH test containers (critical/high/medium/hybrid risk)
├── Procfile                    # Render.com deployment
├── CLAUDE.md                   # Standing rules for AI-assisted development — READ FIRST
├── Build_runbook.md            # Historical design doc for the ALB slice (Node/TS plan —
│                                # superseded by the Python implementation actually in tls_migration/)
├── DEMO.md                     # End-to-end ALB migration demo script
├── demo-reset.sh / .ps1        # Reset demo AWS infra to starting state
│
├── demo-infra/                 # Terraform: provisions a demo ALB on a classical TLS policy
│   ├── main.tf, variables.tf, outputs.tf
│
├── iam/
│   ├── discovery-readonly.json # Minimal IAM policy for AWS discovery (read-only)
│   └── README.md               # Blast-radius statement
│
├── static/
│   ├── index.html              # Landing page
│   ├── tls.html                # TLS scanner UI
│   ├── ssh.html                # SSH scanner UI
│   ├── alb.html                # ALB PQC migration dashboard
│   └── migration.html          # SSH migration UI
│
├── tls_scanner/
│   ├── scan_tls.py             # TLS domain scanner (openssl-based)
│   ├── scan_aws.py             # AWS ACM + KMS scanner
│   └── scan_alb.py             # ALB/NLB listener discovery (read-only)
│
├── tls_migration/               # ALB TLS migration — PROPOSE ONLY, see CLAUDE.md
│   ├── types.py                 # Shared types (TlsListenerAsset, etc.)
│   ├── alb_plan.py              # Computes the Terraform diff (no file writes)
│   ├── alb_cbom.py               # CycloneDX CBOM for ALB assets
│   ├── github_pr.py             # PR chokepoint — branch/commit/PR only, never merge
│   ├── run.py                   # Composes discovery → plan → PR
│   ├── rollback.py               # Computes + opens the inverse PR
│   └── audit.py                  # Append-only audit log reader/writer
│
├── ssh_scanner/
│   ├── scan_ssh.py              # Raw KEX_INIT socket parser (no auth needed)
│   ├── ssh_risk.py              # Weighted risk scoring + MigrationRecommendation objects
│   ├── ssh_versions.py          # OpenSSH/Dropbear/Cisco version lifecycle + PQC capability
│   ├── ssh_algorithms.py        # Algorithm family normalization (curve25519 variants → 1 family)
│   ├── ssh_cbom.py               # CycloneDX 1.6 CBOM
│   ├── ssh_database.py           # ORM: scans, host keys, advertisements, assets
│   ├── ssh_network.py            # CIDR / IP range discovery
│   ├── ssh_assets.py             # Asset tagging, trend snapshots
│   └── ssh_report.py             # Consulting PDF generator
│
├── ssh_migration/                # SSH migration — DIRECT EXECUTION, see CLAUDE.md
│   ├── algorithms.py              # PQC algorithm registry
│   ├── keygen.py                  # Key generation — private keys never leave disk
│   ├── config_hardener.py         # Surgical, version-aware sshd_config patching
│   ├── migration_plan.py          # Phased plan builder
│   ├── executor.py                # SSH execution: validate→backup→apply→verify→rollback
│   ├── rollback.py                # Structured backup directories + RollbackManager
│   └── api.py                     # Router mounted at /migrate/ssh/
│
└── tests/
    └── test_cryptiq.py            # 116+ tests
```

---

## Quick start — local

```bash
git clone <repo-url>
cd Cryptiq-MVP

python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
pip install -r ssh_scanner/requirements.txt

python api.py
```

Open **http://127.0.0.1:8000**

| URL | Tool |
|-----|------|
| http://127.0.0.1:8000 | Landing page |
| http://127.0.0.1:8000/tls | TLS scanner |
| http://127.0.0.1:8000/ssh | SSH scanner |
| http://127.0.0.1:8000/alb | ALB PQC migration dashboard |
| http://127.0.0.1:8000/migrate | SSH migration |
| http://127.0.0.1:8000/docs | Swagger API |

---

## Environment variables

| Variable | Default | Required for |
|----------|---------|---------------|
| `DATABASE_URL` | `sqlite:///cryptiq.db` | TLS scans, workspaces. Use `postgresql://...` in production |
| `SSH_SCANNER_DATABASE_URL` | `sqlite:///./ssh_scanner.db` | SSH scan history |
| `ENCRYPTION_KEY` | none | Encrypting workspace AWS credentials at rest. **Without this, credentials stored via `/workspace/{id}/connect/aws` are PLAINTEXT.** Generate: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `GITHUB_TOKEN` | none | Opening migration/rollback PRs (`tls_migration/github_pr.py`) |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | none | ALB/ACM/KMS discovery if not using per-workspace credentials |

---

## SSH migration — full local test (Docker fleet)

```bash
docker compose -f docker-compose.fleet.yml up -d
sleep 60   # wait for apt-get inside containers

# Scan the deliberately weak legacy container
curl -s -X POST http://127.0.0.1:8000/ssh/scan \
  -H "Content-Type: application/json" \
  -d '{"host":"127.0.0.1","port":2222}' > /tmp/legacy_scan.json

# Generate a version-aware migration plan
python3 -c "
import json, urllib.request
scan = json.load(open('/tmp/legacy_scan.json'))
req = urllib.request.Request('http://127.0.0.1:8000/migrate/ssh/plan',
    data=json.dumps({'scan_result': scan}).encode(),
    headers={'Content-Type':'application/json'})
plan = json.loads(urllib.request.urlopen(req).read())
json.dump(plan, open('/tmp/plan.json','w'))
print(f'{plan[\"total_actions\"]} actions, risk={plan[\"scan_risk_level\"]}')
"
```

Full walkthrough including dry-run, live execution, and verification: see `TESTING.md`.

---

## ALB TLS migration — demo

```bash
cd demo-infra
terraform init && terraform apply    # provisions a demo ALB on a classical TLS policy

# Discover it
curl http://127.0.0.1:8000/aws/alb-listeners?region=us-east-1

# Propose a migration PR (dry run first)
curl -X POST http://127.0.0.1:8000/migrate/alb-tls \
  -H "Content-Type: application/json" \
  -d '{"listener_arn":"<arn>","tf_repo":"/path/to/tf","gh_repo":"you/repo","dry_run":true}'
```

Full script: `DEMO.md`. Teardown: `./demo-reset.sh`.

---

## Run the test suite

```bash
pytest                  # all tests
pytest -k "ssh"          # SSH only
pytest -k "tls"          # TLS only
pytest --cov=. --cov-report=html   # with coverage
```

---

## Risk taxonomy (SSH)

Weighted scoring: host_key 40%, KEX 40%, cipher 10%, MAC 10% — see `ssh_scanner/ssh_risk.py`.

| Host key | Risk |
|----------|------|
| `ssh-rsa` < 2048-bit | critical |
| `ssh-rsa` 2048+ | high |
| `ecdsa-sha2-nistp*` | high |
| `ssh-ed25519` | medium |
| `ml-dsa-65` (FIPS 204) | low |

| KEX | Risk | PQC status |
|-----|------|-----------|
| `diffie-hellman-group1-sha1` | critical | vulnerable |
| `diffie-hellman-group14-sha256` | high | vulnerable |
| `curve25519-sha256` | medium | vulnerable |
| `sntrup761x25519-sha512` | low | hybrid |
| `mlkem768x25519-sha256` | low | hybrid |

---

## Architecture

```
                         http://127.0.0.1:8000
                                │
                          api.py (FastAPI)
                ┌───────────────┼────────────────────────┐
                │               │                        │
          Static UI       Single-shot tools        Workspace tools
       (index/tls/ssh/    /scan /ssh/ /migrate/    /workspace/* (multi-tenant,
        alb/migration)    /aws/                     background jobs, encrypted
                                                      AWS creds)
                │               │                        │
      ┌─────────┴───┐    ┌──────┴───────┐         ┌──────┴──────┐
 tls_scanner/   ssh_scanner/      ssh_migration/      tls_migration/
 scan_tls.py    scan_ssh.py       config_hardener.py  alb_plan.py
 scan_aws.py    ssh_risk.py       executor.py         github_pr.py
 scan_alb.py    ssh_versions.py   keygen.py           run.py / rollback.py
                ssh_algorithms.py rollback.py          audit.py
                ssh_cbom.py
                ssh_database.py
                                       │
                          SQLite / PostgreSQL
                    (cryptiq.db, ssh_scanner.db)
```
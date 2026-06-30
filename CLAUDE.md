# CLAUDE.md — Standing context for the Cryptiq repo

## What this is
A security product that discovers quantum-vulnerable cryptography across a
company's infrastructure — TLS endpoints, AWS load balancers, SSH servers —
scores PQC risk, and either PROPOSES migrations (cloud/ALB) or EXECUTES them
directly with safety rails (SSH, which Cryptiq can reach and modify because it
runs against infrastructure the operator explicitly grants SSH access to).

These are two different trust models. Read carefully — they are not interchangeable.

---

## Trust model A: Cloud/ALB migration — PROPOSE, NEVER APPLY

Applies to: `tls_migration/`, `/migrate/alb-tls*` endpoints, anything touching
AWS, Terraform, or GitHub.

- The engine NEVER mutates cloud resources. No create/update/delete on any AWS
  resource. Discovery (`discover_alb_listeners`) is read-only; migration output
  is a Terraform diff, never an applied change.
- The engine NEVER merges, force-pushes, or deletes in Git. It only creates a
  branch, commits, and opens a pull request (see `tls_migration/github_pr.py`).
  A human merges. The customer's own CI/CD applies the merged change with the
  customer's own credentials.
- If a task appears to require a mutating cloud call or a merge, STOP and flag
  it in your response. Do not implement it.
- AWS discovery uses only read-only operations (Describe*, List*, Get*). See
  `iam/discovery-readonly.json` for the exact minimal policy.
- The engine holds no infrastructure WRITE credential, ever. Its only write
  surface is GitHub (proposing). State this blast-radius fact plainly when asked.
- Environment scoping: prod-tagged listeners are excluded by default
  (`/migrate/alb-tls` requires `allow_prod=true` + `prod_token`). Don't remove
  this gate to make a demo smoother.

## Trust model B: SSH migration — DIRECT EXECUTION WITH SAFETY RAILS

Applies to: `ssh_migration/`, `/migrate/ssh/*` endpoints.

This is intentionally different. The operator runs Cryptiq against their own
SSH fleet and grants it credentials explicitly (password or key) for the
specific purpose of hardening sshd configs and rotating host keys. Direct
execution is the product here — but every execution path must have:

- **dry_run=True by default** on every execute endpoint. Never flip this
  default. The caller must explicitly opt into a live run.
- **Validate before apply**: any sshd_config change is tested with
  `sshd -t -f <temp_file>` BEFORE the production config file is touched.
  See `ssh_migration/config_hardener.py::generate_hardening_commands`.
- **Backup before mutate**: every destructive action backs up the file(s) it's
  about to change to a timestamped directory before changing them. See
  `ssh_migration/rollback.py`.
- **Auto-rollback on failure**: if a step in an action fails (e.g. `sshd -t`
  rejects the new config, or the reload fails), the executor automatically
  restores the backup and reloads. See `MigrationExecutor._attempt_rollback`.
- **Surgical patching, not replacement**: config changes modify only the
  specific weak directives (KexAlgorithms, Ciphers, MACs) and preserve
  unknown/vendor-specific algorithms an admin may have intentionally configured.
  Never regenerate the whole file from scratch.
- **Version-aware recommendations**: never recommend an algorithm the target's
  OpenSSH version doesn't support (e.g. don't suggest ML-KEM hybrid KEX to a
  server running OpenSSH 8.2). See `ssh_scanner/ssh_versions.py` and
  `config_hardener.py::get_recommended_kex`.
- Private key material is NEVER returned over the API or logged. Only
  fingerprints, paths, and public keys leave `ssh_migration/keygen.py`.

If a change to this code would remove a validation step, a backup step, or
the dry_run default, treat that as a regression requiring explicit sign-off,
not a refactor.

---

## Crypto correctness (applies to both trust models)
- Post-quantum policy names, supported KEX groups, and which OpenSSH/cloud
  versions have PQC support CHANGE OFTEN. Never hardcode one from memory.
  Put it in a config constant with a `// VERIFY:` / `# VERIFY:` tag and a link
  to the doc you confirmed it against.
- When unsure about an algorithm, a CBOM schema field, or whether a change is
  semantically safe to automate, leave a `VERIFY:` tag and say so. Do not guess.
- Anything touching custom crypto, persisted encrypted data, root/HSM keys, or
  vendor-controlled crypto is OUT OF SCOPE for automation — flag it as
  "manual review required," never generate a change for it.

## Engineering conventions
- Python (FastAPI) for the API and all scanning/migration logic. TypeScript
  conventions in the original Build Runbook (Phase A–D) describe a parallel
  Node implementation path for the ALB slice that was not ultimately used —
  the Python implementation under `tls_migration/` and `tls_scanner/` is the
  one actually wired into `api.py`. Treat the runbook as historical design
  rationale, not current architecture.
- Small, single-responsibility, typed modules (dataclasses with type hints).
- Every module should have unit tests using MOCKED SDK/network responses.
  No live AWS or live SSH calls in the test suite (tests/test_cryptiq.py).
  Live execution is tested manually against the Docker fleet
  (docker-compose.fleet.yml) — see TESTING.md.
- All GitHub-mutating calls route through a chokepoint
  (`tls_migration/github_pr.py`) that hard-asserts the operation is
  branch-create / commit / open-PR. Nothing bypasses it.
- All SSH-mutating calls route through `ssh_migration/executor.py`, which
  enforces dry_run-by-default, backup-before-mutate, and auto-rollback.
- Every engine action (scan, plan, PR, execute, rollback) writes to an
  append-only audit trail — `tls_migration/audit.py` for ALB,
  `ssh_migration/rollback.py`'s `RollbackManager` + structured backup
  directories for SSH.
- Secrets come from env vars. Never hardcoded, never committed. `.env` is
  gitignored. `ENCRYPTION_KEY` (Fernet) encrypts workspace AWS credentials at
  rest — see `database.py`.

## When in doubt
Ask or flag rather than proceed. A flagged uncertainty costs a sentence; a
wrong guess in this product costs a customer incident — either a botched
cloud migration PR or a broken SSH daemon on a production server.
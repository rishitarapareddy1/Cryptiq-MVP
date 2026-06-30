# Demo Script — ALB TLS → PQC Migration

End-to-end walkthrough from a fresh AWS account to a demoable PQC migration.
Run these steps in order. Expected output is shown at each step.

---

## Prerequisites

- AWS credentials configured (`aws configure` or `AWS_*` env vars)
- Terraform ≥ 1.5 installed
- Python env set up: `pip install -r requirements.txt && pip install -r ssh_scanner/requirements.txt`
- `GITHUB_TOKEN` env var set with `repo` scope (or `public_repo` for public repos)
- `CRYPTIQ_ACTOR` env var set (e.g. `export CRYPTIQ_ACTOR=yourname`)

---

## Step 1 — Provision the demo ALB

```bash
cd demo-infra
terraform init
terraform plan   # Review: should create 6 resources (ALB, listener, SG, cert, TG, etc.)
terraform apply  # YOU apply this — Cryptiq never applies infrastructure changes
```

**Expected output:**
```
Apply complete! Resources: 6 added, 0 changed, 0 destroyed.

Outputs:
alb_arn           = "arn:aws:elasticloadbalancing:us-east-1:123456789:loadbalancer/app/cryptiq-pqc-demo-alb/..."
listener_arn      = "arn:aws:elasticloadbalancing:us-east-1:123456789:listener/app/..."
current_ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
```

---

## Step 2 — Start the Cryptiq server

```bash
cd ..   # back to repo root
python api.py
```

**Expected output:**
```
  Cryptiq PQC Scanner
  Home      →  http://localhost:8000
  ALB       →  http://localhost:8000/alb
  TLS       →  http://localhost:8000/tls
  SSH       →  http://localhost:8000/ssh
  Docs      →  http://localhost:8000/docs
```

---

## Step 3 — Discover the demo ALB (API)

```bash
curl -s "http://localhost:8000/aws/alb-listeners?region=us-east-1" | python -m json.tool
```

**Expected output (abridged):**
```json
{
  "region": "us-east-1",
  "count": 1,
  "listeners": [
    {
      "lb_name": "cryptiq-pqc-demo-alb",
      "port": 443,
      "protocol": "HTTPS",
      "ssl_policy_name": "ELBSecurityPolicy-TLS13-1-2-2021-06",
      "is_post_quantum": false,
      "environment": "staging"
    }
  ]
}
```

`is_post_quantum: false` — this is your migration target.

---

## Step 4 — Discover via the dashboard

Open **http://localhost:8000/alb** in a browser.

1. Enter region `us-east-1` and click **Discover Listeners**
2. You should see 1 row: `cryptiq-pqc-demo-alb` with a red **Needs Migration** pill

---

## Step 5 — Preview the migration diff (dry run)

Click **Open Migration PR** on the red row. In the modal:

1. Enter your GitHub repo: e.g. `yourname/infra-demo`
2. Enter the path to `demo-infra/` on your machine: e.g. `/path/to/Cryptiq-MVP/demo-infra`
3. Click **Preview Diff**

**Expected diff (in modal):**
```diff
-  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
+  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
```

Exactly one line changes. No other fields are touched.

You can also do this via API:
```bash
curl -s -X POST http://localhost:8000/migrate/alb-tls \
  -H "Content-Type: application/json" \
  -d '{
    "listener_arn": "<LISTENER_ARN_FROM_STEP_2>",
    "tf_repo": "/path/to/Cryptiq-MVP/demo-infra",
    "gh_repo": "yourname/infra-demo",
    "dry_run": true
  }' | python -m json.tool
```

---

## Step 6 — Open the real migration PR

In the modal, click **Open PR** (or set `dry_run: false` in the API call).

**Expected:**
- A PR opens in your GitHub repo
- PR title: `cryptiq: migrate cryptiq-pqc-demo-alb:443 to PQ TLS policy`
- PR body contains: current policy, target policy, diff, and: *"This tool will not merge for you"*
- PR is labeled `cryptiq-migration`

---

## Step 7 — Merge the PR (human action)

In GitHub, review and merge the PR. This is the only step Cryptiq does not do.

After merging, your CI/CD (or `terraform apply`) applies the change:
```bash
cd demo-infra
terraform apply   # should show: 1 to change (ssl_policy only)
```

---

## Step 8 — Verify the listener went green

Refresh the dashboard at **http://localhost:8000/alb** → Discover Listeners again.

The row should now show a green **PQ Ready** pill.

```bash
curl -s "http://localhost:8000/aws/alb-listeners?region=us-east-1" | python -c "
import sys,json
d=json.load(sys.stdin)
for l in d['listeners']:
    print(l['lb_name'], '→', 'PQ READY' if l['is_post_quantum'] else 'NEEDS MIGRATION')
"
```

**Expected:**
```
cryptiq-pqc-demo-alb → PQ READY
```

---

## Step 9 — Roll back

```bash
# Get the PR number and body from GitHub, then:
curl -s -X POST http://localhost:8000/migrate/alb-tls/rollback \
  -H "Content-Type: application/json" \
  -d '{
    "listener_arn": "<LISTENER_ARN>",
    "migration_pr_body": "<FULL PR BODY FROM STEP 6>",
    "migration_pr_number": <PR_NUMBER>,
    "tf_file": "/path/to/Cryptiq-MVP/demo-infra/main.tf",
    "gh_repo": "yourname/infra-demo",
    "dry_run": true
  }' | python -m json.tool
```

Review the rollback diff (should restore original policy), then set `dry_run: false` to open the rollback PR.

After merging and applying the rollback, the listener reverts to `ELBSecurityPolicy-TLS13-1-2-2021-06`.

---

## Step 10 — Check the audit log

```bash
curl -s "http://localhost:8000/audit-log" | python -m json.tool
```

Or view it on the **Audit Log** tab in the dashboard.

**Expected entries:** `discovery`, `plan`, `open_pr`, `rollback` — all timestamped and immutable.

---

## Step 11 — Teardown

```bash
cd demo-infra
terraform destroy   # removes all 6 resources; no ongoing charges
```

All resources are tagged `Project = cryptiq-pqc-demo` — verify in the AWS console that nothing was missed.

---

## demo-reset (return to starting state)

Run this to destroy infra, clear the audit log, and reset the DB:

```bash
bash demo-reset.sh
```

or on Windows:

```powershell
.\demo-reset.ps1
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `No listeners found` | Confirm terraform apply completed; check region matches |
| `manual_review_required` | The TF file has multiple `aws_lb_listener` blocks — identify the one to migrate and narrow the search |
| `GITHUB_TOKEN not set` | `export GITHUB_TOKEN=ghp_...` |
| PR body missing metadata | Ensure `dry_run=true` result was used as `migration_pr_body` for rollback |
| `prod_blocked` | Pass `allow_prod=true` and `prod_token="I-UNDERSTAND-PROD"` |

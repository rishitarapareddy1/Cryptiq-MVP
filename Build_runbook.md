# Build Runbook — Vertical Slice 1: ALB TLS → PQC Migration

**Goal of this runbook:** go from an empty repo to a demoable, end-to-end migration of one thing — an AWS ALB HTTPS listener moved from a classical TLS policy to a post-quantum hybrid policy — discovered, proposed as a real pull request, applied on merge, and rollback-able. Against *your own* AWS account.

This is the riskiest mechanic in the whole product. Once it works end to end, generalizing to more connectors, clouds, and migration types is mostly plumbing. Build this first.

**How to use this:** each task is a bounded Claude Code prompt small enough to review in one sitting. Do them in order — the order is by de-risking, not by feature completeness. Don't batch them into one mega-prompt. Review each before moving on.

---

## Prerequisites (do not skip)

This runbook assumes the learning from Weeks 1–6 is done or in progress. Specifically, before Task B1 you must personally understand:

- The AWS ALB/NLB TLS security-policy model and the current PQ policy names (the `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09` family) and supported groups (`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`). **Verify these names against live AWS docs before hardcoding them — they change.**
- How Terraform's `aws_lb_listener` `ssl_policy` field works, and how `terraform plan` produces a diff.
- The "never merge, only propose" principle and why the engine's credentials must be blast-radius-limited.

If you can't explain those three things without notes, finish the learning before you let an agent write the migration code. The agent will encode your blind spots faster than you can catch them.

---

## Recommended stack

One language across the slice keeps the agent effective and your review surface small.

- **TypeScript / Node** for discovery, the engine, and the GitHub integration. The cloud SDKs (`@aws-sdk/client-elastic-load-balancing-v2`) and the GitHub libraries (Octokit) are first-class here.
- **Terraform (HCL)** for the demo infrastructure — i.e., the ALB you'll migrate. Provision your demo target *with Terraform* so the diff path is clean and realistic.
- **Next.js (App Router)** for the thin demo dashboard in Phase D — it hosts both the UI and the engine's API routes in one place. Optional until Phase D; Phases A–C are CLI-only.
- **Vitest** for tests.

If your team is stronger in Python, the discovery and engine layers port cleanly (boto3, PyGithub); keep Terraform and the overall shape identical.

---

## Set up Claude Code for this repo first

Before Task A1, create a `CLAUDE.md` at the repo root. This is the single highest-leverage thing you can do — it's the standing context every Claude Code task inherits. Keep it short and rule-like.

**Prompt:**

> Create a `CLAUDE.md` at the repo root with these standing rules for all work in this repo:
> - This is a security product that will eventually make changes to customers' cloud infrastructure. Correctness and safety beat speed and cleverness.
> - **Never write code that mutates cloud resources, merges pull requests, or deletes anything.** The engine only ever *proposes* changes (opens PRs, generates plans). A human applies them. If a task seems to require a mutating call, stop and flag it instead.
> - All AWS calls in discovery must use read-only operations. List the read-only ELBv2 operations we use.
> - Every module gets unit tests with mocked SDK responses. No live AWS calls in tests.
> - Prefer small, typed, single-responsibility modules. Export types from a shared `src/types.ts`.
> - When you're uncertain about an AWS policy name, API shape, or PQC detail, say so in a comment and leave a `// VERIFY:` tag rather than guessing.
> - Secrets come from environment variables, never hardcoded, never committed. Use a `.env` that is gitignored.

Review what it writes, tighten it, commit it. Re-read it yourself whenever a task feels like it's drifting.

---

## Phase A — Read-only discovery of the one thing

The slice can't migrate what it can't find. Build discovery first, fully read-only, so there's zero risk while you get the AWS plumbing right.

### Task A1 — Repo scaffold

**Brick:** an empty but well-structured TypeScript repo with tests, linting, and a CLI entrypoint.

**Unknown retired:** none yet — this is hygiene. Do it fast.

**Prompt:**

> Scaffold a TypeScript Node project named `pqc-engine`. Include: `tsconfig` (strict mode), Vitest configured, ESLint + Prettier, a `src/` directory, a `src/types.ts` for shared types, a `bin/cli.ts` entrypoint wired to `npm run cli`, a gitignored `.env`, and an `out/` directory (gitignored) for generated artifacts. Add npm scripts for `build`, `test`, `lint`, and `cli`. No business logic yet — just the skeleton, and one passing smoke test.

**Review focus:** strict mode is on; `.env` and `out/` are gitignored. Trivial otherwise.

**Done when:** `npm test` and `npm run lint` pass on a clean checkout.

---

### Task A2 — Discover ALB/NLB listeners and their TLS policies

**Brick:** a module that enumerates load balancers and their current TLS policies, read-only.

**Unknown retired:** can we reliably read the real cryptographic state of TLS termination from the AWS API? (This is the foundation of all discovery.)

**Prompt:**

> Create `src/discovery/aws-tls.ts` using AWS SDK v3 (`@aws-sdk/client-elastic-load-balancing-v2`). It should: (1) list all Application and Network Load Balancers in a given region; (2) for each, list its HTTPS/TLS listeners with their current `SslPolicy`; (3) call `DescribeSSLPolicies` to resolve each policy's supported TLS protocols and key-exchange groups. Return a typed `TlsListenerAsset[]` (define the type in `src/types.ts`) with fields: `lbArn, lbName, listenerArn, port, protocol, sslPolicyName, supportedGroups, isPostQuantum`. Set `isPostQuantum` true only if the policy advertises an ML-KEM hybrid group. Add a CLI subcommand `cli discover-tls --region <r>` that prints a table and writes `out/tls-inventory.json`. Use only read-only operations. Add unit tests with fully mocked SDK responses covering: a classical-only listener, a PQ-capable listener, and an NLB. Do not call any mutating API.

**Review focus:** confirm only `Describe*` operations are used. Check the `isPostQuantum` logic against a real policy — run it against your own account and eyeball one result manually. This is where a subtle wrong assumption propagates everywhere downstream.

**Done when:** running against your real account produces a correct inventory, and you've manually verified at least one `isPostQuantum` verdict.

---

### Task A3 — Provision a demo target with Terraform

**Brick:** a known, IaC-managed ALB on a classical TLS policy — the thing you'll migrate.

**Unknown retired:** do we have a clean, realistic Terraform target whose `ssl_policy` we can diff against? (Don't migrate a console-clicked resource for the first slice; you want the IaC path honest.)

**Prompt:**

> Create a `demo-infra/` Terraform module that provisions a minimal but real ALB with one HTTPS listener on a classical security policy (`ELBSecurityPolicy-TLS13-1-2-2021-06`), using a self-signed or ACM cert, in a default VPC. Keep it cheap and tear-down-able. The `ssl_policy` must be set explicitly so it shows up in a plan diff. Include a README with `terraform apply` / `terraform destroy` steps and an estimated hourly cost. Do not apply it yourself — output the plan for me to review.

**Review focus:** cost (ALBs bill hourly — make sure you can destroy it cleanly), and that `ssl_policy` is explicit. **You** run `terraform apply`, not the agent.

**Done when:** the demo ALB exists, and Task A2's discovery finds it and reports `isPostQuantum: false`.

---

### Task A4 — Emit a minimal CBOM

**Brick:** the discovered TLS assets, expressed as a valid CycloneDX 1.6 CBOM.

**Unknown retired:** can we produce standards-conformant CBOM output? (Needed for the readiness report and GRC integrations later; cheap to nail now.)

**Prompt:**

> Create `src/cbom/from-tls.ts` that converts a `TlsListenerAsset[]` into a CycloneDX 1.6 document with `cryptographic-asset` components and `crypto-properties` (assetType `protocol`, plus the algorithm/group details). Validate output against the CycloneDX 1.6 JSON schema (add the schema and a validation test). Add CLI `cli cbom --in out/tls-inventory.json --out out/cbom.json`. Unit-test that generated CBOMs validate against the schema. Leave `// VERIFY:` tags anywhere you're unsure about the exact schema field for a crypto property.

**Review focus:** schema validation actually runs and passes. Resolve the `// VERIFY:` tags yourself against the spec.

**Done when:** `out/cbom.json` validates against the CycloneDX 1.6 schema.

---

## Phase B — The migration mechanic (highest-risk bricks)

This is the heart of the product and the part most likely to look right while being subtly wrong. Slow down. Strongest engineer reviews everything here.

### Task B1 — Compute the migration diff

**Brick:** given a discovered classical listener, produce the exact Terraform change to move it to a PQ policy — as a diff, applying nothing.

**Unknown retired:** can we correctly and safely generate the *change* (not just detect the gap)?

**Prompt:**

> Create `src/migrate/tls-plan.ts`. Given a `TlsListenerAsset` flagged `isPostQuantum: false` and the path to the Terraform repo managing it, locate the `aws_lb_listener` resource for that listener and produce a unified diff that changes only its `ssl_policy` to `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09` (make the target policy a config constant with a `// VERIFY:` note to confirm against live AWS docs). Do not modify any other field. Return `{ diff, currentPolicy, targetPolicy, resourceAddress }`. If the listener can't be confidently located in the Terraform source, return a typed "manual review required" result instead of guessing. Unit-test the locate-and-diff logic against fixture Terraform files, including the ambiguous case where it must bail to manual review. No file writes, no AWS calls, no terraform execution.

**Review focus:** the *only* field that changes is `ssl_policy`. The bail-to-manual-review path on ambiguity actually triggers — test it. This conservatism is the product's credibility; an over-eager diff engine is worse than none.

**Done when:** it emits a correct one-line-of-meaning diff for the demo ALB, and refuses to guess on a deliberately ambiguous fixture.

---

### Task B2 — Open a PR (start with a token, not a full App)

**Brick:** open a real pull request in a GitHub repo with a generated change.

**Unknown retired:** can we get a proposed change in front of a human through their normal review surface?

> **Simplification for slice 1:** use a personal access token + Octokit to open the PR against your own repo. The full multi-tenant GitHub App (Probot, installation flow, Checks API) is real work you'll need for external customers — defer it to the generalize phase. For your own infra demo, a PAT is enough and far less to review.

**Prompt:**

> Create `src/github/open-pr.ts` using Octokit and a `GITHUB_TOKEN` env var. Given a repo, a base branch, a new branch name, a file path, the new file contents, a PR title, and a PR body, it should: create the branch, commit the change, and open a pull request. It must **never** merge, never force-push, and never touch any branch other than the one it creates. Return the PR URL. Add an integration test guarded behind an env flag that runs against a throwaway test repo; default test run uses a mocked Octokit. Document the minimal token scopes required.

**Review focus:** confirm there is no merge call anywhere. Confirm minimal token scopes. The branch-only constraint is load-bearing.

**Done when:** running it opens a real PR in your test repo containing the Task B1 diff.

---

### Task B3 — Wire discovery → plan → PR

**Brick:** the end-to-end "migrate this listener" command, proposing only.

**Unknown retired:** does the whole chain hold together against real infra?

**Prompt:**

> Create `src/migrate/run.ts` and CLI `cli migrate-tls --listener <arn> --tf-repo <path> --gh-repo <owner/name>`. It composes the existing modules: confirm the listener is `isPostQuantum: false` via discovery, generate the diff via `tls-plan`, and open a PR via `open-pr` with a body that includes: the current and target policy, the rationale (HNDL risk + the relevant compliance driver), the full diff, and an explicit "review and merge to apply; this tool will not merge for you" line. If discovery shows the listener is already PQ, exit cleanly with no PR. Add a `--dry-run` flag (see B4) that does everything except open the PR and instead prints what it *would* do. Integration-test the composition with mocked dependencies.

**Review focus:** the already-migrated short-circuit works (no duplicate PRs). The PR body is honest and complete.

**Done when:** one command against your demo ALB opens a correct, human-readable migration PR.

---

### Task B4 — Dry-run and rollback (the safety pair)

**Brick:** every migration is previewable and reversible.

**Unknown retired:** can a customer trust the engine enough to grant write access? Dry-run and rollback are the concrete answers.

**Prompt:**

> Two additions. (1) Ensure `--dry-run` is a first-class mode across `migrate-tls`: it runs discovery and diff generation and prints the exact PR that would be opened, but performs no GitHub writes. (2) Create `src/migrate/rollback.ts` and `cli rollback-tls`: given a PR opened by this tool (identify via a label or branch-name convention the tool sets), generate the inverse diff that restores the original `ssl_policy`, and open a rollback PR. The original policy must be captured at migration time and stored in the PR metadata so rollback never has to guess. Test that a migrate-then-rollback cycle returns the Terraform to its exact original state.

**Review focus:** rollback restores the *exact* original policy, sourced from stored metadata, not inferred. The migrate→rollback round-trip is byte-identical on the `ssl_policy` field. This is the most important test in the slice.

**Done when:** you can migrate the demo ALB via PR, merge it, then roll it back via PR, and the Terraform is back to its starting state.

---

## Phase C — Safety hardening

The slice "works" after Phase B. Phase C is what lets it near anyone else's infrastructure. Don't demo to a prospect's security team without it.

### Task C1 — Least-privilege credential design

**Brick:** an IAM policy the engine *could* hold that is incapable of the worst case.

**Unknown retired:** can we prove to a CISO that the engine's blast radius is bounded?

**Prompt:**

> Write a least-privilege IAM policy JSON for the discovery role: read-only ELBv2 describe operations only, no write, no KMS, no secrets, no IAM. Put it in `iam/discovery-readonly.json` with an inline explanation of each permission. Separately, document in `iam/README.md` why the engine itself never holds infrastructure write credentials at all — it writes only to GitHub (proposing), and the customer's own CI/CD applies the merged change with the customer's existing credentials. Include a short "blast radius" statement: the worst thing a compromise of our credentials could do is read TLS configuration metadata and open a pull request.

**Review focus:** the blast-radius statement is actually true given the code. If any module holds an AWS write credential, that's a bug to fix now. This document is a sales asset as much as a security one.

**Done when:** the policy is minimal and the blast-radius claim is defensible.

---

### Task C2 — Guardrails and audit log

**Brick:** structural enforcement of "propose only," plus a record of every action.

**Unknown retired:** can we *enforce* the safety invariant rather than rely on it being followed?

**Prompt:**

> Add a guardrail layer. (1) A single chokepoint module that all GitHub-mutating calls route through, which hard-asserts the operation is branch-create / commit / open-PR and throws on any merge/force-push/delete attempt — so the invariant is enforced in one auditable place, not scattered. (2) An append-only JSONL audit log (`out/audit.log`) recording every discovery scan, plan, PR opened, and rollback, with timestamp, target, actor, and outcome. Unit-test that the chokepoint rejects a simulated merge attempt.

**Review focus:** there is genuinely no path to a mutating GitHub call that bypasses the chokepoint. Grep for direct Octokit mutation calls outside it.

**Done when:** the chokepoint test passes and the audit log captures a full migrate+rollback cycle.

---

### Task C3 — Environment scoping

**Brick:** the engine refuses to touch production before staging by default.

**Unknown retired:** will the engine respect customer change-management instead of bulldozing it?

**Prompt:**

> Add environment scoping. Targets are classified via a tag convention (e.g., `Environment=staging|prod`). By default, `migrate-tls` operates only on non-prod targets and requires an explicit `--allow-prod` flag plus a typed confirmation token to act on anything tagged prod. Surface the environment of each asset in discovery output and in the PR body. Test that a prod-tagged listener is skipped without the flag.

**Review focus:** prod is excluded by default, full stop. The flag-gate is annoying on purpose.

**Done when:** discovery labels environments and prod is opt-in only.

---

## Phase D — Thin demo UI

CLI is enough to *prove* the slice. A small UI is what makes it *land* in a demo. Keep it minimal.

### Task D1 — Asset dashboard

**Prompt:**

> Create a minimal Next.js (App Router) dashboard. One page: a table of TLS assets from `out/tls-inventory.json` (or a `/api/discover` route that runs discovery live), each row showing LB name, listener, current policy, environment, and a red/green PQ-status pill. No auth, no styling beyond clean defaults — this is an internal demo. Read-only view for now.

**Review focus:** it reflects real discovery output. Nothing fancy.

**Done when:** the dashboard shows your demo ALB as a red (non-PQ) row.

---

### Task D2 — The hero button

**Prompt:**

> Add an "Open migration PR" button to each red row, wired to a `/api/migrate` route that runs the `migrate-tls` flow in dry-run first (showing the proposed diff in a modal), then on confirm opens the real PR and displays the PR link. Add a "Roll back" affordance for rows with an open migration PR. Surface the audit log on a second tab. Keep all the safety gates from Phase C intact — the UI calls the same engine, it does not bypass it.

**Review focus:** the UI path goes through the exact same guardrailed engine as the CLI — no shortcut endpoints that skip the chokepoint or env scoping.

**Done when:** in the browser, you click a red row → see the diff → confirm → a real PR opens → you merge it in GitHub → the row goes green → you roll it back.

---

## Phase E — Demo script and teardown

### Task E1 — End-to-end demo runbook

**Prompt:**

> Write `DEMO.md`: a step-by-step script to run the full slice against a fresh AWS account from zero — provision the demo ALB, run discovery, show the dashboard, trigger a migration PR, merge it, show it go green, roll it back, and tear everything down. Include the expected output at each step and the teardown commands. Add a `make demo-reset` that returns everything to the starting state.

**Done when:** someone else on the team can run `DEMO.md` start to finish without you in the room.

---

## What you'll have at the end

A working, honest, end-to-end migration of one real thing — the exact "hero moment" the Week 9–10 prototype calls for, built in de-risking order with every dangerous brick reviewed by hand. From here, generalizing is the agent-friendly part: more discovery connectors, a second cloud, the full GitHub App for multi-tenancy, the vendor-readiness backend, the readiness-report generator. Those reuse the patterns this slice establishes, so Claude Code gets *more* effective from here, not less.

## Three standing rules while you build

1. **The agent proposes; you decide on anything that touches safety or crypto correctness.** Phases B and C are where "looks right" and "is right" diverge most.
2. **Don't let building crowd out the 15 customer conversations.** A perfect migration engine nobody will grant write access to is a science project. The conversations and the code are both due; the conversations are easier to skip and matter more.
3. **Re-verify the moving facts before they ship in front of anyone** — the PQ policy names, the supported groups, which AWS services have gained PQC support. They change quarterly. Keep the `// VERIFY:` tags honest.
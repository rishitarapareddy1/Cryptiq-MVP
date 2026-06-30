# CLAUDE.md — Standing context for the pqc-engine repo

## What this is
A security product that discovers quantum-vulnerable cryptography in a company's
infrastructure and PROPOSES migrations to post-quantum algorithms. It will
eventually operate in customers' environments. Correctness and safety beat speed,
cleverness, and feature completeness — every time.

## The non-negotiable invariant: PROPOSE, NEVER APPLY
- The engine NEVER mutates cloud resources. No create/update/delete on any AWS
  (or other cloud) resource. Discovery is read-only; migration output is a diff.
- The engine NEVER merges, force-pushes, or deletes in Git. It only creates a
  branch, commits, and opens a pull request. A human merges. The customer's own
  CI/CD applies the merged change with the customer's own credentials.
- If a task appears to require a mutating cloud call or a merge, STOP and flag it
  in your response. Do not implement it. This is not a preference; it is the
  product's core safety guarantee and the basis on which customers grant access.

## AWS rules
- Discovery uses only read-only operations (Describe*, List*, Get*). Never a
  mutating ELBv2/KMS/IAM/Secrets call.
- The engine holds no infrastructure WRITE credential, ever. Its only write
  surface is GitHub (proposing). State this blast-radius fact plainly when asked.
- Cross-account access (later, for tenants) uses an IAM role with an ExternalId,
  never long-lived keys.

## Crypto correctness
- Post-quantum policy names, supported groups, and which services have PQC support
  CHANGE OFTEN. Never hardcode one from memory. Put it in a config constant with a
  `// VERIFY:` tag and a link to the live AWS doc you confirmed it against.
- When unsure about an algorithm, a CBOM schema field, or whether a change is
  semantically safe to automate, leave a `// VERIFY:` tag and say so. Do not guess.
- Anything touching custom crypto, persisted encrypted data, root/HSM keys, or
  vendor-controlled crypto is OUT OF SCOPE for automation — flag it as
  "manual review required," never generate a change for it.

## Engineering conventions
- TypeScript strict mode. Small, single-responsibility, typed modules.
- Shared types live in `src/types.ts`.
- Every module ships with unit tests using MOCKED SDK responses. No live cloud
  calls in tests.
- All GitHub-mutating calls route through one chokepoint module that hard-asserts
  the operation is branch-create / commit / open-PR. Nothing bypasses it.
- Every engine action (scan, plan, PR, rollback) writes to the append-only audit
  log with timestamp, target, actor, outcome.
- Secrets come from env vars. Never hardcoded, never committed. `.env` is gitignored.

## When in doubt
Ask or flag rather than proceed. A flagged uncertainty costs a sentence; a wrong
guess in this product costs a customer incident.
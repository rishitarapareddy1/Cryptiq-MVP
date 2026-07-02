# RUNBOOK — where every file goes, then run it two ways

This supersedes the scattered instructions from earlier messages. One
source of truth from here.

## Repo layout after copying everything in

```
Cryptiq-MVP/
├── api.py                              ← replace (merged version)
├── code_signing/                       ← new folder, copy in whole
│   ├── __init__.py
│   ├── api.py
│   ├── backends/
│   │   ├── __init__.py
│   │   ├── generic.py
│   │   ├── github_actions.py
│   │   └── native.py
│   ├── cbom.py
│   ├── database.py
│   ├── discovery.py
│   ├── keystore.py
│   ├── signer.py
│   └── types.py
├── password_hashing/                   ← new folder, copy in whole
│   ├── __init__.py
│   ├── api.py
│   ├── cbom.py
│   ├── database.py
│   ├── hardener.py
│   ├── platforms.py
│   ├── risk.py
│   ├── scanner.py
│   └── types.py
├── tests/
│   ├── test_code_signing.py            ← new
│   ├── test_password_hashing.py        ← new
│   └── test_extensibility.py           ← new
├── demo_signing_artifacts/             ← new, for code-signing demo
│   ├── CHANGELOG.md
│   ├── cli.py
│   ├── install.sh
│   ├── release.yaml
│   └── subdir/helper.py
├── pwhash_samples/                     ← new, for password-hashing demo
│   ├── Dockerfile.pwhash_target
│   ├── sample_shadow.txt
│   ├── sample_windows_dump.txt
│   ├── sample_cisco_ios.txt
│   └── sample_panos.txt
├── docker-compose.yml                  ← replace (adds codesign/pwhash env vars + volume note)
├── docker-compose.tools-fleet.yml      ← new, sits next to docker-compose.fleet.yml
└── frontend/
    ├── next.config.js                  ← replace (adds /codesign, /pwhash to proxy)
    ├── app/
    │   ├── page.tsx                    ← replace (adds Code Signing + Password Hashing cards)
    │   ├── codesign/page.tsx           ← replace with the codesign version
    │   └── pwhash/page.tsx             ← replace with the pwhash version
    └── components/
        └── Icon.tsx                    ← replace (adds sign/verify/hash/workflow icons)
```

Every "new folder, copy in whole" item: create the folder if it doesn't
exist, drop every file from that section of this delivery into it.
Every "replace" item: the delivered file is the full file, not a diff —
overwrite what's there.

---

## 1. Running the website

**Terminal 1 — backend**
```bash
cd Cryptiq-MVP
source venv/bin/activate
pip install -r requirements.txt      # code_signing/password_hashing only use
                                      # cryptography + SQLAlchemy, both already listed
python api.py
```
Wait for `Application startup complete.` Confirm:
```bash
curl http://127.0.0.1:8000/health
```
→ `{"status":"ok","service":"cryptiq","version":"1.1.0"}`

**Terminal 2 — frontend**
```bash
cd Cryptiq-MVP/frontend
npm install        # only if you haven't already
npm run dev
```
Open **http://localhost:3000**.

That `⚠ Warning: Next.js inferred your workspace root... Detected
additional lockfiles` you saw is unrelated to anything here — it's
because there's a `package-lock.json` at both the repo root and in
`frontend/`. Harmless, but to silence it permanently, add to
`frontend/next.config.js`:
```js
const nextConfig = {
  turbopack: { root: __dirname },
  // ...rest of your config
};
```

**Sanity check the two new routers are live:**
```bash
curl -s http://127.0.0.1:8000/openapi.json \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print([p for p in d['paths'] if p.startswith('/codesign') or p.startswith('/pwhash')])"
```
Should print ~20 paths, not `[]`.

Then click through:
- http://localhost:3000/codesign
- http://localhost:3000/pwhash

Full click-by-click checklist for both (and SSH) is in `TESTING.md`.

---

## 2. Running everything from the command line

### 2a. Run the test suite
```bash
cd Cryptiq-MVP
source venv/bin/activate
pytest tests/test_code_signing.py tests/test_password_hashing.py tests/test_extensibility.py -v
```
Expect **142 passed**. Run the full suite (`pytest`) to confirm nothing
else regressed — expect everything green except the pre-existing,
unrelated `TestPageRoutes` failures (those check for static HTML pages
that predate the Next.js frontend; not something this delivery touches).

### 2b. Docker containers — what each one is and how to start it

You end up with **three separate docker-compose files**, each doing a
different job. You don't need all of them running at once — start
whichever ones match what you're testing.

| File | What it starts | When you need it |
|---|---|---|
| `docker-compose.yml` | The Cryptiq backend itself, containerized | Only if you want to run the *backend* in Docker instead of `python api.py` directly. For local dev, running `python api.py` on your Mac (as you're already doing) is simpler — skip this file entirely unless you specifically want a containerized backend. |
| `docker-compose.fleet.yml` *(already in your repo)* | SSH test targets: `ssh_target` (modern, port 2222) and `ssh_legacy` (deliberately weak, port 2223) | Testing the SSH Scanner/Migration pages |
| `docker-compose.tools-fleet.yml` *(new)* | `pwhash_target`: a container with a real, mixed-strength `/etc/shadow` | Testing the Password Hashing → Linux tab against a real file instead of pasting the sample text |

**Start the SSH fleet** (you already have this file, just hadn't started it):
```bash
cd Cryptiq-MVP
docker compose -f docker-compose.fleet.yml up -d
docker ps    # confirm cryptiq_ssh_target and cryptiq_ssh_legacy are running
nc -zv localhost 2222   # should say "succeeded"
nc -zv localhost 2223   # should say "succeeded"
```
Now go scan `localhost:2222` and `localhost:2223` in the SSH Scanner page
— `2222` should come back clean-ish, `2223` should come back
critical/quantum-vulnerable. (This is the fix for the blank-scan issue
from your last message — nothing was listening on those ports before.)

**Start the password-hashing target:**
```bash
docker compose -f docker-compose.tools-fleet.yml up -d --build
docker exec cryptiq_pwhash_target cat /etc/shadow
```
Copy that output into the Linux tab on `/pwhash` instead of the static
sample file.

**Code signing needs no container at all** — point the Discover field at
`demo_signing_artifacts/` using its absolute path on whatever machine is
running `python api.py` (e.g.
`/Users/pranav/Documents/Cryptiq-MVP/demo_signing_artifacts`).

**If you do run the backend containerized** (`docker-compose.yml`), the
same `demo_signing_artifacts/` directory is visible *inside* that
container at `/app/demo_signing_artifacts` (because that compose file
bind-mounts the whole repo) — use that path instead in the UI.

**Tear everything down when you're done:**
```bash
docker compose -f docker-compose.fleet.yml down
docker compose -f docker-compose.tools-fleet.yml down
```

### 2c. Everything in one shot, if you just want it all running
```bash
cd Cryptiq-MVP
docker compose -f docker-compose.fleet.yml up -d
docker compose -f docker-compose.tools-fleet.yml up -d --build
source venv/bin/activate && python api.py &
cd frontend && npm run dev
```
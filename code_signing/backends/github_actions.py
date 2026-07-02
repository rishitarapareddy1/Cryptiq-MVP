"""
code_signing/backends/github_actions.py
------------------------------------------
This is the answer to "most code signing happens in GitHub CI/CD, I want
to change that too": a PROPOSAL backend. It doesn't sign anything itself
— it generates a `.github/workflows/*.yml` file that signs release
artifacts automatically on every future release, which is how code
signing actually runs in most companies' pipelines (a release-time CI
step, not a manual local action — see the note in signer.py's docstring).

Two methods, pick with `method=`:
  - "cosign"  : Sigstore cosign, keyless OIDC signing (no key management
                at all — identity comes from the GitHub Actions OIDC
                token). This is the modern default for most orgs.
  - "gpg"     : traditional GPG detached-sign against a secret key stored
                in a GitHub Actions secret. Use this if the counterparty
                you're sending artifacts to expects a GPG signature
                specifically (e.g. verifying against a known public key
                out-of-band, common for .deb/.rpm repos).

WIRING THIS TO ACTUALLY OPEN A PR (natural next step, not done here):
Cryptiq already has a "propose via GitHub PR, human merges" pipeline in
tls_migration/github_pr.py, used by the ALB TLS migration feature. The
generated workflow YAML from propose() below is exactly the kind of
single-file diff that pipeline is built to open a PR for — pass the
returned `path` and `content` into that module's PR-opening function the
same way tls_migration/run.py does for its Terraform diff. Not wired here
because it means reading and matching github_pr.py's exact function
signature rather than guessing it; flagging the seam clearly instead.
"""

from __future__ import annotations

from code_signing.backends import SigningBackendInfo, register

_COSIGN_WORKFLOW = """\
name: Sign release artifacts (cosign, keyless)

on:
  release:
    types: [published]

permissions:
  contents: read
  id-token: write   # required for keyless OIDC signing

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install cosign
        uses: sigstore/cosign-installer@v3

      - name: Sign each release asset
        env:
          GH_TOKEN: ${{{{ github.token }}}}
        run: |
          for asset in {glob_pattern}; do
            [ -e "$asset" ] || continue
            cosign sign-blob --yes "$asset" \\
              --output-signature "$asset.sig" \\
              --output-certificate "$asset.pem"
          done

      - name: Upload signatures to the release
        env:
          GH_TOKEN: ${{{{ github.token }}}}
        run: |
          gh release upload "${{{{ github.event.release.tag_name }}}}" \\
            {glob_pattern}.sig {glob_pattern}.pem --clobber
"""

_GPG_WORKFLOW = """\
name: Sign release artifacts (GPG)

on:
  release:
    types: [published]

permissions:
  contents: write

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Import signing key
        run: |
          echo "${{{{ secrets.CODESIGN_GPG_PRIVATE_KEY }}}}" | gpg --batch --import
        env:
          GPG_TTY: $(tty)

      - name: Sign each release asset
        run: |
          for asset in {glob_pattern}; do
            [ -e "$asset" ] || continue
            gpg --batch --yes --local-user "${{{{ secrets.CODESIGN_GPG_KEY_ID }}}}" \\
              --detach-sign --armor "$asset"
          done

      - name: Upload signatures to the release
        env:
          GH_TOKEN: ${{{{ github.token }}}}
        run: |
          gh release upload "${{{{ github.event.release.tag_name }}}}" {glob_pattern}.asc --clobber
"""

_TEMPLATES = {"cosign": _COSIGN_WORKFLOW, "gpg": _GPG_WORKFLOW}


def run(
    method: str = "cosign",
    glob_pattern: str = "dist/*",
    workflow_filename: str = "sign-release.yml",
    dry_run: bool = True,
    output_repo_path: str | None = None,
    **_kwargs,
) -> dict:
    template = _TEMPLATES.get(method)
    if not template:
        raise ValueError(f"Unknown method '{method}'. Use one of: {list(_TEMPLATES)}")

    content = template.format(glob_pattern=glob_pattern)
    rel_path = f".github/workflows/{workflow_filename}"

    result = {
        "backend": "github_actions", "method": method,
        "path": rel_path, "content": content, "applied": False,
    }

    if not dry_run and output_repo_path:
        from pathlib import Path
        target = Path(output_repo_path) / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        result["applied"] = True
        result["written_to"] = str(target)

    return result


register(SigningBackendInfo(
    id="github_actions", label="GitHub Actions workflow (proposal)", kind="proposal",
    description="Generates a .github/workflows/*.yml that signs every future release "
                "automatically via cosign (keyless) or GPG — doesn't sign anything itself, "
                "it produces the CI config that does. Always available (no local tool required "
                "to generate the file; running it obviously requires the repo's CI).",
    available=lambda: True,
    run=run,
))
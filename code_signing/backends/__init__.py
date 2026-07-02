"""
code_signing/backends/__init__.py
------------------------------------
Plugin registry for "how do I actually sign this file / what process
produces the signature". Two kinds of backend:

  1. DIRECT backends: actually produce a signature right now, on this
     machine (native OS tool, or Cryptiq's own generic Ed25519/RSA-PSS).
  2. PROPOSAL backends: don't sign anything themselves — they generate a
     CI/CD pipeline artifact (a workflow file) that will do the signing
     on every future release, because that's how most companies actually
     run code signing in practice: as an automated release step, not an
     ad hoc local action. See github_actions.py.

Adding a new backend — a new CI system, a new native tool, a new signing
service (e.g. a cloud KMS/HSM-backed signer, Sigstore/cosign keyless,
Azure Trusted Signing) — is one call to register(), same shape either way:

    from code_signing.backends import SigningBackendInfo, register

    register(SigningBackendInfo(
        id="gitlab_ci", label="GitLab CI", kind="proposal",
        description="Generates a .gitlab-ci.yml signing job.",
        available=lambda: True,
        run=my_gitlab_ci_workflow_generator,
    ))

GET /codesign/backends is driven entirely off this registry, same pattern
as password_hashing/platforms.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Literal, Optional

BackendKind = Literal["direct", "proposal"]


@dataclass
class SigningBackendInfo:
    id: str
    label: str
    kind: BackendKind
    description: str
    available: Callable[[], bool]
    # DIRECT backends implement run(path, **kwargs) -> FileSignature-shaped dict
    # PROPOSAL backends implement run(**kwargs) -> dict describing the generated artifact
    run: Callable[..., Any]

    def to_dict(self) -> dict:
        return {
            "id": self.id, "label": self.label, "kind": self.kind,
            "description": self.description, "available": self.available(),
        }


_REGISTRY: dict[str, SigningBackendInfo] = {}


def register(backend: SigningBackendInfo) -> None:
    _REGISTRY[backend.id] = backend


def get(backend_id: str) -> Optional[SigningBackendInfo]:
    return _REGISTRY.get(backend_id)


def list_backends() -> list[dict]:
    return [b.to_dict() for b in _REGISTRY.values()]


# Import built-ins for their registration side-effects.
from code_signing.backends import native as _native  # noqa: E402,F401
from code_signing.backends import generic as _generic  # noqa: E402,F401
from code_signing.backends import github_actions as _github_actions  # noqa: E402,F401
"""
code_signing/discovery.py
---------------------------
Recursive directory walk for "what in this tree is worth signing".

Answers your "given many files of code like a whole directory, identify
the files recursively" requirement. Read-only: hashes files, never opens
them for writing.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from code_signing.types import (
    DiscoveredFile, SignerKind, SIGNABLE_EXTENSIONS, DEFAULT_EXCLUDE_DIRS,
)

CHUNK = 1024 * 1024  # 1MB


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _classify(path: Path) -> Optional[SignerKind]:
    # double extensions first (.tar.gz)
    name = path.name.lower()
    for ext, kind in SIGNABLE_EXTENSIONS.items():
        if ext.count(".") > 1 and name.endswith(ext):
            return kind
    suffix = path.suffix.lower()
    return SIGNABLE_EXTENSIONS.get(suffix)


def discover_signable_files(
    root: str,
    extensions: Optional[list[str]] = None,
    exclude_dirs: Optional[set[str]] = None,
    sign_everything: bool = False,
    max_files: int = 5000,
) -> list[DiscoveredFile]:
    """
    Walk `root` recursively and return every file Cryptiq would sign.

    Args:
        root            : directory to walk
        extensions      : restrict to these extensions only (e.g. [".exe",".dll"]).
                           None = use the default signable-extension map.
        exclude_dirs    : directory names to skip (defaults to vendor/build noise)
        sign_everything : if True, ignore the extension map and hash every
                           regular file under root (still respects exclude_dirs).
        max_files       : safety cap so a bad path doesn't hash a whole disk
    """
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    exclude = exclude_dirs if exclude_dirs is not None else DEFAULT_EXCLUDE_DIRS
    allow = {e.lower() for e in extensions} if extensions else None

    out: list[DiscoveredFile] = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in exclude and not d.startswith(".git")]
        for fname in filenames:
            if len(out) >= max_files:
                return out
            if fname.endswith(".cryptiq.sig.json"):
                continue  # never re-discover/re-sign our own signature sidecars
            fpath = Path(dirpath) / fname

            kind = _classify(fpath)
            if not sign_everything:
                if kind is None:
                    continue
                if allow is not None and fpath.suffix.lower() not in allow:
                    continue
            else:
                kind = kind or SignerKind.GENERIC

            try:
                stat = fpath.stat()
                digest = _sha256_file(fpath)
            except (OSError, PermissionError):
                continue

            out.append(DiscoveredFile(
                path=str(fpath),
                size_bytes=stat.st_size,
                sha256=digest,
                extension=fpath.suffix.lower() or "(none)",
                recommended_signer=kind,
                mtime=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            ))
    return out


def summarize_discovery(files: list[DiscoveredFile]) -> dict:
    by_signer: dict[str, int] = {}
    total_bytes = 0
    for f in files:
        by_signer[f.recommended_signer.value] = by_signer.get(f.recommended_signer.value, 0) + 1
        total_bytes += f.size_bytes
    return {
        "total_files": len(files),
        "total_bytes": total_bytes,
        "by_recommended_signer": by_signer,
    }
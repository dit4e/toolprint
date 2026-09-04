"""What is on disk, as opposed to what a server says about itself.

A server's self-reported version is a claim, and across 29 public servers 16 of
them made a claim that did not match their published package - several a year
stale, one the literal string "0.8.x", one the version of a bundled dependency.

The package manager's own cache is the second opinion, and reading it stays
inside the offline guarantee: this is the local filesystem, not a registry.

What this can and cannot say:

  * It reports the version the package manager has on disk for a given spec.
    For `npx -y pkg` that is the copy npx would run, because npx keys its cache
    directory by the spec and reuses it.
  * It cannot prove that copy is the one that just ran. A cache cleared between
    the scan and the read, or two entries for the same package, make the answer
    ambiguous - so every distinct version found is reported rather than one
    being picked.
  * It finds nothing for a server that has never been run on this machine, which
    is not an error: absence of a cached copy is absence of evidence.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import List, Optional, Sequence

# npm keys each npx cache directory by a hash of the requested spec, and records
# that spec in a package.json at the top of the directory.
NPX_ROOTS = ("~/.npm/_npx",)
UV_ROOTS = ("~/.cache/uv/archive-v0", "~/Library/Caches/uv/archive-v0")

MAX_NPX_DIRS = 400          # a busy machine accumulates these; do not walk forever


def package_from_args(command: Optional[str], args: Sequence[str]) -> Optional[str]:
    """The package a runner was asked for, without any version suffix."""
    if not command:
        return None
    for arg in args or ():
        if arg.startswith("-"):
            continue
        spec = arg
        # "@scope/pkg@1.2.3" -> "@scope/pkg";  "pkg==1.2.3" -> "pkg"
        spec = re.split(r"[=<>!~]=*", spec, 1)[0]
        at = spec.rfind("@")
        if at > 0:
            spec = spec[:at]
        return spec or None
    return None


def _read_version(path: Path) -> Optional[str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8")).get("version")
    except (OSError, ValueError):
        return None
    return value if isinstance(value, str) else None


def npm_versions(package: str) -> List[str]:
    """Versions of `package` present in npx's cache, newest-listed first."""
    found: List[str] = []
    for root in NPX_ROOTS:
        base = Path(os.path.expanduser(root))
        if not base.is_dir():
            continue
        try:
            entries = sorted(base.iterdir(), key=lambda p: p.name)[:MAX_NPX_DIRS]
        except OSError:
            continue
        for entry in entries:
            marker = entry / "package.json"
            if not marker.is_file():
                continue
            try:
                deps = json.loads(marker.read_text(encoding="utf-8")).get("dependencies")
            except (OSError, ValueError):
                continue
            # The marker names the spec this directory was created for.
            if not isinstance(deps, dict) or package not in deps:
                continue
            version = _read_version(entry / "node_modules" / Path(package) / "package.json")
            if version and version not in found:
                found.append(version)
    return found


def _normalise(name: str) -> str:
    """PEP 503-ish: a distribution name compared without punctuation or case."""
    return re.sub(r"[-_.]+", "_", name).lower()


def uv_versions(package: str) -> List[str]:
    """Versions of `package` in uv's archive cache, read from .dist-info names.

    uv stores wheels unpacked under archive-v0/<opaque>/<name>-<version>.dist-info
    with the distribution name normalised, so `mcp-server-time` is on disk as
    `mcp_server_time-2025.9.25.dist-info`.
    """
    wanted = _normalise(package)
    found: List[str] = []
    for root in UV_ROOTS:
        base = Path(os.path.expanduser(root))
        if not base.is_dir():
            continue
        try:
            archives = list(base.iterdir())
        except OSError:
            continue
        for archive in archives:
            try:
                names = os.listdir(archive)
            except OSError:
                continue
            for name in names:
                if not name.endswith(".dist-info"):
                    continue
                stem = name[: -len(".dist-info")]
                dist, _, version = stem.rpartition("-")
                if dist and version and _normalise(dist) == wanted and version not in found:
                    found.append(version)
    return found


def versions_on_disk(command: Optional[str], args: Sequence[str]) -> List[str]:
    """Every version of the requested package the local package manager holds."""
    package = package_from_args(command, args)
    if not package:
        return []
    base = os.path.basename(command or "")
    if base.startswith("npx") or base.startswith("npm"):
        return npm_versions(package)
    if base.startswith("uvx") or base.startswith("uv"):
        return uv_versions(package)
    return []

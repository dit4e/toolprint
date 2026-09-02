"""Config discovery and parsing. No network, no subprocesses, ever.

This is the --no-connect path in full: it reads JSON files off disk and produces
an Inventory. It must be safe to run anywhere without explanation, which is why
it has no import of subprocess or urllib.
"""

from __future__ import annotations

import glob
import json
import os
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from . import auth, registry
from .model import CollectionError, Inventory, Server

# Config keys that mark a server as switched off, across clients.
DISABLED_KEYS = ("disabled", "isDisabled")


def normalise_root(path: Optional[str]) -> Optional[str]:
    """Canonical form of a project path, so one project is always one context.

    Claude Code stores project keys as the user typed them, while discovered
    config files carry the path we globbed. On macOS those routinely differ -
    /var vs /private/var, /tmp vs /private/tmp - and a symlinked home or
    checkout does the same on Linux. Left unnormalised, one project splits into
    two contexts and every per-context number is computed over half the servers.
    """
    if not path:
        return None
    try:
        return str(Path(path).resolve())
    except OSError:
        return path


def _walk_container(doc: object, steps: Sequence[str], label: Optional[str] = None) -> Iterator[Tuple[Optional[str], dict]]:
    """Yield (label, servers_dict) for each container the descriptor selects.

    "*" means every key at this level is its own container and its name becomes
    the label - that is how Claude Code's projects["<path>"].mcpServers works.
    """
    if not isinstance(doc, dict):
        return
    if not steps:
        yield label, doc
        return
    step, rest = steps[0], steps[1:]
    if step == "*":
        for key, value in doc.items():
            for item in _walk_container(value, rest, key):
                yield item
    elif step in doc:
        for item in _walk_container(doc[step], rest, label):
            yield item


def _normalise_transport(raw_type: Optional[str], command: Optional[str], url: Optional[str]) -> Tuple[str, List[str]]:
    notes: List[str] = []
    if isinstance(raw_type, str):
        declared = raw_type.strip().lower()
        if declared in ("stdio", "http", "sse", "ws"):
            return declared, notes
        if declared in ("streamable-http", "streamablehttp", "http-stream"):
            return "http", notes
        if declared == "websocket":
            return "ws", notes
        notes.append("unrecognised transport type {!r}; inferred instead".format(raw_type))
    if command:
        return "stdio", notes
    if url:
        scheme = url.split("://", 1)[0].lower() if "://" in url else ""
        if scheme in ("ws", "wss"):
            return "ws", notes
        if scheme in ("http", "https"):
            # Cannot distinguish Streamable HTTP from legacy SSE without connecting.
            notes.append("http transport assumed; SSE vs Streamable HTTP needs --connect")
            return "http", notes
    return "unknown", notes


def parse_server(
    name: str,
    raw: object,
    client_id: str,
    scope: str,
    scope_detail: Optional[str],
    source_path: str,
    project_root: Optional[str] = None,
) -> Optional[Server]:
    if not isinstance(raw, dict):
        return None

    command = raw.get("command") if isinstance(raw.get("command"), str) else None
    url = raw.get("url") if isinstance(raw.get("url"), str) else None
    args = [a for a in raw.get("args", []) if isinstance(a, str)] if isinstance(raw.get("args"), list) else []
    env = raw.get("env") if isinstance(raw.get("env"), dict) else {}
    headers = raw.get("headers") if isinstance(raw.get("headers"), dict) else {}
    headers_helper = raw.get("headersHelper") if isinstance(raw.get("headersHelper"), str) else None
    has_oauth = isinstance(raw.get("oauth"), dict)

    transport, notes = _normalise_transport(raw.get("type"), command, url)
    secrets = auth.scan_for_secrets(headers, env, args, url)
    auth_method, auth_notes = auth.classify(secrets, headers, env, headers_helper, has_oauth)

    enabled = True
    for key in DISABLED_KEYS:
        if raw.get(key) is True:
            enabled = False
    if raw.get("enabled") is False:
        enabled = False

    return Server(
        name=name,
        client=client_id,
        scope=scope,
        scope_detail=scope_detail,
        source_path=source_path,
        project_root=project_root,
        transport=transport,
        command=command,
        args=args,
        url=url,
        env_names=sorted(env.keys()),
        header_names=sorted(headers.keys()),
        headers_helper=headers_helper,
        raw_headers={k: v for k, v in headers.items() if isinstance(v, str)},
        raw_env={k: v for k, v in env.items() if isinstance(v, str)},
        has_oauth=has_oauth,
        enabled=enabled,
        auth_method=auth_method,
        secret_locations=secrets,
        parse_notes=notes + auth_notes,
    )


def parse_file(
    path: Path,
    client: registry.Client,
    source: registry.Source,
    project_root: Optional[str] = None,
) -> Tuple[List[Server], List[CollectionError]]:
    servers: List[Server] = []
    errors: List[CollectionError] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(CollectionError(str(path), client.id, "unreadable", str(exc)))
        return servers, errors
    try:
        doc = json.loads(text)
    except ValueError as exc:
        errors.append(CollectionError(str(path), client.id, "malformed", "invalid JSON: {}".format(exc)))
        return servers, errors

    for label, container in _walk_container(doc, source.container):
        if not isinstance(container, dict):
            continue
        for name, raw in container.items():
            # Claude Code's local scope names its project in the container key;
            # workspace/project scopes take it from the root the file was found under.
            applies_to = normalise_root(
                label if source.container is registry.AT_CLAUDE_PROJECTS else project_root
            )
            server = parse_server(
                name, raw, client.id, source.scope, label, str(path), applies_to
            )
            if server is None:
                errors.append(
                    CollectionError(
                        str(path),
                        client.id,
                        "unexpected_shape",
                        "server {!r} is not an object".format(name),
                    )
                )
                continue
            servers.append(server)
    return servers, errors


def claude_code_project_roots(home: Path) -> List[Path]:
    """Project directories Claude Code already knows about.

    A better source of candidate project roots than guessing at a directory tree:
    these are paths the user has actually worked in.
    """
    config = home / ".claude.json"
    if not config.is_file():
        return []
    try:
        doc = json.loads(config.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    projects = doc.get("projects")
    if not isinstance(projects, dict):
        return []
    return [Path(p).resolve() for p in projects if isinstance(p, str) and Path(p).is_dir()]


def expand_project_roots(patterns: Iterable[str], home: Path, use_claude_projects: bool = True) -> List[Path]:
    roots: List[Path] = []
    seen = set()

    def add(path: Path) -> None:
        resolved = path.resolve()
        if resolved.is_dir() and str(resolved) not in seen:
            seen.add(str(resolved))
            roots.append(resolved)

    if use_claude_projects:
        for path in claude_code_project_roots(home):
            add(path)
    for pattern in patterns:
        expanded = os.path.expanduser(pattern)
        matches = glob.glob(expanded)
        if matches:
            for match in matches:
                add(Path(match))
        else:
            add(Path(expanded))
    return roots


def _candidate_paths(
    source: registry.Source, home: Path, project_roots: Sequence[Path]
) -> List[Tuple[Path, Optional[str]]]:
    bases = [home] if source.where == registry.HOME else list(project_roots)
    paths: List[Tuple[Path, Optional[str]]] = []
    for base in bases:
        root = None if source.where == registry.HOME else str(base)
        pattern = str(base / source.pattern)
        if any(ch in source.pattern for ch in "*?["):
            paths.extend((Path(p), root) for p in sorted(glob.glob(pattern)))
        else:
            paths.append((Path(pattern), root))
    return paths


def collect(
    clients: Optional[Sequence[str]] = None,
    explicit_configs: Optional[Sequence[str]] = None,
    project_patterns: Optional[Sequence[str]] = None,
    home: Optional[Path] = None,
    use_claude_projects: bool = True,
) -> Inventory:
    """Walk the registry and build an Inventory. Failures are recorded, not raised."""
    home = home or Path.home()
    inventory = Inventory()

    if explicit_configs:
        # Explicit --config disables auto-discovery: if you name the files,
        # finding others would be surprising.
        for raw_path in explicit_configs:
            path = Path(os.path.expanduser(raw_path))
            inventory.paths_scanned.append(str(path))
            if not path.is_file():
                inventory.errors.append(CollectionError(str(path), None, "unreadable", "no such file"))
                continue
            matched = _parse_unknown_shape(path, inventory)
            if not matched:
                inventory.errors.append(
                    CollectionError(str(path), None, "unexpected_shape", "no recognised server container")
                )
        _finalise(inventory)
        return inventory

    roots = expand_project_roots(project_patterns or [], home, use_claude_projects)

    for client in registry.CLIENTS:
        if clients and client.id not in clients:
            continue
        for source in client.sources:
            if not registry.applies_here(source):
                continue
            for path, root in _candidate_paths(source, home, roots):
                if not path.is_file():
                    continue
                inventory.paths_scanned.append(str(path))
                servers, errors = parse_file(path, client, source, root)
                inventory.servers.extend(servers)
                inventory.errors.extend(errors)

    _finalise(inventory)
    return inventory


def _parse_unknown_shape(path: Path, inventory: Inventory) -> bool:
    """For --config, try each known container shape until one yields servers."""
    shapes = [
        ("mcpServers", registry.AT_MCPSERVERS),
        ("servers", registry.AT_SERVERS),
        ("projects", registry.AT_CLAUDE_PROJECTS),
    ]
    matched = False
    for label, container in shapes:
        pseudo_client = registry.Client(id="explicit", name="explicit --config")
        pseudo_source = registry.Source(registry.HOME, str(path), "explicit", container)
        servers, errors = parse_file(path, pseudo_client, pseudo_source)
        inventory.errors.extend(errors)
        if servers:
            matched = True
            inventory.servers.extend(servers)
    return matched


def _finalise(inventory: Inventory) -> None:
    # De-duplicate scanned paths while preserving order.
    seen: Dict[str, None] = {}
    for path in inventory.paths_scanned:
        seen.setdefault(path, None)
    inventory.paths_scanned = list(seen)
    inventory.clients_found = sorted({s.client for s in inventory.servers})
    # Deterministic ordering: the two-run test in M2 depends on this.
    inventory.servers.sort(key=lambda s: (s.client, s.scope, s.scope_detail or "", s.name))

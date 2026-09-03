"""The approved baseline: what the tool surface looked like when someone reviewed it.

A baseline records component hashes plus just enough schema shape to say *how* a
schema changed - whether a parameter was removed, a type narrowed, or a required
field added - because "the schema hash changed" is not actionable on its own.

Identity is `name@transport:endpoint`, not the config key. Moving a server from
user scope to project scope is not tool drift and must not read as any, whereas
the same name pointing at a different endpoint is a different server and should.

False-positive management is not optional here. `approve` records who accepted
what and when; `exceptions` carry a reason and an expiry so a standing exception
cannot become permanent by neglect. Without both, this recreates certificate
warning fatigue and users will --fail-on none it into irrelevance.
"""

from __future__ import annotations

import datetime
import json
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__, canonical, effects, lexical
from .model import Inventory, Server

BASELINE_VERSION = 1
DEFAULT_PATH = ".toolprint-baseline.json"


def server_identity(server: Server) -> str:
    endpoint = server.url_host or server.command_basename or "?"
    return "{}@{}:{}".format(server.name, server.transport, endpoint)


def _schema_shape(schema: Any) -> Dict[str, Any]:
    """Enough of a schema to classify a later change, and no more.

    Storing the whole schema would make the baseline a second copy of the tool
    surface; storing only a hash would make every change indistinguishable.
    """
    resolved, _ = canonical.canonicalise(schema, resolve=True)
    if not isinstance(resolved, dict):
        return {"required": [], "properties": {}}
    properties = resolved.get("properties")
    shape: Dict[str, List[str]] = {}
    if isinstance(properties, dict):
        for name in sorted(properties):
            value = properties[name]
            declared = value.get("type") if isinstance(value, dict) else None
            if isinstance(declared, str):
                shape[name] = [declared]
            elif isinstance(declared, list):
                shape[name] = sorted(str(t) for t in declared)
            else:
                shape[name] = []
    required = resolved.get("required")
    return {
        "required": sorted(str(r) for r in required) if isinstance(required, list) else [],
        "properties": shape,
    }


def tool_record(tool: Dict[str, Any]) -> Dict[str, Any]:
    hashes = canonical.hash_tool(tool)
    classified = effects.classify(tool)
    record = OrderedDict(sorted(hashes.items()))
    record["effect"] = classified["effect"]
    record["declared_ceiling"] = classified["declared_ceiling"]
    record["annotations"] = {
        key: tool.get("annotations", {}).get(key)
        for key in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
        if isinstance(tool.get("annotations"), dict)
        and key in tool.get("annotations", {})
    }
    record["schema_shape"] = _schema_shape(tool.get("inputSchema"))
    return record


def snapshot(inventory: Inventory) -> Dict[str, Any]:
    """Current state, in the same shape a baseline stores. One entry per server."""
    servers: Dict[str, Any] = {}
    for server in sorted(inventory.servers, key=lambda s: s.key):
        if server.fetch_status != "ok" or not server.tools:
            continue
        identity = server_identity(server)
        if identity in servers:
            continue  # the same running server registered twice
        tools = OrderedDict()
        for tool in sorted(server.tools, key=lambda t: str(t.get("name"))):
            name = tool.get("name")
            if isinstance(name, str):
                tools[name] = tool_record(tool)
        record = OrderedDict(sorted(canonical.hash_server(server.tools).items()))
        record["transport"] = server.transport
        record["auth_method"] = server.auth_method
        record["tools"] = tools
        servers[identity] = record
    return OrderedDict(sorted(servers.items()))


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build(inventory: Inventory, approved_by: Optional[str] = None,
          note: Optional[str] = None) -> Dict[str, Any]:
    stamp = now()
    return OrderedDict([
        ("baseline_version", BASELINE_VERSION),
        ("generator", "toolprint/{}".format(__version__)),
        # Bumping the effect-class verb lists changes classifications, which would
        # otherwise be indistinguishable from real drift. A bump is a re-approval
        # event, not a finding.
        ("heuristics_version", effects.HEURISTICS_VERSION),
        ("created_at", stamp),
        # Some servers describe themselves differently per platform:
        # desktop-commander's start_process embeds "Running on macOS. Default
        # shell: zsh." and a block of OS-specific advice. Baseline on a laptop,
        # check in Linux CI, and the description hash differs forever - firing
        # DRIFT-003, the rug-pull rule, which is the worst one to cry wolf on.
        ("platform", sys.platform),
        ("approved_at", stamp),
        ("approved_by", approved_by),
        ("note", note),
        ("exceptions", []),
        ("servers", _stamp_first_observed(snapshot(inventory), stamp)),
    ])


def _stamp_first_observed(servers: Dict[str, Any], stamp: str) -> Dict[str, Any]:
    """Record when each server entered the watch.

    Without this, a server added in week six looks like it had six quiet weeks.
    Any rate computed across the whole file would then be wrong in the direction
    that flatters the result, which is the worst direction for it to be wrong in.
    """
    for record in servers.values():
        record.setdefault("first_observed", stamp)
    return servers


def adopt_new(document: Dict[str, Any], current: Dict[str, Any],
              stamp: Optional[str] = None) -> List[str]:
    """Add servers that are being watched but were never baselined.

    Adding a server to the watchlist is an intentional act, not drift, so it
    produces no change to approve - which meant it never entered the baseline and
    was compared against nothing, indefinitely.
    """
    stamp = stamp or now()
    stored = document.setdefault("servers", {})
    added = []
    for identity in sorted(current):
        if identity not in stored:
            record = json.loads(json.dumps(current[identity]))
            record["first_observed"] = stamp
            stored[identity] = record
            added.append(identity)
    return added


def dropped(document: Dict[str, Any], current: Dict[str, Any]) -> List[str]:
    """Baselined servers no longer being watched or no longer reachable."""
    return sorted(set(document.get("servers") or {}) - set(current))


def load(path: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Return (baseline, error). A missing or unreadable baseline is exit code 3."""
    file = Path(path)
    if not file.is_file():
        return None, "no baseline at {}".format(path)
    try:
        document = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, "baseline at {} is unreadable: {}".format(path, exc)
    if not isinstance(document, dict) or "servers" not in document:
        return None, "baseline at {} is not a toolprint baseline".format(path)
    if document.get("baseline_version") != BASELINE_VERSION:
        return None, "baseline schema version {}, this build writes {}".format(
            document.get("baseline_version"), BASELINE_VERSION)
    return document, None


def save(path: str, document: Dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------

def active_exceptions(document: Dict[str, Any], today: Optional[str] = None
                      ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split exceptions into (active, expired). Expiry is mandatory by design."""
    today = today or datetime.date.today().isoformat()
    active, expired = [], []
    for item in document.get("exceptions") or []:
        if not isinstance(item, dict):
            continue
        expires = str(item.get("expires") or "")
        (expired if expires and expires < today else active).append(item)
    return active, expired


def is_excepted(exceptions: Sequence[Dict[str, Any]], server: str, tool: Optional[str],
                rule: str) -> Optional[Dict[str, Any]]:
    for item in exceptions:
        if item.get("rule") not in (rule, "*"):
            continue
        if item.get("server") not in (server, "*"):
            continue
        if item.get("tool") not in (tool, "*", None):
            continue
        return item
    return None


# --------------------------------------------------------------------------
# First-baseline safety checks
# --------------------------------------------------------------------------

def first_baseline_objections(inventory: Inventory) -> List[str]:
    """Reasons to refuse writing a clean baseline over a suspicious state.

    Trust-on-first-use means a baseline blesses whatever is there. Writing one
    over a description that already contains a bidi override, or a server that
    already names another server's tools, records the attack as approved and
    guarantees it is never reported again.
    """
    objections: List[str] = []
    by_server: Dict[str, List[Dict[str, Any]]] = {}
    for server in inventory.servers:
        if server.fetch_status == "ok" and server.tools:
            by_server.setdefault(server_identity(server), []).extend(server.tools)

    for identity in sorted(by_server):
        for tool in by_server[identity]:
            for hit in lexical.inspect_tool(tool):
                objections.append("{} / {}: {} in {} ({})".format(
                    identity, tool.get("name"), hit["kind"], hit["field"], hit["detail"]))

    for hit in lexical.shadowing(by_server):
        objections.append("{} / {}: description names {!r}, owned by {}".format(
            hit["server"], hit["tool"], hit["references"], hit["owned_by"]))
    return objections

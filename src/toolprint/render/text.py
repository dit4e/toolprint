"""Terminal renderer.

Emits redacted fields only: names, basenames and hosts. No env values, no header
values, no full command lines, no URL paths or query strings. The renderer is the
enforcement point for that rule, so it reads Server.command_basename and
Server.url_host rather than the raw fields.

The headline is the heaviest *context*, not the machine-wide total. A conversation
happens in one client in one project, so that pairing is the only unit in which
"what do my tools cost per conversation" has an answer.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from .. import __version__, tokens
from ..connect import context_cost
from ..context import Context, all_shadowed
from ..findings.engine import Report
from ..findings.library import SEVERITY_ORDER
from ..model import AUTH_LITERAL_SECRET, Inventory, Server

SEVERITY_MARK = {
    "critical": "[CRITICAL]",
    "high": "[HIGH]    ",
    "medium": "[MEDIUM]  ",
    "low": "[LOW]     ",
    "info": "[INFO]    ",
}

AUTH_LABEL = {
    "literal_secret": "literal-secret",
    "helper_command": "helper-cmd",
    "env_var": "env-var",
    "oauth": "oauth",
    "none": "none",
    "unknown": "unknown",
}
STATUS_LABEL = {
    "ok": "ok",
    "auth_required": "auth required",
    "unreachable": "unreachable",
    "error": "error",
    "unsupported": "unsupported transport",
    "not_mcp": "not an MCP endpoint",
    "not_attempted": "not attempted",
}


def _plural(count: int, singular: str, plural: str = "") -> str:
    return "{} {}".format(count, singular if count == 1 else (plural or singular + "s"))


def _counts(values: List[str]) -> str:
    tally: Dict[str, int] = {}
    for value in values:
        tally[value] = tally.get(value, 0) + 1
    return " · ".join(
        "{} {}".format(count, name)
        for name, count in sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))
    )


def _endpoint(server: Server) -> str:
    if server.transport == "stdio":
        return server.command_basename or "?"
    return server.url_host or "?"


def _shorten(path: Optional[str], width: int = 44) -> str:
    if not path:
        return "-"
    if len(path) <= width:
        return path
    return "..." + path[-(width - 3):]


def render(
    inventory: Inventory,
    contexts: Optional[Sequence[Context]] = None,
    window: int = 200000,
    tool_name: str = "toolprint",
    report: Optional[Report] = None,
) -> str:
    out: List[str] = []
    add = out.append
    servers = inventory.servers
    connected = any(s.fetch_status != "not_attempted" for s in servers)
    mode = "--connect" if connected else "--no-connect"

    add("{} {} — {}".format(tool_name, __version__, mode))
    add("")

    if not servers:
        add("  No MCP servers found in {} scanned.".format(
            _plural(len(inventory.paths_scanned), "config file")))
        _render_errors(inventory, add)
        return "\n".join(out)

    if connected and contexts:
        _render_cost(contexts, window, add)

    if report is not None:
        _render_findings(report, add)

    _render_inventory(inventory, servers, add)
    if contexts:
        _render_contexts(contexts, connected, add)
        _render_shadowed(contexts, add)
    if report is None:
        _render_credentials(servers, add)
    if connected:
        _render_fetch_failures(servers, add)
        _render_method(servers, add)
    _render_notes(servers, add)
    _render_errors(inventory, add)
    return "\n".join(out)


def _render_cost(contexts: Sequence[Context], window: int, add) -> None:
    costed = [(c,) + context_cost(c) for c in contexts]
    costed = [row for row in costed if row[2] > 0]
    if not costed:
        return
    costed.sort(key=lambda row: -row[2])
    context, tool_count, total, _ = costed[0]

    add("  HEAVIEST CONTEXT — {}".format(context.label))
    add("    {} · {} · {} tokens · {:.1f}% of a {:,}-token window".format(
        _plural(len(context.servers), "server"),
        _plural(tool_count, "tool"),
        "{:,}".format(total),
        100.0 * total / window if window else 0.0,
        window,
    ))
    add("")
    add("    A conversation loads exactly one context. This is the cost of the")
    add("    most expensive one, before you have typed anything.")
    add("")


def _render_findings(report: Report, add) -> None:
    if not report.findings:
        add("  FINDINGS — none")
        add("")
        return
    tally = _counts([f.severity for f in report.findings])
    add("  FINDINGS — {}".format(tally))
    add("")
    for finding in report.findings:
        add("  {} {}  {}".format(
            SEVERITY_MARK.get(finding.severity, finding.severity), finding.id, finding.title))
        add("      {}".format(finding.detail))
        shown = finding.affected[:6]
        for item in shown:
            target = item["server"] + ("/" + item["tool"] if item["tool"] else "")
            add("        - {}".format(target))
        if len(finding.affected) > len(shown):
            add("        ... and {} more".format(len(finding.affected) - len(shown)))
        add("      fix: {}".format(finding.fix))
        if finding.narrative:
            add("      {}".format(finding.narrative))
        add("")


def _render_inventory(inventory: Inventory, servers: List[Server], add) -> None:
    identities = {(s.name, s.transport, _endpoint(s)) for s in servers}
    add("  INVENTORY")
    add("    {} · {} · {} · {}".format(
        _plural(len(servers), "entry", "entries"),
        _plural(len(identities), "distinct server"),
        _plural(len(inventory.clients_found), "client"),
        _plural(len(inventory.paths_scanned), "config file"),
    ))
    add("    transport: {}".format(_counts([s.transport for s in servers])))
    add("    auth:      {}".format(
        _counts([AUTH_LABEL.get(s.auth_method, s.auth_method) for s in servers])))
    disabled = [s for s in servers if not s.enabled]
    if disabled:
        add("    {} present but disabled".format(_plural(len(disabled), "server")))
    add("")


def _render_contexts(contexts: Sequence[Context], connected: bool, add) -> None:
    add("  CONTEXTS — what actually loads, after scope precedence")
    add("    (* = version the server reports, from a config that pins none)")
    for context in contexts:
        tool_count, total, _ = context_cost(context)
        summary = _plural(len(context.servers), "server")
        if connected and total:
            summary += " · {} tools · {:,} tokens".format(tool_count, total)
        if context.shadowed:
            summary += " · {} shadowed".format(len(context.shadowed))
        add("    {}".format(context.label))
        add("      {}".format(summary))
        for server in context.servers:
            status = ""
            if connected:
                if server.fetch_status == "ok":
                    status = "{:>4} tools  {:>7} tok".format(
                        len(server.tools), "{:,}".format(server.token_total or 0))
                else:
                    status = STATUS_LABEL.get(server.fetch_status, server.fetch_status)
            version = server.server_version or ""
            if version and server.transport == "stdio" and not server.version_pinned:
                version += "*"      # running, but not what the config asked for
            add("        {:<20} {:<6} {:<18} {:<9} {:<14} {}".format(
                server.name[:20], server.scope[:6], _endpoint(server)[:18], version[:9],
                AUTH_LABEL.get(server.auth_method, server.auth_method), status).rstrip())
        add("")


def _render_shadowed(contexts: Sequence[Context], add) -> None:
    shadowed = all_shadowed(contexts)
    if not shadowed:
        return
    conflicts = [s for s in shadowed if s.endpoint_differs]
    add("  SHADOWED CONFIGURATION — {} that never load".format(
        _plural(len(shadowed), "entry", "entries")))
    add("    A more specific scope defines the same name. The whole entry from the")
    add("    winning scope is used; nothing is merged. Editing a shadowed entry has")
    add("    no effect and gives no warning.")
    add("")
    for item in shadowed:
        marker = "  !" if item.endpoint_differs else "   "
        add("   {} {:<18} {} scope in {}".format(
            marker, item.loser.name[:18], item.loser.scope, _shorten(item.loser.source_path)))
        add("        overridden by {} scope: {} {}".format(
            item.winner.scope, item.winner.transport, _endpoint(item.winner)))
        if item.endpoint_differs:
            add("        ! points somewhere different ({} {}) — OAuth is stored per".format(
                item.loser.transport, _endpoint(item.loser)))
            add("          endpoint, so which definition loads changes what you are signed in to")
    if conflicts:
        add("")
        add("    {} shadowed {} point somewhere different from the entry that wins.".format(
            len(conflicts), "entry" if len(conflicts) == 1 else "entries"))
    add("")


def _render_credentials(servers: List[Server], add) -> None:
    exposed = [s for s in servers if s.auth_method == AUTH_LITERAL_SECRET]
    if not exposed:
        return
    add("  ATTENTION — literal credentials in config files")
    for server in exposed:
        for location in server.secret_locations:
            add("    {}  {}".format(server.key, location.field))
            add("        {}".format(location.reason))
    add("    Config files are not a credential store. Move these to environment")
    add("    variables and reference them as ${VAR} in the config.")
    add("")


def _render_fetch_failures(servers: List[Server], add) -> None:
    failed = [s for s in servers if s.fetch_status not in ("ok", "not_attempted")]
    if not failed:
        return
    seen = set()
    add("  RETRIEVAL FAILURES")
    for server in failed:
        identity = (server.name, server.fetch_status, server.fetch_detail)
        if identity in seen:
            continue
        seen.add(identity)
        add("    {:<24} {:<22} {}".format(
            server.name[:24],
            STATUS_LABEL.get(server.fetch_status, server.fetch_status),
            (server.safe_detail or "")[:64]))
    add("")


def _render_method(servers: List[Server], add) -> None:
    methods = sorted({s.token_method for s in servers if s.token_method})
    eras = sorted({s.protocol_era for s in servers if s.protocol_era})
    versions = sorted({s.protocol_version for s in servers if s.protocol_version})
    add("  METHOD")
    for method in methods:
        add("    tokens:   {}".format(tokens.describe_method(method)))
    if not methods:
        add("    tokens:   not counted")
    if eras:
        add("    protocol: {} ({})".format(", ".join(eras), ", ".join(versions)))
    add("    counted:  tool name, title, description and schemas, as sent to the model")
    add("")


def _render_notes(servers: List[Server], add) -> None:
    notes = [(s.key, n) for s in servers for n in s.parse_notes]
    if not notes:
        return
    add("  notes")
    for key, note in notes:
        add("    {}: {}".format(key, note))
    add("")


def _render_errors(inventory: Inventory, add) -> None:
    if not inventory.errors:
        return
    add("  collection errors ({})".format(len(inventory.errors)))
    for error in inventory.errors:
        add("    [{}] {}".format(error.kind, error.path))
        add("        {}".format(error.detail))

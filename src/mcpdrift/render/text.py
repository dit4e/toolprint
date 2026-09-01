"""Terminal renderer for the static inventory.

Emits redacted fields only: names, basenames and hosts. No env values, no header
values, no full command lines, no URL paths or query strings. The renderer is the
enforcement point for that rule, so it reads Server.command_basename and
Server.url_host rather than the raw fields.
"""

from __future__ import annotations

from typing import Dict, List

from .. import __version__
from ..model import AUTH_LITERAL_SECRET, Inventory, Server

AUTH_LABEL = {
    "literal_secret": "literal-secret",
    "helper_command": "helper-cmd",
    "env_var": "env-var",
    "oauth": "oauth",
    "none": "none",
    "unknown": "unknown",
}


def _plural(count: int, singular: str, plural: str = "") -> str:
    return "{} {}".format(count, singular if count == 1 else (plural or singular + "s"))


def _counts(values: List[str]) -> str:
    tally: Dict[str, int] = {}
    for value in values:
        tally[value] = tally.get(value, 0) + 1
    return " · ".join("{} {}".format(count, name) for name, count in sorted(tally.items(), key=lambda kv: (-kv[1], kv[0])))


def _endpoint(server: Server) -> str:
    if server.transport == "stdio":
        return server.command_basename or "?"
    return server.url_host or "?"


def render(inventory: Inventory, tool_name: str = "mcpdrift") -> str:
    out: List[str] = []
    servers = inventory.servers
    add = out.append

    add("{} {} — static inventory (--no-connect)".format(tool_name, __version__))
    add("")

    if not servers:
        add("  No MCP servers found in {} config file(s) scanned.".format(len(inventory.paths_scanned)))
        _render_errors(inventory, add)
        return "\n".join(out)

    # Entries and distinct servers are different numbers and the gap is often
    # large: the same server is commonly registered in several clients and, in
    # Claude Code, in several scopes of one file. Reporting only the entry count
    # overstates the real tool surface, and a reader who spots that stops
    # trusting the rest of the report.
    identities = {(s.name, s.transport, _endpoint(s)) for s in servers}
    duplicated = len(servers) - len(identities)
    add("  {} · {} · {} · {}".format(
        _plural(len(servers), "entry", "entries"),
        _plural(len(identities), "distinct server"),
        _plural(len(inventory.clients_found), "client"),
        _plural(len(inventory.paths_scanned), "config file"),
    ))
    if duplicated:
        add("  {} entr{} duplicate a server already registered elsewhere".format(
            duplicated, "y" if duplicated == 1 else "ies"))
    add("  transport: {}".format(_counts([s.transport for s in servers])))
    add("  auth:      {}".format(_counts([AUTH_LABEL.get(s.auth_method, s.auth_method) for s in servers])))
    disabled = [s for s in servers if not s.enabled]
    if disabled:
        add("  {} server(s) present but disabled".format(len(disabled)))
    add("")

    name_w = max(len(s.name) for s in servers)
    name_w = min(max(name_w, 4), 28)
    endpoint_w = min(max((len(_endpoint(s)) for s in servers), default=8), 34)

    group = None
    for server in servers:
        if server.scope == "explicit":
            header = server.source_path
        else:
            header = "{} / {}".format(server.client, server.scope)
            if server.scope_detail:
                header += "  [{}]".format(server.scope_detail)
        if header != group:
            group = header
            add("  {}".format(header))
        flag = " " if server.enabled else "-"
        extras = []
        if server.header_names:
            extras.append("hdr: " + ",".join(server.header_names))
        if server.env_names:
            extras.append("env: " + ",".join(server.env_names))
        if server.headers_helper:
            extras.append("headersHelper")
        add("   {} {:<{nw}}  {:<7} {:<{ew}} {:<14} {}".format(
            flag,
            server.name[:name_w],
            server.transport,
            _endpoint(server)[:endpoint_w],
            AUTH_LABEL.get(server.auth_method, server.auth_method),
            "  ".join(extras),
            nw=name_w, ew=endpoint_w,
        ).rstrip())
    add("")

    exposed = [s for s in servers if s.auth_method == AUTH_LITERAL_SECRET]
    if exposed:
        add("  ATTENTION — literal credentials in config files")
        for server in exposed:
            for location in server.secret_locations:
                add("    {}  {}".format(server.key, location.field))
                add("        {}".format(location.reason))
        add("    Config files are not a credential store. Move these to environment")
        add("    variables and reference them as ${VAR} in the config.")
        add("")

    notes = [(s.key, n) for s in servers for n in s.parse_notes]
    if notes:
        add("  notes")
        for key, note in notes:
            add("    {}: {}".format(key, note))
        add("")

    _render_errors(inventory, add)
    return "\n".join(out)


def _render_errors(inventory: Inventory, add) -> None:
    if not inventory.errors:
        return
    add("  collection errors ({})".format(len(inventory.errors)))
    for error in inventory.errors:
        add("    [{}] {}".format(error.kind, error.path))
        add("        {}".format(error.detail))

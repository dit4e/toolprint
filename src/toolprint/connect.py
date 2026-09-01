"""Orchestrates --connect: what gets contacted, once each, and what gets said first.

Three rules shape this file.

1. Fetch once per distinct server, not once per context. The same server is
   commonly registered across several clients and projects; on a machine with a
   dozen projects, naive per-context fetching would spawn the same subprocess
   over and over. "We start each of your servers once" is a defensible thing to
   say to a security reviewer. "We start them repeatedly" is not.

2. Never contact a shadowed server. It does not load in any context, so its tools
   cost nothing and it has no business being spawned. Fewer processes, and the
   count is honest.

3. Say exactly what will happen before it happens. For stdio that means printing
   the command line to be spawned; the user can then decline with --no-connect.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from . import protocol, tokens
from .context import Context
from .model import Server


def fetch_identity(server: Server) -> Tuple:
    """Two entries with the same identity are the same running server.

    Deliberately keyed on what is launched or contacted rather than on the name:
    the same name pointing at two different endpoints is two servers, and the
    same endpoint under two names is one.
    """
    if server.transport == "stdio":
        return ("stdio", server.command, tuple(server.args))
    return (server.transport, server.url)


@dataclass
class Plan:
    """What --connect intends to do, before it does any of it."""

    targets: List[Server] = field(default_factory=list)
    skipped_shadowed: int = 0
    skipped_unsupported: List[Server] = field(default_factory=list)

    def describe(self) -> str:
        lines = ["This will contact {} server(s), once each:".format(len(self.targets)), ""]
        spawns = [s for s in self.targets if s.transport == "stdio"]
        remotes = [s for s in self.targets if s.transport != "stdio"]
        if spawns:
            lines.append("  Local processes to be started ({}):".format(len(spawns)))
            lines.append("  These are started the same way your MCP client already starts them,")
            lines.append("  on this machine, using servers you already chose to run.")
            for server in spawns:
                lines.append("    $ {}".format(" ".join([server.command or "?"] + server.args)))
            lines.append("")
        if remotes:
            lines.append("  Remote endpoints to be contacted ({}):".format(len(remotes)))
            for server in remotes:
                lines.append("    {} {}  (credentials read from your existing config/environment)".format(
                    server.transport.upper(), server.url_host))
            lines.append("")
        if self.skipped_shadowed:
            lines.append("  Skipping {} shadowed entr{} - they never load in any context.".format(
                self.skipped_shadowed, "y" if self.skipped_shadowed == 1 else "ies"))
        for server in self.skipped_unsupported:
            lines.append("  Skipping {} - {} transport is not supported yet.".format(
                server.key, server.transport))
        return "\n".join(lines)


def plan(contexts: Sequence[Context]) -> Plan:
    """Distinct, loadable servers across every context. Order is deterministic."""
    result = Plan()
    seen: Dict[Tuple, Server] = {}

    loaded: List[Server] = []
    for context in contexts:
        loaded.extend(context.servers)
    result.skipped_shadowed = sum(len(c.shadowed) for c in contexts)

    for server in sorted(loaded, key=lambda s: s.key):
        if not server.enabled:
            continue
        identity = fetch_identity(server)
        if identity in seen:
            continue
        seen[identity] = server
        if server.transport in ("stdio", "http", "sse"):
            result.targets.append(server)
        else:
            result.skipped_unsupported.append(server)
    return result


def execute(
    plan_: Plan,
    contexts: Sequence[Context],
    timeout: float = 15.0,
    progress=None,
) -> None:
    """Fetch each target once, then mirror the result onto every matching entry."""
    results: Dict[Tuple, Server] = {}

    for server in plan_.targets:
        if progress:
            progress(server)
        protocol.fetch(server, timeout=timeout, cwd=server.project_root)
        if server.tools:
            per_tool, total, method = tokens.count_tools(server.tools)
            server.tool_tokens = per_tool
            server.token_total = total
            server.token_method = method
        results[fetch_identity(server)] = server

    # One fetch, many entries: copy the outcome onto every other entry that
    # denotes the same running server, in every context.
    for context in contexts:
        for entry in context.servers:
            source = results.get(fetch_identity(entry))
            if source is None or source is entry:
                continue
            entry.fetch_status = source.fetch_status
            entry.fetch_detail = source.fetch_detail
            entry.protocol_era = source.protocol_era
            entry.protocol_version = source.protocol_version
            entry.tools = source.tools
            entry.tool_tokens = source.tool_tokens
            entry.token_total = source.token_total
            entry.token_method = source.token_method


def context_cost(context: Context) -> Tuple[int, int, Optional[str]]:
    """(tool_count, token_total, method) for one context's resolved surface."""
    tool_count = 0
    total = 0
    method: Optional[str] = None
    for server in context.servers:
        if not server.enabled:
            continue
        tool_count += len(server.tools)
        total += server.token_total or 0
        method = server.token_method or method
    return tool_count, total, method

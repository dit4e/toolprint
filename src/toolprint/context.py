"""Context resolution: what actually loads, as opposed to what is configured.

A conversation happens in exactly one client, in exactly one project. That pairing
is a *context*, and it is the only unit in which "what do my MCP tools cost per
conversation" has an answer. The machine-wide inventory is not a conservative
overestimate of a context - it describes no state the system is ever in.

All three multi-scope clients resolve the same way (verified 2026-08-31): the more
specific scope wins, the whole entry from the winning scope is used, and there is
no field merging. So a losing entry does not partially apply - it does not apply
at all. That is what makes shadowed configuration invisible to whoever wrote it,
and it is why the loser list is worth reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from . import registry
from .model import Inventory, Server


@dataclass
class Shadowed:
    """A configured server that never loads because a higher scope defines it."""

    loser: Server
    winner: Server

    @property
    def endpoint_differs(self) -> bool:
        """Same name, different destination: the dangerous kind of shadowing.

        Benign duplication is noise. A shadowed entry pointing somewhere *else* is
        a live hazard: OAuth is stored per endpoint, so authenticating the
        definition that loads in one project leaves you signed out in another, and
        after M5 a silent endpoint change under a shadowed name is a rug pull with
        no visible symptom.
        """
        return (
            self.loser.transport != self.winner.transport
            or (self.loser.url_host or self.loser.command_basename)
            != (self.winner.url_host or self.winner.command_basename)
        )


@dataclass
class Context:
    """One client in one project: the surface a single conversation sees."""

    client: str
    project: Optional[str]  # None = any directory with no project-level config
    servers: List[Server] = field(default_factory=list)
    shadowed: List[Shadowed] = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.project is None:
            return "{} (no project config)".format(self.client)
        return "{} in {}".format(self.client, self.project)

    @property
    def key(self) -> str:
        return "{}::{}".format(self.client, self.project or "-")


def _client_by_id(client_id: str) -> registry.Client:
    """Look up a client, synthesising one for sources outside the registry.

    Servers read from an explicit --config file carry a client id that is not in
    the registry. Returning None for those dropped them from every context, so
    they were never resolved and never contacted - which silently broke
    --connect for any explicit config, not just the unusual ones. An unknown
    source has a single scope, so it needs no precedence table; every entry
    wins.
    """
    for client in registry.CLIENTS:
        if client.id == client_id:
            return client
    return registry.Client(id=client_id, name=client_id)


def _resolve(client: registry.Client, entries: Sequence[Server]) -> Context:
    by_name: Dict[str, List[Server]] = {}
    for entry in entries:
        by_name.setdefault(entry.name, []).append(entry)

    winners: List[Server] = []
    shadowed: List[Shadowed] = []
    for name in sorted(by_name):
        # Rank first, then source path, so a tie resolves the same way every run.
        ranked = sorted(by_name[name], key=lambda s: (client.rank(s.scope), s.source_path))
        winners.append(ranked[0])
        shadowed.extend(Shadowed(loser, ranked[0]) for loser in ranked[1:])
    return Context(client.id, None, winners, shadowed)


def resolve_all(inventory: Inventory) -> List[Context]:
    """Build every context implied by the inventory, ordered deterministically."""
    contexts: List[Context] = []

    by_client: Dict[str, List[Server]] = {}
    for server in inventory.servers:
        by_client.setdefault(server.client, []).append(server)

    for client_id in sorted(by_client):
        client = _client_by_id(client_id)
        entries = by_client[client_id]
        user_entries = [e for e in entries if e.project_root is None]
        projects = sorted({e.project_root for e in entries if e.project_root})

        for project in projects:
            scoped = user_entries + [e for e in entries if e.project_root == project]
            context = _resolve(client, scoped)
            context.project = project
            contexts.append(context)

        # A client with user-scope servers also has a context in any directory
        # that carries no project config. Only emit it when it differs from the
        # per-project contexts, otherwise it is noise.
        if user_entries:
            baseline = _resolve(client, user_entries)
            contexts.append(baseline)

    contexts.sort(key=lambda c: (c.client, c.project or ""))
    return contexts


def all_shadowed(contexts: Sequence[Context]) -> List[Shadowed]:
    """Shadowed entries across all contexts, de-duplicated by (loser, winner)."""
    seen = set()
    out: List[Shadowed] = []
    for context in contexts:
        for item in context.shadowed:
            identity = (item.loser.source_path, item.loser.name, item.winner.source_path)
            if identity in seen:
                continue
            seen.add(identity)
            out.append(item)
    out.sort(key=lambda s: (s.loser.client, s.loser.name, s.loser.source_path))
    return out

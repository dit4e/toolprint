"""JSON renderer for the static inventory.

Like the text renderer, this is a redaction enforcement point: it reads only the
safe accessors. Key order is fixed and servers are pre-sorted by the collector so
that two runs produce byte-identical output - the M2 two-run test depends on it.

This is not findings.json. That schema arrives in M2; this is the M0 interchange
format and will become an input to the findings engine rather than a public
contract.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Dict, Optional, Sequence

from .. import __version__
from ..connect import context_cost
from ..context import Context, all_shadowed
from ..model import Inventory, Server


def server_dict(server: Server) -> Dict[str, Any]:
    return OrderedDict([
        ("name", server.name),
        ("client", server.client),
        ("scope", server.scope),
        ("scope_detail", server.scope_detail),
        ("source_path", server.source_path),
        ("transport", server.transport),
        ("command_basename", server.command_basename),
        ("url_host", server.url_host),
        ("env_names", server.env_names),
        ("header_names", server.header_names),
        ("headers_helper", bool(server.headers_helper)),
        ("has_oauth", server.has_oauth),
        ("enabled", server.enabled),
        ("auth_method", server.auth_method),
        ("secret_locations", [
            OrderedDict([("field", s.field), ("reason", s.reason)])
            for s in server.secret_locations
        ]),
        ("parse_notes", server.parse_notes),
        ("fetch_status", server.fetch_status),
        ("fetch_detail", server.safe_detail),
        ("protocol_era", server.protocol_era),
        ("protocol_version", server.protocol_version),
        ("tool_count", len(server.tools)),
        ("token_total", server.token_total),
        ("token_method", server.token_method),
    ])


def context_dict(context: Context) -> Dict[str, Any]:
    tool_count, total, method = context_cost(context)
    return OrderedDict([
        ("client", context.client),
        ("project", context.project),
        ("label", context.label),
        ("server_count", len(context.servers)),
        ("tool_count", tool_count),
        ("token_total", total),
        ("token_method", method),
        ("servers", [s.key for s in context.servers]),
        ("shadowed", [
            OrderedDict([
                ("name", item.loser.name),
                ("loser_scope", item.loser.scope),
                ("loser_source", item.loser.source_path),
                ("winner_scope", item.winner.scope),
                ("winner_source", item.winner.source_path),
                ("endpoint_differs", item.endpoint_differs),
            ])
            for item in context.shadowed
        ]),
    ])


def inventory_dict(
    inventory: Inventory, contexts: Optional[Sequence[Context]] = None
) -> Dict[str, Any]:
    connected = any(s.fetch_status != "not_attempted" for s in inventory.servers)
    return OrderedDict([
        ("schema_version", 0),  # 0 = pre-findings.json interim shape
        ("generator", "mcpdrift/{}".format(__version__)),
        ("mode", "connect" if connected else "no_connect"),
        ("clients_found", inventory.clients_found),
        ("paths_scanned", inventory.paths_scanned),
        ("contexts", [context_dict(c) for c in (contexts or [])]),
        ("shadowed_total", len(all_shadowed(contexts or []))),
        ("servers", [server_dict(s) for s in inventory.servers]),
        ("collection_errors", [
            OrderedDict([
                ("path", e.path),
                ("client", e.client),
                ("kind", e.kind),
                ("detail", e.detail),
            ])
            for e in inventory.errors
        ]),
    ])

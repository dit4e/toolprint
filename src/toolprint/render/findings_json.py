"""findings.json - the contract every renderer consumes.

One deliberate choice worth stating: `summary` describes the
*heaviest context* rather than the machine-wide union, and a `contexts` array
carries the rest. A conversation loads one client in one project, so the union
has no reader - it describes no state the system is ever in.

Sensitivity: this file contains tool names, descriptions and schemas and is as
sensitive as a bundle. That is why the M3 viewer is client-side.

`generated_at` is the only field that varies between two runs of an unchanged
system. Everything else is ordered deterministically so the M2 two-run test can
compare byte-for-byte with that one field held constant.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Dict, List, Optional, Sequence

from .. import __version__, effects
from ..connect import context_cost
from ..context import Context
from ..model import Inventory, Server
from ..findings.engine import Finding, Report

SCHEMA_VERSION = 1


def _finding(finding: Finding) -> Dict[str, Any]:
    return OrderedDict([
        ("id", finding.id),
        ("severity", finding.severity),
        ("category", finding.category),
        ("title", finding.title),
        ("detail", finding.detail),
        ("affected", [
            OrderedDict([("server", a.get("server", "")), ("tool", a.get("tool", ""))])
            for a in finding.affected
        ]),
        ("fix", finding.fix),
        ("remediation", finding.remediation),
        ("evidence", finding.evidence),
        ("narrative", finding.narrative),
    ])


def _server(server: Server, classified: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    tally = effects.counts(list(classified.values()))
    return OrderedDict([
        ("key", server.key),
        ("name", server.name),
        ("client", server.client),
        ("scope", server.scope),
        ("project", server.project_root),
        ("source_path", server.source_path),
        ("transport", server.transport),
        ("command_basename", server.command_basename),
        ("url_host", server.url_host),
        ("env_names", server.env_names),
        ("header_names", server.header_names),
        ("auth_method", server.auth_method),
        ("enabled", server.enabled),
        ("fetch_status", server.fetch_status),
        ("fetch_detail", server.safe_detail),
        ("protocol_era", server.protocol_era),
        ("protocol_version", server.protocol_version),
        ("tool_count", len(server.tools)),
        ("token_total", server.token_total),
        ("token_method", server.token_method),
        ("effect_counts", tally),
        ("tools", [
            OrderedDict([
                ("name", name),
                ("tokens", server.tool_tokens.get(name)),
                ("effect", classified[name]["effect"]),
                ("declared_ceiling", classified[name]["declared_ceiling"]),
                ("mislabelled", classified[name]["mislabelled"]),
            ])
            for name in sorted(classified)
        ]),
    ])


def _context(context: Context) -> Dict[str, Any]:
    tool_count, total, method = context_cost(context)
    return OrderedDict([
        ("key", context.key),
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


def build(
    inventory: Inventory,
    report: Report,
    generated_at: str,
    changes: Optional[Sequence[Any]] = None,
) -> Dict[str, Any]:
    return OrderedDict([
        ("schema_version", SCHEMA_VERSION),
        ("generated_at", generated_at),
        ("generator", "toolprint/{}".format(__version__)),
        ("heuristics_version", effects.HEURISTICS_VERSION),
        ("mode", report.summary["mode"]),
        ("summary", OrderedDict(sorted(report.summary.items()))),
        ("contexts", [_context(c) for c in report.contexts]),
        ("servers", [
            _server(s, report.effects_by_server.get(s.key, {}))
            for s in inventory.servers
        ]),
        ("cost_breakdown", report.cost_breakdown),
        ("findings", [_finding(f) for f in report.findings]),
        ("collection_errors", [
            OrderedDict([
                ("path", e.path), ("client", e.client),
                ("kind", e.kind), ("detail", e.detail),
            ])
            for e in inventory.errors
        ]),
        ("drift", [
            OrderedDict([
                ("rule", c.rule), ("severity", c.severity), ("title", c.title),
                ("server", c.server), ("tool", c.tool), ("detail", c.detail),
                ("evidence", c.evidence), ("excepted", bool(c.excepted)),
            ])
            for c in (changes or [])
        ] if changes is not None else None),
        ("benchmark", None),  # M6
    ])

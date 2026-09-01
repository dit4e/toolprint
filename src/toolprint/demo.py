"""A synthetic findings document, for showing the report before installing anything.

Everything here is invented. The company, hosts and tool names are fictional and
the numbers are chosen to exercise every severity and every section of the
viewer, including a drift block and a peer comparison that the free tool does not
yet produce. It exists so the output can be seen before anyone runs a scan, and
so the viewer's rendering of sections M5 and M6 will fill in can be checked now.

It is deliberately obvious that this is a demo: nothing here should ever be
mistaken for a real assessment.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Dict

from . import __version__, effects
from .findings import library
from .render.findings_json import SCHEMA_VERSION

CONTEXT = "claude_code::/src/acme-platform"
SERVER_KEYS = [
    "claude_code/local/crm",
    "claude_code/local/billing",
    "claude_code/user/github",
    "claude_code/local/warehouse",
    "claude_code/local/filesystem",
    "claude_code/local/pagerduty",
]


def _finding(fid, severity, detail, affected=(), narrative=None, evidence=None):
    spec = library.definition(fid)
    return OrderedDict([
        ("id", spec.id), ("severity", severity), ("category", spec.category),
        ("title", spec.title), ("detail", detail),
        ("affected", [OrderedDict([("server", s), ("tool", t)]) for s, t in affected]),
        ("fix", spec.fix), ("remediation", spec.remediation),
        ("evidence", evidence or {}), ("narrative", narrative),
    ])


def document() -> Dict[str, Any]:
    return OrderedDict([
        ("schema_version", SCHEMA_VERSION),
        ("generated_at", "2026-08-31T09:00:00Z"),
        ("generator", "toolprint/{} (demo)".format(__version__)),
        ("heuristics_version", effects.HEURISTICS_VERSION),
        ("mode", "connect"),
        ("summary", OrderedDict(sorted({
            "mode": "connect",
            "entry_count": 31,
            "distinct_server_count": 15,
            "context_count": 6,
            "heaviest_context": CONTEXT,
            "heaviest_context_label": "claude_code in /src/acme-platform",
            "server_count": 15,
            "tool_count": 300,
            "total_tokens": 75170,
            "context_window": 200000,
            "context_pct": 37.59,
            "est_cost_per_conversation_usd": 0.2255,
            "token_method": "tiktoken",
            "effect_counts": {"read": 180, "write": 73, "external": 12, "irreversible": 35},
            "mislabelled_tools": 6,
            "unauthenticated_high_consequence": 12,
            "shadowed_entries": 4,
            "unused_tools": 214,
        }.items()))),
        ("contexts", [
            OrderedDict([
                ("key", CONTEXT), ("client", "claude_code"), ("project", "/src/acme-platform"),
                ("label", "claude_code in /src/acme-platform"), ("server_count", 15),
                ("tool_count", 300), ("token_total", 75170), ("token_method", "tiktoken"),
                ("servers", SERVER_KEYS),
                ("shadowed", [OrderedDict([
                    ("name", "warehouse"), ("loser_scope", "user"),
                    ("loser_source", "~/.cursor/mcp.json"), ("winner_scope", "project"),
                    ("winner_source", "/src/acme-platform/.mcp.json"),
                    ("endpoint_differs", True),
                ])]),
            ]),
            OrderedDict([
                ("key", "claude_code::/src/acme-billing"), ("client", "claude_code"),
                ("project", "/src/acme-billing"), ("label", "claude_code in /src/acme-billing"),
                ("server_count", 9), ("tool_count", 141), ("token_total", 38402),
                ("token_method", "tiktoken"), ("servers", []), ("shadowed", []),
            ]),
            OrderedDict([
                ("key", "cursor::-"), ("client", "cursor"), ("project", None),
                ("label", "cursor (no project config)"), ("server_count", 4),
                ("tool_count", 52), ("token_total", 12880), ("token_method", "tiktoken"),
                ("servers", []), ("shadowed", []),
            ]),
        ]),
        ("servers", [
            OrderedDict([
                ("key", key), ("name", name), ("client", "claude_code"), ("scope", scope),
                ("project", "/src/acme-platform"), ("source_path", "~/.claude.json"),
                ("transport", transport), ("command_basename", command),
                ("url_host", host), ("env_names", []), ("header_names", []),
                ("auth_method", auth), ("enabled", True), ("fetch_status", status),
                ("fetch_detail", None), ("protocol_era", "modern"),
                ("protocol_version", "2026-07-28"), ("tool_count", tools),
                ("token_total", tokens), ("token_method", "tiktoken"),
                ("effect_counts", {}), ("tools", []),
            ])
            for key, name, scope, transport, command, host, auth, tools, tokens, status in [
                ("claude_code/local/crm", "crm", "local", "http", None, "crm.internal.acme", "none", 61, 18240, "ok"),
                ("claude_code/local/billing", "billing", "local", "http", None, "billing.internal.acme", "env_var", 44, 14980, "ok"),
                ("claude_code/user/github", "github", "user", "stdio", "npx", None, "literal_secret", 51, 12610, "ok"),
                ("claude_code/local/warehouse", "warehouse", "local", "http", None, "warehouse.acme.io", "oauth", 38, 9870, "ok"),
                ("claude_code/local/filesystem", "filesystem", "local", "stdio", "npx", None, "none", 14, 2627, "ok"),
                ("claude_code/local/pagerduty", "pagerduty", "local", "http", None, "events.pagerduty.com", "helper_command", 0, None, "auth_required"),
            ]
        ]),
        ("cost_breakdown", [
            OrderedDict([("server", "claude_code/local/crm"), ("tool", tool), ("tokens", tokens)])
            for tool, tokens in [
                ("contact.bulk_update", 2480), ("opportunity.create", 1920),
                ("contact.search", 1710), ("account.merge", 1480), ("contact.delete", 1310),
                ("invoice.issue", 1240), ("report.generate", 1105), ("note.append", 980),
            ]
        ]),
        ("findings", [
            _finding("AUTH-001", library.CRITICAL,
                     "12 tools on 2 remote servers can delete, send or spend, and the server "
                     "is reachable over the network with no credential configured.",
                     [("claude_code/local/crm", "contact.delete"),
                      ("claude_code/local/crm", "account.merge"),
                      ("claude_code/local/billing", "invoice.void")],
                     narrative="The CRM server was stood up for a proof of concept in March and "
                               "was never moved behind the internal gateway. It is reachable "
                               "from any host on the corporate network."),
            _finding("HYG-002", library.HIGH,
                     "3 server entries hold a credential as a literal value in a client "
                     "config file rather than as a ${VAR} reference.",
                     [("claude_code/user/github", "")]),
            _finding("AUTH-002", library.HIGH,
                     "44 tools across 3 servers with destructive or outbound capability "
                     "authenticate with a long-lived static credential.",
                     [("claude_code/local/billing", "invoice.issue")]),
            _finding("COST-001", library.MEDIUM,
                     "claude_code in /src/acme-platform loads 300 tools across 15 servers, "
                     "using 37.6% of a 200,000-token window before any user input."),
            _finding("EFFECT-002", library.MEDIUM,
                     "6 tools declare a safety annotation that its own name or schema "
                     "contradicts.",
                     [("claude_code/local/crm", "contact.purge")]),
            _finding("HYG-004", library.MEDIUM,
                     "1 server entry shadowed by a definition pointing somewhere else entirely.",
                     [("cursor/user/warehouse", "")]),
            _finding("COST-002", library.LOW,
                     "The 5 heaviest tools account for 47% of this context's tool budget.",
                     [("claude_code/local/crm", "contact.bulk_update")]),
            _finding("HYG-003", library.LOW,
                     "3 server entries defined but never loaded: a higher-precedence scope "
                     "defines the same name."),
            _finding("EFFECT-001", library.INFO,
                     "In claude_code in /src/acme-platform: 73 can write, 12 can send or "
                     "reach outside, 35 can do something irreversible.",
                     evidence={"effect_counts": {"read": 180, "write": 73,
                                                 "external": 12, "irreversible": 35},
                               "high_consequence": 47}),
        ]),
        ("collection_errors", []),
        ("drift", [
            OrderedDict([("severity", "critical"), ("server", "crm"), ("tool", "contact.export"),
                         ("detail", "effect class escalated from read to external since baseline")]),
            OrderedDict([("severity", "high"), ("server", "billing"), ("tool", "invoice.issue"),
                         ("detail", "description changed while schema was unchanged")]),
            OrderedDict([("severity", "medium"), ("server", "warehouse"), ("tool", "sku.lookup"),
                         ("detail", "new required parameter added")]),
        ]),
        ("benchmark", OrderedDict([("rows", [
            OrderedDict([("label", "Tools per context"), ("value", 300), ("median", 128), ("percentile", 92)]),
            OrderedDict([("label", "Tokens per context"), ("value", 75170), ("median", 31400), ("percentile", 89)]),
            OrderedDict([("label", "Irreversible tools"), ("value", 35), ("median", 11), ("percentile", 94)]),
            OrderedDict([("label", "Servers with no auth"), ("value", 3), ("median", 1), ("percentile", 81)]),
        ])])),
    ])

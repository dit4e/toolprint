"""The findings engine. Everything renders from its output; nothing renders from
raw collected data.

One judgement is worth stating up front, because getting it wrong would make the
tool useless. "No authentication" means something completely different for a
local stdio subprocess than for a remote endpoint. A filesystem server started on
your own machine has no credential because it needs none; a remote server with
no credential is reachable by anything that can reach the URL. Flagging every
local server as critically unauthenticated is exactly the alert fatigue that ends
with users passing --fail-on none, so AUTH-001 applies only to remote transports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .. import effects
from ..connect import context_cost
from ..context import Context, all_shadowed
from ..model import (
    AUTH_ENV_VAR, AUTH_HELPER_COMMAND, AUTH_LITERAL_SECRET, AUTH_NONE, Inventory, Server,
)
from . import library
from .library import CRITICAL, HIGH, INFO, LOW, MEDIUM

REMOTE_TRANSPORTS = ("http", "sse", "ws")

# Share of the context window at which the cost finding escalates.
COST_THRESHOLDS = ((50.0, HIGH), (25.0, MEDIUM), (10.0, LOW))
# Concentration at which trimming a few tools is the cheapest available fix.
CONCENTRATION_TOOLS = 5
CONCENTRATION_SHARE = 0.40


@dataclass
class Finding:
    id: str
    severity: str
    category: str
    title: str
    detail: str
    fix: str
    remediation: str
    affected: List[Dict[str, str]] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    narrative: Optional[str] = None  # hand-written interpretation, paid engagements only


@dataclass
class Report:
    summary: Dict[str, Any]
    contexts: List[Context]
    cost_breakdown: List[Dict[str, Any]]
    findings: List[Finding]
    effects_by_server: Dict[str, Dict[str, Dict[str, Any]]]


def _make(finding_id: str, severity: str, detail: str, **kwargs) -> Finding:
    spec = library.definition(finding_id)
    return Finding(
        id=spec.id,
        severity=severity,
        category=spec.category,
        title=spec.title,
        detail=detail,
        fix=spec.fix,
        remediation=spec.remediation,
        **kwargs,
    )


def _plural(count: int, singular: str, plural: str = "") -> str:
    return "{} {}".format(count, singular if count == 1 else (plural or singular + "s"))


def _fetched(servers: Sequence[Server]) -> List[Server]:
    return [s for s in servers if s.fetch_status == "ok" and s.tools]


def _high_consequence(server: Server, classified: Dict[str, Dict[str, Any]]) -> List[str]:
    return sorted(
        name for name, info in classified.items()
        if info["effect"] in effects.HIGH_CONSEQUENCE
    )


def heaviest(contexts: Sequence[Context]) -> Optional[Context]:
    costed = [(context_cost(c)[1], c) for c in contexts]
    costed = [(total, c) for total, c in costed if total > 0]
    if not costed:
        return max(contexts, key=lambda c: len(c.servers)) if contexts else None
    # Tie-break on key so the choice is stable between runs.
    return max(costed, key=lambda pair: (pair[0], pair[1].key))[1]


# --- individual finding builders -------------------------------------------

def _auth_findings(servers: Sequence[Server], by_server: Dict[str, Dict[str, Dict[str, Any]]]) -> List[Finding]:
    found: List[Finding] = []

    unauthenticated: List[Dict[str, str]] = []
    static_credential: List[Dict[str, str]] = []
    for server in sorted(_fetched(servers), key=lambda s: s.key):
        risky = _high_consequence(server, by_server.get(server.key, {}))
        if not risky:
            continue
        entries = [{"server": server.key, "tool": tool} for tool in risky]
        if server.auth_method == AUTH_NONE and server.transport in REMOTE_TRANSPORTS:
            unauthenticated.extend(entries)
        elif server.auth_method in (AUTH_ENV_VAR, AUTH_LITERAL_SECRET):
            static_credential.extend(entries)

    if unauthenticated:
        hosts = sorted({e["server"] for e in unauthenticated})
        found.append(_make(
            "AUTH-001", CRITICAL,
            "{} on {} can delete, send or spend, and the server is reachable over "
            "the network with no credential configured.".format(
                _plural(len(unauthenticated), "tool"), _plural(len(hosts), "remote server")),
            affected=unauthenticated,
            evidence={"servers": hosts},
        ))

    if static_credential:
        hosts = sorted({e["server"] for e in static_credential})
        found.append(_make(
            "AUTH-002", HIGH,
            "{} across {} with destructive or outbound capability authenticate "
            "with a long-lived static credential.".format(
                _plural(len(static_credential), "tool"), _plural(len(hosts), "server")),
            affected=static_credential,
            evidence={"servers": hosts},
        ))

    helpers = sorted(s.key for s in servers if s.headers_helper)
    if helpers:
        found.append(_make(
            "AUTH-003", MEDIUM,
            "{} obtain authentication headers by running an external command.".format(
                _plural(len(helpers), "server")),
            affected=[{"server": key, "tool": ""} for key in helpers],
        ))
    return found


def _effect_findings(context: Optional[Context], by_server: Dict[str, Dict[str, Dict[str, Any]]]) -> List[Finding]:
    found: List[Finding] = []
    if context is None:
        return found

    tally = {effect: 0 for effect in effects.CLASSES}
    mislabelled: List[Dict[str, str]] = []
    evidence: Dict[str, Any] = {}
    for server in sorted(context.servers, key=lambda s: s.key):
        classified = by_server.get(server.key, {})
        for name in sorted(classified):
            info = classified[name]
            tally[info["effect"]] = tally.get(info["effect"], 0) + 1
            if info["mislabelled"]:
                mislabelled.append({"server": server.key, "tool": name})
                evidence[server.key + "/" + name] = info["evidence"]

    risky = tally[effects.EXTERNAL] + tally[effects.IRREVERSIBLE]
    if sum(tally.values()):
        found.append(_make(
            "EFFECT-001", INFO,
            "In {}: {} can write, {} can send or reach outside, {} can do "
            "something irreversible.".format(
                context.label, tally[effects.WRITE],
                tally[effects.EXTERNAL], tally[effects.IRREVERSIBLE]),
            evidence={"effect_counts": tally, "high_consequence": risky},
        ))

    if mislabelled:
        found.append(_make(
            "EFFECT-002", MEDIUM,
            "{} declare a safety annotation that its own name or schema "
            "contradicts.".format(_plural(len(mislabelled), "tool")),
            affected=mislabelled,
            evidence=evidence,
        ))
    return found


def _cost_findings(context: Optional[Context], window: int, breakdown: Sequence[Dict[str, Any]]) -> List[Finding]:
    found: List[Finding] = []
    if context is None or not window:
        return found
    tool_count, total, method = context_cost(context)
    if not total:
        return found

    percentage = 100.0 * total / window
    severity = INFO
    for threshold, level in COST_THRESHOLDS:
        if percentage >= threshold:
            severity = level
            break

    found.append(_make(
        "COST-001", severity,
        "{} loads {} across {}, using {:.1f}% of a {:,}-token window before any "
        "user input.".format(
            context.label, _plural(tool_count, "tool"),
            _plural(len(context.servers), "server"), percentage, window),
        evidence={
            "context": context.key,
            "tokens": total,
            "context_window": window,
            "context_pct": round(percentage, 2),
            "token_method": method,
        },
    ))

    top = list(breakdown[:CONCENTRATION_TOOLS])
    if top and total:
        share = sum(item["tokens"] for item in top) / float(total)
        if share >= CONCENTRATION_SHARE:
            found.append(_make(
                "COST-002", LOW,
                "The {} heaviest tools account for {:.0f}% of this context's tool "
                "budget.".format(len(top), share * 100),
                affected=[{"server": item["server"], "tool": item["tool"]} for item in top],
                evidence={"share": round(share, 3)},
            ))
    return found


def _hygiene_findings(inventory: Inventory, contexts: Sequence[Context]) -> List[Finding]:
    found: List[Finding] = []

    failures: List[Dict[str, str]] = []
    detail_by_server: Dict[str, Any] = {}
    seen = set()
    for server in sorted(inventory.servers, key=lambda s: s.key):
        if server.fetch_status in ("ok", "not_attempted"):
            continue
        identity = (server.name, server.fetch_status)
        if identity in seen:
            continue
        seen.add(identity)
        failures.append({"server": server.key, "tool": ""})
        detail_by_server[server.key] = {
            "status": server.fetch_status, "detail": server.safe_detail}
    if failures:
        found.append(_make(
            "HYG-001", LOW,
            "{} configured and enabled but could not be reached.".format(
                _plural(len(failures), "server")),
            affected=failures,
            evidence=detail_by_server,
        ))

    exposed: List[Dict[str, str]] = []
    locations: Dict[str, Any] = {}
    for server in sorted(inventory.servers, key=lambda s: s.key):
        if server.auth_method != AUTH_LITERAL_SECRET:
            continue
        exposed.append({"server": server.key, "tool": ""})
        locations[server.key] = [
            {"field": item.field, "reason": item.reason} for item in server.secret_locations]
    if exposed:
        found.append(_make(
            "HYG-002", HIGH,
            "{} hold a credential as a literal value in a client config file "
            "rather than as a ${{VAR}} reference.".format(
                _plural(len(exposed), "server entry", "server entries")),
            affected=exposed,
            evidence={"locations": locations},
        ))

    unpinned = [
        s for s in sorted(inventory.servers, key=lambda s: s.key)
        if s.transport == "stdio" and s.enabled and not s.version_pinned
    ]
    if unpinned:
        seen_pins: Dict[str, Any] = {}
        for server in unpinned:
            seen_pins[server.key] = {
                "running_version": server.server_version,
                "reported_name": server.server_name,
                "command": server.command_basename,
            }
        known = [s for s in unpinned if s.server_version]
        found.append(_make(
            "HYG-005", LOW,
            "{} run whatever version the package manager had cached{}.".format(
                _plural(len(unpinned), "local server"),
                "; {} reported a version for themselves".format(len(known))
                if known else ""),
            affected=[{"server": s.key, "tool": ""} for s in unpinned],
            evidence={"servers": seen_pins},
        ))

    shadowed = all_shadowed(contexts)
    benign = [s for s in shadowed if not s.endpoint_differs]
    conflicting = [s for s in shadowed if s.endpoint_differs]
    if benign:
        found.append(_make(
            "HYG-003", LOW,
            "{} defined but never loaded: a higher-precedence scope defines the "
            "same name.".format(_plural(len(benign), "server entry", "server entries")),
            affected=[{"server": s.loser.key, "tool": ""} for s in benign],
            evidence={"shadowed": [
                {"name": s.loser.name, "loser": s.loser.source_path,
                 "loser_scope": s.loser.scope, "winner_scope": s.winner.scope}
                for s in benign]},
        ))
    if conflicting:
        found.append(_make(
            "HYG-004", MEDIUM,
            "{} shadowed by a definition pointing somewhere else entirely.".format(
                _plural(len(conflicting), "server entry", "server entries")),
            affected=[{"server": s.loser.key, "tool": ""} for s in conflicting],
            evidence={"conflicts": [
                {"name": s.loser.name,
                 "shadowed_endpoint": "{} {}".format(
                     s.loser.transport, s.loser.url_host or s.loser.command_basename),
                 "loaded_endpoint": "{} {}".format(
                     s.winner.transport, s.winner.url_host or s.winner.command_basename)}
                for s in conflicting]},
        ))
    return found


def _cost_breakdown(context: Optional[Context]) -> List[Dict[str, Any]]:
    if context is None:
        return []
    rows: List[Dict[str, Any]] = []
    for server in context.servers:
        for tool, count in server.tool_tokens.items():
            rows.append({"server": server.key, "tool": tool, "tokens": count})
    # Descending cost, then by name so equal-cost tools order stably.
    rows.sort(key=lambda row: (-row["tokens"], row["server"], row["tool"]))
    return rows


def analyse(
    inventory: Inventory,
    contexts: Sequence[Context],
    window: int = 200000,
    price_per_mtok: Optional[float] = None,
) -> Report:
    by_server: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for server in inventory.servers:
        if server.tools:
            by_server[server.key] = effects.classify_all(server.tools)

    top_context = heaviest(contexts)
    breakdown = _cost_breakdown(top_context)

    findings: List[Finding] = []
    findings.extend(_auth_findings(inventory.servers, by_server))
    findings.extend(_effect_findings(top_context, by_server))
    findings.extend(_cost_findings(top_context, window, breakdown))
    findings.extend(_hygiene_findings(inventory, contexts))
    # Most severe first; stable id order within a severity.
    findings.sort(key=lambda f: (-library.SEVERITY_ORDER[f.severity], f.id))

    tool_count, total, method = context_cost(top_context) if top_context else (0, 0, None)
    connected = any(s.fetch_status != "not_attempted" for s in inventory.servers)

    # Every other number in `summary` describes the heaviest context, so these
    # must too. Counting effects across all entries instead would double-count a
    # server registered in two clients and produce a total that does not match
    # tool_count sitting three lines above it.
    context_classified = [
        info
        for server in (top_context.servers if top_context else [])
        for info in by_server.get(server.key, {}).values()
    ]

    summary = {
        "mode": "connect" if connected else "no_connect",
        "entry_count": len(inventory.servers),
        "distinct_server_count": len({
            (s.name, s.transport, s.url_host or s.command_basename) for s in inventory.servers}),
        "context_count": len(contexts),
        "heaviest_context": top_context.key if top_context else None,
        "heaviest_context_label": top_context.label if top_context else None,
        "server_count": len(top_context.servers) if top_context else 0,
        "tool_count": tool_count,
        "total_tokens": total,
        "context_window": window,
        "context_pct": round(100.0 * total / window, 2) if window and total else 0.0,
        "est_cost_per_conversation_usd": (
            round(total / 1_000_000.0 * price_per_mtok, 4)
            if price_per_mtok and total else None),
        "token_method": method,
        "effect_counts": effects.counts(context_classified),
        "mislabelled_tools": sum(1 for info in context_classified if info["mislabelled"]),
        "unauthenticated_high_consequence": sum(
            len(f.affected) for f in findings if f.id == "AUTH-001"),
        "shadowed_entries": len(all_shadowed(contexts)),
        "unpinned_servers": sum(
            1 for s in inventory.servers
            if s.transport == "stdio" and s.enabled and not s.version_pinned),
        "unused_tools": None,  # requires --usage data; M2 does not consume it
    }

    return Report(summary, list(contexts), breakdown, findings, by_server)

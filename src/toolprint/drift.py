"""Drift classification, per spec section 8. First match wins.

The ordering is the design. Rule 3 - description changed while schema did not -
sits above the schema rules because it is the rug-pull signature: an attacker
rewriting a tool's instructions has to leave the schema alone or the tool stops
working, so that exact correlation is the thing worth shouting about. Ranking a
schema change above it would bury the finding under routine churn.

Every rule is checked against active exceptions before it is emitted, and an
exception without an expiry date does not exist: see baseline.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from . import effects, lexical
from .findings.library import CRITICAL, HIGH, LOW, MEDIUM

# Stable rule ids, in precedence order.
RULES = [
    ("DRIFT-001", CRITICAL, "Effect class escalated"),
    ("DRIFT-002", CRITICAL, "Safety annotation revoked"),
    ("DRIFT-003", HIGH, "Description changed while schema did not"),
    ("DRIFT-004", HIGH, "Suspicious characters newly present"),
    ("DRIFT-005", HIGH, "Description newly references another server's tools"),
    ("DRIFT-006", MEDIUM, "Breaking schema change"),
    ("DRIFT-007", MEDIUM, "New tool appeared"),
    ("DRIFT-008", MEDIUM, "Server instructions changed"),
    ("DRIFT-009", LOW, "Additive schema change"),
    ("DRIFT-010", LOW, "Tool removed"),
]
RULE_TITLE = {rid: title for rid, _, title in RULES}
RULE_SEVERITY = {rid: sev for rid, sev, _ in RULES}

REMEDIATION = {
    "DRIFT-001": "A tool that used to read can now write, send or destroy. Review the "
                 "new definition before approving it, and treat any use since the "
                 "change as having had that capability.",
    "DRIFT-002": "The server withdrew a safety annotation it previously declared. "
                 "Clients and reviewers act on these, so verify why before approving.",
    "DRIFT-003": "The instructions the model reads changed while the callable contract "
                 "did not. This is the signature of a definition rewritten to steer "
                 "behaviour rather than to change functionality. Read the new text.",
    "DRIFT-004": "Characters that hide meaning from a human reader appeared in text the "
                 "model reads. Inspect the raw bytes, not the rendered description.",
    "DRIFT-005": "A description now names tools belonging to a different server, which "
                 "is how one server steers calls intended for another.",
    "DRIFT-006": "The callable contract changed in a way that can break existing calls. "
                 "Confirm this was an intentional release.",
    "DRIFT-007": "A tool appeared in an approved server. Review what it can do before "
                 "approving it into the baseline.",
    "DRIFT-008": "The server's instruction string changed. It is prepended to context "
                 "and is not covered by any tool's schema.",
    "DRIFT-009": "Parameters were added without breaking existing calls. Usually a "
                 "routine release; approve to silence.",
    "DRIFT-010": "A tool disappeared from an approved server. Confirm it was retired "
                 "deliberately rather than failing to load.",
}


@dataclass
class Change:
    rule: str
    severity: str
    title: str
    server: str
    tool: Optional[str]
    detail: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    excepted: Optional[Dict[str, Any]] = None


def _annotation_revoked(old: Dict[str, Any], new: Dict[str, Any]) -> Optional[str]:
    old_ann, new_ann = old.get("annotations") or {}, new.get("annotations") or {}
    if old_ann.get("readOnlyHint") is True and new_ann.get("readOnlyHint") is False:
        return "readOnlyHint changed from true to false"
    if old_ann.get("destructiveHint") is False and new_ann.get("destructiveHint") is True:
        return "destructiveHint changed from false to true"
    return None


def _schema_delta(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, List[str]]:
    """Classify a schema change as breaking, additive, or neither."""
    old_shape = old.get("schema_shape") or {"required": [], "properties": {}}
    new_shape = new.get("schema_shape") or {"required": [], "properties": {}}
    old_props: Dict[str, List[str]] = old_shape.get("properties") or {}
    new_props: Dict[str, List[str]] = new_shape.get("properties") or {}
    old_required = set(old_shape.get("required") or [])
    new_required = set(new_shape.get("required") or [])

    breaking, additive = [], []
    for name in sorted(set(old_props) - set(new_props)):
        breaking.append("parameter {!r} removed".format(name))
    for name in sorted(new_required - old_required):
        if name in old_props:
            breaking.append("parameter {!r} is now required".format(name))
        else:
            breaking.append("new required parameter {!r}".format(name))
    for name in sorted(set(old_props) & set(new_props)):
        old_types, new_types = set(old_props[name]), set(new_props[name])
        if old_types and new_types and new_types < old_types:
            breaking.append("parameter {!r} narrowed to {}".format(
                name, ", ".join(sorted(new_types))))
        elif old_types and new_types and old_types < new_types:
            additive.append("parameter {!r} widened to {}".format(
                name, ", ".join(sorted(new_types))))
    for name in sorted(set(new_props) - set(old_props)):
        if name not in new_required:
            additive.append("optional parameter {!r} added".format(name))
    for name in sorted(old_required - new_required):
        additive.append("parameter {!r} is no longer required".format(name))
    return {"breaking": breaking, "additive": additive}


def _classify_tool(server: str, name: str, old: Dict[str, Any], new: Dict[str, Any],
                   live: Optional[Dict[str, Any]],
                   cross_refs: Sequence[Dict[str, Any]]) -> Optional[Change]:
    """First matching rule wins. Order is precedence, not convenience."""
    def make(rule: str, detail: str, **evidence) -> Change:
        return Change(rule, RULE_SEVERITY[rule], RULE_TITLE[rule], server, name,
                      detail, evidence)

    revoked = _annotation_revoked(old, new)
    old_effect, new_effect = old.get("effect"), new.get("effect")
    if old_effect in effects.RANK and new_effect in effects.RANK:
        if effects.RANK[new_effect] > effects.RANK[old_effect]:
            # Rule 1 outranks rule 2 per spec section 8, and both are critical -
            # but a revoked annotation is usually the *cause* of the escalation,
            # and a report that hides the cause is harder to act on.
            because = _schema_delta(old, new)["breaking"]
            cause = (revoked if revoked else
                     ("; ".join(because[:2]) if because else None))
            return make("DRIFT-001",
                        "effect class escalated from {} to {}{}".format(
                            old_effect, new_effect,
                            " ({})".format(cause) if cause else ""),
                        was=old_effect, now=new_effect, cause=cause)

    if revoked:
        return make("DRIFT-002", revoked)

    description_changed = old.get("description_hash") != new.get("description_hash")
    schema_changed = old.get("schema_hash") != new.get("schema_hash")

    # DELIBERATE DEVIATION from spec section 8, which orders 3 before 4 and 5.
    # Taken literally, rules 4 and 5 are almost unreachable: text carrying a bidi
    # override or naming another server's tool has, by definition, also changed
    # its description, so rule 3 would always claim it first and the specific
    # explanation would never be printed. All three are HIGH, so nothing is
    # under-reported by checking the specific cases first - the reader simply
    # gets "invisible characters appeared" instead of "the text changed", which
    # is the difference between an actionable finding and a diff.
    if description_changed and live is not None:
        hits = lexical.inspect_tool(live)
        if hits:
            return make("DRIFT-004",
                        "; ".join("{} in {}".format(h["kind"], h["field"]) for h in hits[:3]),
                        findings=hits[:5])

    if description_changed:
        for reference in cross_refs:
            if reference.get("tool") == name:
                return make("DRIFT-005",
                            "description names {!r}, owned by {}".format(
                                reference["references"], reference["owned_by"]),
                            references=reference["references"])

    if description_changed and not schema_changed:
        return make("DRIFT-003",
                    "the description or title changed while the schema did not",
                    description_hash_was=old.get("description_hash", "")[:12],
                    description_hash_now=new.get("description_hash", "")[:12])

    if schema_changed:
        delta = _schema_delta(old, new)
        if delta["breaking"]:
            return make("DRIFT-006", "; ".join(delta["breaking"][:4]), **delta)
        if delta["additive"]:
            return make("DRIFT-009", "; ".join(delta["additive"][:4]), **delta)
        return make("DRIFT-009", "schema changed without a shape-level difference", **delta)

    if old.get("annotations_hash") != new.get("annotations_hash"):
        return make("DRIFT-002", "annotations changed")
    return None


def compare(baseline_doc: Dict[str, Any], current: Dict[str, Any],
            live_tools: Optional[Dict[str, Dict[str, Any]]] = None,
            exceptions: Sequence[Dict[str, Any]] = ()) -> List[Change]:
    """Diff a snapshot against an approved baseline."""
    from .baseline import is_excepted

    live_tools = live_tools or {}
    old_servers = baseline_doc.get("servers") or {}
    changes: List[Change] = []

    # Cross-server shadowing needs every server's tool names at once, so it is
    # computed here rather than per tool.
    cross_by_server: Dict[str, List[Dict[str, Any]]] = {}
    if live_tools:
        as_lists = {identity: list(tools.values()) for identity, tools in live_tools.items()}
        for hit in lexical.shadowing(as_lists):
            cross_by_server.setdefault(hit["server"], []).append(hit)

    for identity in sorted(set(old_servers) | set(current)):
        old_server = old_servers.get(identity)
        new_server = current.get(identity)
        if old_server is None or new_server is None:
            # A server appearing or disappearing entirely is inventory, not drift:
            # it is already reported by the findings engine, and duplicating it
            # here would double-count it in CI.
            continue

        if old_server.get("instructions_hash") != new_server.get("instructions_hash"):
            changes.append(Change("DRIFT-008", RULE_SEVERITY["DRIFT-008"],
                                  RULE_TITLE["DRIFT-008"], identity, None,
                                  "server instruction string changed"))

        old_tools = old_server.get("tools") or {}
        new_tools = new_server.get("tools") or {}
        live = live_tools.get(identity) or {}
        refs = cross_by_server.get(identity, [])

        for name in sorted(set(new_tools) - set(old_tools)):
            changes.append(Change("DRIFT-007", RULE_SEVERITY["DRIFT-007"],
                                  RULE_TITLE["DRIFT-007"], identity, name,
                                  "tool appeared in an approved server",
                                  {"effect": new_tools[name].get("effect")}))
        for name in sorted(set(old_tools) - set(new_tools)):
            changes.append(Change("DRIFT-010", RULE_SEVERITY["DRIFT-010"],
                                  RULE_TITLE["DRIFT-010"], identity, name,
                                  "tool no longer advertised"))
        for name in sorted(set(old_tools) & set(new_tools)):
            change = _classify_tool(identity, name, old_tools[name], new_tools[name],
                                    live.get(name), refs)
            if change is not None:
                changes.append(change)

    for change in changes:
        change.excepted = is_excepted(exceptions, change.server, change.tool, change.rule)

    order = {rid: index for index, (rid, _, _) in enumerate(RULES)}
    changes.sort(key=lambda c: (order.get(c.rule, 99), c.server, c.tool or ""))
    return changes

"""Drift classification. Sixteen rules, checked in order; the first match wins.

Rule ids are stable - exceptions reference them - so they are assigned in the
order the rules were written, and the RULES list below is ordered by precedence.
The two stopped coinciding once rules were added, so read the list, not the
numbers.

The ordering is the design. Rule 3 - description changed while schema did not -
sits above the schema rules because it is the rug-pull signature: an attacker
rewriting a tool's instructions has to leave the schema alone or the tool stops
working, so that exact correlation is the thing worth shouting about. Ranking a
schema change above it would bury the finding under routine churn.

Every rule is checked against active exceptions before it is emitted, and an
exception without an expiry date does not exist: see baseline.py.
"""

from __future__ import annotations

import collections
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import canonical, effects, lexical, surface
from .findings.library import CRITICAL, HIGH, LOW, MEDIUM

# Stable rule ids, in precedence order.
RULES = [
    ("DRIFT-001", CRITICAL, "Effect class escalated"),
    ("DRIFT-002", CRITICAL, "Safety annotation revoked"),
    ("DRIFT-003", HIGH, "Description changed while schema did not"),
    ("DRIFT-004", HIGH, "Suspicious characters newly present"),
    ("DRIFT-005", HIGH, "Description newly references another server's tools"),
    ("DRIFT-014", HIGH, "Tools moved behind a dispatch router"),
    ("DRIFT-006", MEDIUM, "Breaking schema change"),
    ("DRIFT-007", MEDIUM, "New tool appeared"),
    ("DRIFT-008", MEDIUM, "Server instructions changed"),
    ("DRIFT-011", MEDIUM, "Safety annotation added or relaxed"),
    ("DRIFT-009", LOW, "Additive schema change"),
    ("DRIFT-015", LOW, "Schema changed inside its parameters"),
    ("DRIFT-016", LOW, "Description reformatted"),
    ("DRIFT-010", LOW, "Tool removed"),
    ("DRIFT-012", LOW, "Tool annotations changed"),
    ("DRIFT-013", LOW, "Server version changed"),
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
    "DRIFT-015": "The schema changed but no parameter was added, removed, retyped or "
                 "made required, so the change is in what the parameters say - "
                 "their descriptions, enums, defaults or constraints. Descriptions "
                 "inside a schema are text the model reads, the same as the tool's "
                 "own. The recorded shape cannot show which; compare the `check "
                 "--bundle` output from before and after.",
    "DRIFT-016": "Only the layout of the description changed - line breaks and spacing. "
                 "No word was added, removed or altered. Recorded so the baseline stays "
                 "current, not because anything needs review. Non-ASCII spaces are not "
                 "treated as layout, so an inserted non-breaking or zero-width character "
                 "is still reported as a real change.",
    "DRIFT-010": "A tool disappeared from an approved server. Confirm it was retired "
                 "deliberately rather than failing to load.",
    "DRIFT-011": "A safety hint changed without being revoked - most often a tool "
                 "newly claiming to be read-only or non-destructive. That is also how "
                 "a rug pull lowers a reviewer's guard, so confirm the claim matches "
                 "what the tool now does.",
    "DRIFT-012": "An annotation outside the four safety hints changed. Vendors use "
                 "these to gate and categorise tools, so it is usually a release "
                 "detail - but it is text the client reads, so check what moved.",
    "DRIFT-013": "The server reported a different version than the baseline recorded. "
                 "Usually the explanation for every other change on this server; if "
                 "there are none, an upgrade landed with an identical tool surface.",
    "DRIFT-014": "Tools disappeared in the same release that added a tool taking an "
                 "operation name and a free-form argument object. Their capability "
                 "has almost certainly moved behind that router rather than been "
                 "retired, which means it left the surface this tool can observe: "
                 "from here, changes to those operations produce no drift. Check "
                 "what the router reaches before approving, and pin the version.",
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


# The four hints the spec defines. Everything else in an annotations object is a
# vendor extension: real, and worth reporting, but not a safety claim.
HINT_KEYS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


def _annotation_revoked(old: Dict[str, Any], new: Dict[str, Any]) -> Optional[str]:
    old_ann, new_ann = old.get("annotations") or {}, new.get("annotations") or {}
    if old_ann.get("readOnlyHint") is True and new_ann.get("readOnlyHint") is False:
        return "readOnlyHint changed from true to false"
    if old_ann.get("destructiveHint") is False and new_ann.get("destructiveHint") is True:
        return "destructiveHint changed from false to true"
    return None


def _annotation_delta(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Key-level annotation diff, split into safety hints and everything else.

    Baselines written before 0.3.1 stored only the four hints, so a vendor key
    present in the new record cannot be told apart from one that was always
    there and simply never written down. That case is reported as indeterminate
    rather than as an addition - claiming a key is new when the record cannot
    show that is how a routine release gets read as tampering.
    """
    old_ann = old.get("annotations") or {}
    new_ann = new.get("annotations") or {}
    hints_only = set(old_ann) <= set(HINT_KEYS)
    partial = hints_only and not set(new_ann) <= set(HINT_KEYS)

    hints, vendor = [], []
    for key in sorted(set(old_ann) | set(new_ann)):
        was, now = old_ann.get(key), new_ann.get(key)
        if was == now and key in old_ann and key in new_ann:
            continue
        if key not in old_ann:
            phrase = "{} added as {}".format(key, json.dumps(now))
        elif key not in new_ann:
            phrase = "{} removed (was {})".format(key, json.dumps(was))
        else:
            phrase = "{} changed from {} to {}".format(key, json.dumps(was), json.dumps(now))
        (hints if key in HINT_KEYS else vendor).append(phrase)

    return {"hint_changes": hints, "vendor_changes": vendor, "partial_record": partial}


def _sentence_edit(old: Dict[str, Any], new: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Which sentences a description lost and gained, as hashes.

    None when either record predates sentence hashes. Baselines written before
    this change hold only the byte-exact description hash, so for them the edit
    cannot be named and nothing is grouped - they behave exactly as they did.
    """
    was, now = old.get("description_sentences"), new.get("description_sentences")
    if not isinstance(was, list) or not isinstance(now, list):
        return None
    lost = collections.Counter(was) - collections.Counter(now)
    gained = collections.Counter(now) - collections.Counter(was)
    return {"sentences_removed": sorted(lost.elements()),
            "sentences_added": sorted(gained.elements())}


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
            # Escalation outranks annotation revocation, and both are critical -
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

    # The specific checks run before the general one, reversing the obvious
    # order. Otherwise DRIFT-004 and DRIFT-005 are almost unreachable: text carrying a bidi
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

    if (description_changed and not schema_changed
            and old.get("description_text_hash")
            and old.get("description_text_hash") == new.get("description_text_hash")):
        # Checked after DRIFT-004 and DRIFT-005, so a hidden character or a
        # cross-server reference arriving alongside a reformat is still reported
        # as what it is.
        return make("DRIFT-016", "line breaks or spacing changed; the wording did not")

    if description_changed and not schema_changed:
        evidence = {"description_hash_was": old.get("description_hash", "")[:12],
                    "description_hash_now": new.get("description_hash", "")[:12]}
        edit = _sentence_edit(old, new)
        if edit is not None:
            evidence.update(edit)
        return make("DRIFT-003",
                    "the description or title changed while the schema did not",
                    **evidence)

    if schema_changed:
        delta = _schema_delta(old, new)
        if delta["breaking"]:
            return make("DRIFT-006", "; ".join(delta["breaking"][:4]), **delta)
        if delta["additive"]:
            return make("DRIFT-009", "; ".join(delta["additive"][:4]), **delta)
        # Not additive: nothing was added. This went out as "Additive schema
        # change" with empty `additive` and `breaking` lists, which is 89 of the
        # 101 DRIFT-009s the public corpus ever recorded - the title was wrong
        # most of the time it appeared. chrome-devtools 1.9.0's new_page was
        # one: a parenthetical added to a property description.
        return make("DRIFT-015",
                    "no parameter was added, removed, retyped or made required; "
                    "a description, enum, default or constraint inside the schema changed",
                    schema_hash_was=old.get("schema_hash", "")[:12],
                    schema_hash_now=new.get("schema_hash", "")[:12])

    if old.get("annotations_hash") != new.get("annotations_hash"):
        # Reaching here means _annotation_revoked already returned None, so no
        # safety guarantee was withdrawn - which is what DRIFT-002 says happened.
        # Reporting it as such made every vendor annotation a critical finding
        # with nothing in the evidence to argue with.
        delta = _annotation_delta(old, new)
        detail = "; ".join((delta["hint_changes"] + delta["vendor_changes"])[:4])
        if delta["partial_record"]:
            detail = (detail + "; " if detail else "") + (
                "the baseline recorded only safety hints, so other keys cannot be "
                "compared")
        if delta["hint_changes"]:
            return make("DRIFT-011", detail or "a safety hint changed", **delta)
        return make("DRIFT-012", detail or "annotations changed", **delta)
    return None


def _group_identical_edits(changes: List[Change],
                          live_tools: Dict[str, Dict[str, Any]]) -> List[Change]:
    """One finding for one edit, however many tools it touched.

    azure 3.0.0-beta.43 removed the same boilerplate sentence from 59 tool
    descriptions and reflowed their layout. That arrived as 59 separate
    DRIFT-003s - the rug-pull signature, ranked high - for a template tidy-up,
    which is exactly the volume that gets a monitor switched off.

    Grouping reduces the count and never the severity. An attacker adding the
    same instruction to every tool would produce an identical edit too, and it
    must not be downgraded for being done at scale. Only DRIFT-003s whose
    removed and added sentences match exactly are merged, so a tool whose edit
    differs even slightly - the 60th azure tool gained "record retrieval, and
    version history" - keeps its own finding instead of disappearing into the
    group. Excepted changes are never grouped.
    """
    buckets: Dict[Tuple[str, Tuple[str, ...], Tuple[str, ...]], List[Change]] = {}
    keep: List[Change] = []
    for change in changes:
        removed = change.evidence.get("sentences_removed")
        added = change.evidence.get("sentences_added")
        if (change.rule != "DRIFT-003" or change.excepted or change.tool is None
                or removed is None or added is None or not (removed or added)):
            keep.append(change)
            continue
        key = (change.server, tuple(removed), tuple(added))
        buckets.setdefault(key, []).append(change)

    for (server, removed, added), members in sorted(buckets.items()):
        if len(members) < 2:
            keep.extend(members)
            continue
        tools = sorted(m.tool for m in members)
        added_text: List[str] = []
        for tool in tools:
            texts = canonical.sentence_texts((live_tools.get(server) or {}).get(tool) or {})
            added_text = [texts[h] for h in added if h in texts]
            if len(added_text) == len(added):
                break
        detail = "the same edit was made to {} tools' descriptions while their schemas did " \
                 "not change: {} sentence(s) removed, {} added".format(
                     len(tools), len(removed), len(added))
        if added_text:
            detail += " - added: " + "; ".join(repr(t[:120]) for t in added_text[:3])
        keep.append(Change(
            "DRIFT-003", RULE_SEVERITY["DRIFT-003"], RULE_TITLE["DRIFT-003"], server, None,
            detail,
            {"tools": tools, "sentences_removed": list(removed),
             "sentences_added": list(added), "added_text": added_text},
            excepted=False))
    return keep


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

        # A version bump is the ordinary explanation for every other change on
        # this server, and it was being collected but never compared - so a
        # routine upgrade arrived as a set of unexplained tool findings. Only
        # reported when both versions are known: a server that does not report
        # one, or was baselined without connecting, would otherwise flap.
        old_version, new_version = (old_server.get("server_version"),
                                    new_server.get("server_version"))
        if old_version and new_version and old_version != new_version:
            changes.append(Change("DRIFT-013", RULE_SEVERITY["DRIFT-013"],
                                  RULE_TITLE["DRIFT-013"], identity, None,
                                  "server version {} -> {}".format(old_version, new_version),
                                  {"was": old_version, "now": new_version}))

        old_tools = old_server.get("tools") or {}
        new_tools = new_server.get("tools") or {}
        live = live_tools.get(identity) or {}
        refs = cross_by_server.get(identity, [])

        appeared = sorted(set(new_tools) - set(old_tools))
        retired = sorted(set(old_tools) - set(new_tools))

        # Tools vanishing in the same revision that adds a router is not
        # retirement, it is relocation: the capability moved somewhere this
        # tool cannot see. Sentry did exactly this - 15 tools including
        # create_project, create_team and create_dsn replaced by one
        # execute_sentry_tool - and it was reported as fifteen low-severity
        # removals advising the reader to "confirm it was retired
        # deliberately". Needs the live schema, because a stored record keeps
        # only property names and types and cannot show that an object
        # declares nothing about its contents.
        routers = [n for n in appeared if surface.is_dispatch_router(live.get(n) or {})]
        if routers and retired:
            changes.append(Change(
                "DRIFT-014", RULE_SEVERITY["DRIFT-014"], RULE_TITLE["DRIFT-014"],
                identity, None,
                "{} disappeared in the same revision that added {}, which takes an "
                "operation name and a free-form argument object".format(
                    "{} tools".format(len(retired)) if len(retired) > 1
                    else "{!r}".format(retired[0]),
                    ", ".join(repr(r) for r in routers[:2])),
                {"router": routers, "gone": retired,
                 "effects": sorted({old_tools[n].get("effect") for n in retired})}))

        # The per-tool findings stay. They are what `approve` acts on, and
        # dropping them would leave the relocated tools in the baseline for
        # good; the finding above is the reading, not a replacement for it.
        for name in appeared:
            changes.append(Change("DRIFT-007", RULE_SEVERITY["DRIFT-007"],
                                  RULE_TITLE["DRIFT-007"], identity, name,
                                  "tool appeared in an approved server",
                                  {"effect": new_tools[name].get("effect")}))
        for name in retired:
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

    changes = _group_identical_edits(changes, live_tools)

    order = {rid: index for index, (rid, _, _) in enumerate(RULES)}
    changes.sort(key=lambda c: (order.get(c.rule, 99), c.server, c.tool or ""))
    return changes

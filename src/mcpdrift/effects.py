"""Effect-class inference: what a tool can actually do to the world.

Three independent signals, per spec section 9. The highest class any of them
produces wins, and annotations alone never downgrade a classification - a server
asserting readOnlyHint on a tool called delete_account is making a claim, not
providing evidence.

  A  declared annotations  readOnlyHint, destructiveHint, idempotentHint, openWorldHint
  B  lexical               the verb in the tool name
  C  schema hints          parameters named confirm, force, dry_run, cascade, ...

When the signals disagree - annotations claiming read-only while the name or
schema say otherwise - the tool is reported as MISLABELED. No other scanner
reports this, and it is the most useful thing here: a wrong annotation is worse
than a missing one, because clients and users act on it.

HEURISTICS_VERSION is recorded in every output. Changing any list below changes
classifications, which would otherwise be indistinguishable from real drift in
M5, so a bump is a re-approval event rather than a finding.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

HEURISTICS_VERSION = 1

READ = "read"
WRITE = "write"
EXTERNAL = "external"
IRREVERSIBLE = "irreversible"

# Display order only. `external` and `irreversible` are treated jointly as high
# consequence everywhere severity is decided, so their relative rank never
# changes an outcome - it only decides which single label a tool is shown under.
RANK = {READ: 0, WRITE: 1, EXTERNAL: 2, IRREVERSIBLE: 3}
CLASSES = (READ, WRITE, EXTERNAL, IRREVERSIBLE)
HIGH_CONSEQUENCE = (EXTERNAL, IRREVERSIBLE)

VERBS: Dict[str, Tuple[str, ...]] = {
    READ: ("get", "list", "read", "search", "fetch", "query", "find", "show",
           "describe", "count", "view", "inspect", "check", "lookup"),
    WRITE: ("create", "update", "set", "put", "post", "add", "insert", "upsert",
            "edit", "modify", "append", "move", "rename", "write", "patch",
            "assign", "upload", "save"),
    IRREVERSIBLE: ("delete", "remove", "drop", "purge", "destroy", "revoke",
                   "terminate", "cancel", "archive", "truncate", "reset",
                   "wipe", "erase", "prune", "revert"),
    EXTERNAL: ("send", "email", "publish", "notify", "tweet", "sms", "deploy",
               "pay", "charge", "transfer", "invite", "share", "broadcast",
               "dispatch", "submit"),
}

# Parameters that only exist because the operation is dangerous.
DANGEROUS_PARAMS = {
    "confirm": IRREVERSIBLE,
    "force": IRREVERSIBLE,
    "permanent": IRREVERSIBLE,
    "cascade": IRREVERSIBLE,
    "hard_delete": IRREVERSIBLE,
    "harddelete": IRREVERSIBLE,
    "dry_run": WRITE,
    "dryrun": WRITE,
    "recursive": WRITE,
    "overwrite": WRITE,
}

# Split tool names on separators and camelCase: "createIssue", "issues.create",
# "github__create_issue" all yield a "create" token.
_TOKENS = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")


def tokenise(name: str) -> List[str]:
    return [t.lower() for t in _TOKENS.split(name or "") if t]


def highest(classes: Sequence[str]) -> str:
    """Highest class present, defaulting to read when nothing is known."""
    present = [c for c in classes if c in RANK]
    if not present:
        return READ
    return max(present, key=lambda c: RANK[c])


def from_annotations(
    annotations: Optional[Dict[str, Any]],
) -> Tuple[Optional[str], Optional[str], List[str]]:
    """Signal A. Returns (floor, ceiling, reasons).

    Annotations make two different kinds of statement and conflating them
    produces false accusations. A *floor* says the tool is at least this
    consequential; a *ceiling* says it is at most this consequential. Only a
    ceiling can be contradicted by evidence.

      readOnlyHint: true   ceiling = read          "this only reads"
      readOnlyHint: false  floor   = write         "this is not merely a read"
      destructiveHint: true   floor   = irreversible
      destructiveHint: false  ceiling = external   "this is not destructive"

    Treating `readOnlyHint: false` as a claim of *write* and then flagging any
    higher inference was wrong, and wrong in the worst direction: on a real
    server it accused three correctly-annotated tools (deploy_schema,
    deploy_studio, publish_documents) of mislabelling because they declared
    themselves not-read-only and were then inferred as `external`. The annotation
    vocabulary has no way to say "external", so that is not a contradiction - it
    is the server being as precise as the schema allows.
    """
    if not isinstance(annotations, dict):
        return None, None, []
    reasons: List[str] = []
    floor: Optional[str] = None
    ceiling: Optional[str] = None

    if annotations.get("readOnlyHint") is True:
        ceiling = READ
        reasons.append("readOnlyHint is true")
    elif annotations.get("readOnlyHint") is False:
        floor = WRITE
        reasons.append("readOnlyHint is false")

    if annotations.get("destructiveHint") is True:
        floor = IRREVERSIBLE
        reasons.append("destructiveHint is true")
    elif annotations.get("destructiveHint") is False:
        # Not destructive, so anything up to and including external is consistent.
        # Keep the tighter ceiling when readOnlyHint already set one.
        ceiling = READ if ceiling == READ else EXTERNAL
        reasons.append("destructiveHint is false")

    if annotations.get("openWorldHint") is True:
        reasons.append("openWorldHint is true")
    return floor, ceiling, reasons


def from_name(name: str) -> Tuple[Optional[str], List[str]]:
    """Signal B. The verb in the name, matched as a whole token."""
    tokens = set(tokenise(name))
    hits: List[str] = []
    reasons: List[str] = []
    for effect in CLASSES:
        matched = sorted(tokens & set(VERBS[effect]))
        if matched:
            hits.append(effect)
            reasons.append("name contains {!r} ({})".format(matched[0], effect))
    if not hits:
        return None, reasons
    return highest(hits), reasons


def from_schema(schema: Optional[Dict[str, Any]]) -> Tuple[Optional[str], List[str]]:
    """Signal C. Parameters that only exist because the operation is dangerous."""
    if not isinstance(schema, dict):
        return None, []
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return None, []
    hits: List[str] = []
    reasons: List[str] = []
    for parameter in sorted(properties):
        effect = DANGEROUS_PARAMS.get(parameter.lower().replace("-", "_"))
        if effect:
            hits.append(effect)
            reasons.append("parameter {!r} implies {}".format(parameter, effect))
    if not hits:
        return None, reasons
    return highest(hits), reasons


def classify(tool: Dict[str, Any]) -> Dict[str, Any]:
    """Return the effect class for one tool, with the evidence behind it."""
    name = tool.get("name") if isinstance(tool.get("name"), str) else ""
    floor, ceiling, annotation_reasons = from_annotations(tool.get("annotations"))
    lexical, name_reasons = from_name(name)
    schematic, schema_reasons = from_schema(tool.get("inputSchema"))

    inferred = [c for c in (lexical, schematic) if c]
    # Annotations raise the floor but never lower the result: a server asserting
    # read-only on a tool called delete_account is making a claim, not evidence.
    effect = highest([c for c in (floor, lexical, schematic) if c])

    # Mislabelled only when the evidence exceeds a ceiling the server actually
    # declared. A missing or less specific annotation is not a contradiction.
    mislabelled = bool(
        ceiling is not None and inferred and RANK[highest(inferred)] > RANK[ceiling]
    )

    return {
        "effect": effect,
        "declared_floor": floor,
        "declared_ceiling": ceiling,
        "inferred": highest(inferred) if inferred else None,
        "mislabelled": mislabelled,
        "evidence": annotation_reasons + name_reasons + schema_reasons,
        "heuristics_version": HEURISTICS_VERSION,
    }


def classify_all(tools: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Effect classification per tool name, in a stable order."""
    result: Dict[str, Dict[str, Any]] = {}
    for tool in tools:
        name = tool.get("name")
        if isinstance(name, str):
            result[name] = classify(tool)
    return result


def counts(classifications: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    tally = {effect: 0 for effect in CLASSES}
    for item in classifications:
        effect = item.get("effect")
        if effect in tally:
            tally[effect] += 1
    return tally

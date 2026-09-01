"""The findings library: stable ids, fixed titles, standard remediation text.

Written once, before the findings that use them. Three reasons, in ascending
order of importance:

  * Reports stay comparable between runs and between machines.
  * A stable id survives rewording, so a baseline can reference it in M5.
  * After a handful of assessments most findings repeat, so writing the
    remediation text once is most of the margin on a paid engagement.

Severity is decided by the engine, not fixed here: the same finding can be
critical or low depending on what it applies to. What is fixed is the id, the
title and the advice - the parts a reader compares across reports.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

# Ascending, so `>=` comparisons read naturally against a --fail-on threshold.
SEVERITY_ORDER: Dict[str, int] = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}
SEVERITIES: List[str] = [INFO, LOW, MEDIUM, HIGH, CRITICAL]

AUTH = "auth"
EFFECT = "effect"
COST = "cost"
HYGIENE = "hygiene"
DRIFT = "drift"


@dataclass(frozen=True)
class Definition:
    id: str
    category: str
    title: str
    # One imperative line for the terminal. Kept separate from `remediation`
    # because the first sentence of an explanation is the diagnosis, not the
    # action, and truncating prose to fit a line reliably produces the wrong one.
    fix: str
    remediation: str


DEFINITIONS: Dict[str, Definition] = {d.id: d for d in [
    Definition(
        "AUTH-001", AUTH,
        "High-consequence tools reachable without authentication",
        "Put an authenticated transport in front of these servers, or unload "
        "the destructive tools.",
        "Put an authenticated transport in front of these servers, or remove "
        "the destructive tools from the surface the model sees. A server with "
        "no credential is reachable by anything that can reach the endpoint.",
    ),
    Definition(
        "AUTH-002", AUTH,
        "Static credential grants destructive or outbound capability",
        "Move to scoped OAuth where the server supports it, and rotate the "
        "key.",
        "A long-lived API key in an environment variable cannot be scoped per "
        "conversation and is not revoked when a session ends. Prefer OAuth "
        "with least-privilege scopes, and rotate the key if it has ever been "
        "shared.",
    ),
    Definition(
        "AUTH-003", AUTH,
        "Authentication headers are minted by an external command",
        "Confirm what the helper command does and that its own inputs are "
        "protected.",
        "A headersHelper runs an arbitrary program in the credential path, "
        "and the resulting auth posture cannot be determined statically. "
        "Confirm what the command does and that its own inputs are protected.",
    ),
    Definition(
        "EFFECT-001", EFFECT,
        "Capability profile of the loaded tool surface",
        "Check that every destructive and outbound tool needs to be loaded "
        "here.",
        "Review whether every destructive and outbound tool needs to be "
        "loaded in this context. Tools the model can see, it can call.",
    ),
    Definition(
        "EFFECT-002", EFFECT,
        "Tool annotations disagree with the tool's name or schema",
        "Report it to the server's maintainer; treat the annotation as absent "
        "meanwhile.",
        "A tool declaring readOnlyHint while its name or parameters indicate "
        "otherwise is worse than one declaring nothing, because clients and "
        "reviewers act on the annotation. Report this to the server's "
        "maintainer; until it is fixed, treat the annotation as absent.",
    ),
    Definition(
        "COST-001", COST,
        "Tool definitions consume a large share of the context window",
        "Unload servers this project does not use.",
        "This is spent on every request in the context, before any user "
        "input. Remove servers not needed in this project, or split them "
        "across projects so each context loads only what it uses.",
    ),
    Definition(
        "COST-002", COST,
        "A small number of tools dominate the context cost",
        "Trim or unload the few heaviest tool definitions first.",
        "Concentrated cost is the cheapest thing to fix: removing or trimming "
        "a few verbose tool definitions recovers most of the budget without "
        "reducing capability elsewhere.",
    ),
    Definition(
        "HYG-001", HYGIENE,
        "Configured server could not be reached",
        "Fix or remove the entry.",
        "A server that fails to start is dead configuration: it costs nothing "
        "in tokens but it also does nothing, and it hides the fact that "
        "whatever it was meant to provide is missing. Fix or remove the "
        "entry.",
    ),
    Definition(
        "HYG-002", HYGIENE,
        "Literal credential stored in an MCP client config file",
        "Move the value to an environment variable, reference it as ${VAR}, "
        "and rotate it.",
        "Config files are not a credential store: they are world-readable, "
        "are routinely copied between machines, and are easy to commit by "
        "accident. Move the value to an environment variable and reference it "
        "as ${VAR}. Treat any credential that has been stored this way as "
        "exposed and rotate it.",
    ),
    Definition(
        "HYG-003", HYGIENE,
        "Configured server is shadowed and never loads",
        "Remove the shadowed entry, or rename it if both were meant to load.",
        "A higher-precedence scope defines the same server name, and the "
        "whole entry from that scope is used - nothing is merged. Editing the "
        "shadowed entry has no effect and produces no warning. Remove it, or "
        "rename it if both were meant to load.",
    ),
    Definition(
        "HYG-004", HYGIENE,
        "Shadowed server points to a different endpoint than the one that "
        "loads",
        "Rename one of the two definitions.",
        "Two definitions of one name resolve to different destinations "
        "depending on which project you are in. Credentials are stored per "
        "endpoint, so authenticating in one project leaves you "
        "unauthenticated in another, and a later change to either definition "
        "is invisible. Rename one.",
    ),
]}


def definition(finding_id: str) -> Definition:
    return DEFINITIONS[finding_id]


def at_or_above(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 0)

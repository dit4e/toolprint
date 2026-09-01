"""SARIF 2.1.0 output.

This matters more than it looks: SARIF drops straight into GitHub code scanning,
which is free distribution to exactly the audience that should be running this in
CI. A finding that appears as an annotation on a pull request gets acted on; the
same finding in terminal output does not.

Results are anchored to the config file that defines the server, because that is
the file someone has to edit to fix them. A finding with no location is filed
against the repository root and is easy to ignore.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Dict, List, Optional, Sequence

from .. import __version__
from ..drift import REMEDIATION, RULES, Change
from ..findings.engine import Finding, Report
from ..findings.library import DEFINITIONS
from ..model import Inventory

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/dit4e/toolprint"

# SARIF has four levels; toolprint has five severities.
LEVEL = {"critical": "error", "high": "error", "medium": "warning",
         "low": "note", "info": "note"}
# Keep the original severity visible, since two of ours collapse onto "error".
RANK = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.1}


def _rules() -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    for spec in sorted(DEFINITIONS.values(), key=lambda d: d.id):
        rules.append(OrderedDict([
            ("id", spec.id),
            ("name", spec.id.replace("-", "")),
            ("shortDescription", {"text": spec.title}),
            ("fullDescription", {"text": spec.remediation}),
            ("help", {"text": "{}\n\nFix: {}".format(spec.remediation, spec.fix)}),
            ("properties", {"category": spec.category}),
        ]))
    for rule_id, severity, title in RULES:
        rules.append(OrderedDict([
            ("id", rule_id),
            ("name", rule_id.replace("-", "")),
            ("shortDescription", {"text": title}),
            ("fullDescription", {"text": REMEDIATION[rule_id]}),
            ("help", {"text": REMEDIATION[rule_id]}),
            ("defaultConfiguration", {"level": LEVEL.get(severity, "warning")}),
            ("properties", {"category": "drift"}),
        ]))
    return rules


def _location(path: Optional[str]) -> List[Dict[str, Any]]:
    if not path:
        return []
    return [{"physicalLocation": {
        "artifactLocation": {"uri": path.lstrip("/"), "uriBaseId": "%SRCROOT%"}}}]


def _source_paths(inventory: Inventory) -> Dict[str, str]:
    return {s.key: s.source_path for s in inventory.servers}


def _result(rule_id: str, severity: str, message: str, path: Optional[str],
            fingerprint: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    result = OrderedDict([
        ("ruleId", rule_id),
        ("level", LEVEL.get(severity, "warning")),
        ("rank", RANK.get(severity, 0.5)),
        ("message", {"text": message}),
        ("locations", _location(path)),
        # Stable across runs, so code scanning tracks one finding rather than
        # closing and reopening it on every scan.
        ("partialFingerprints", {"toolprintFingerprint/v1": fingerprint}),
        ("properties", OrderedDict([("severity", severity)])),
    ])
    if extra:
        result["properties"].update(extra)
    return result


def build(report: Report, inventory: Inventory,
          changes: Sequence[Change] = ()) -> Dict[str, Any]:
    paths = _source_paths(inventory)
    results: List[Dict[str, Any]] = []

    for finding in report.findings:
        first = finding.affected[0] if finding.affected else {}
        path = paths.get(first.get("server", ""))
        target = first.get("server", "")
        if first.get("tool"):
            target += "/" + first["tool"]
        results.append(_result(
            finding.id, finding.severity,
            "{}: {}".format(finding.title, finding.detail),
            path, "{}:{}".format(finding.id, target),
            {"affectedCount": len(finding.affected)},
        ))

    for change in changes:
        if change.excepted:
            continue  # an accepted exception is not a CI failure
        target = "{}/{}".format(change.server, change.tool or "")
        results.append(_result(
            change.rule, change.severity,
            "{}: {} ({})".format(change.title, change.detail, target),
            None, "{}:{}".format(change.rule, target),
        ))

    return OrderedDict([
        ("$schema", SCHEMA),
        ("version", "2.1.0"),
        ("runs", [OrderedDict([
            ("tool", {"driver": OrderedDict([
                ("name", "toolprint"),
                ("version", __version__),
                ("informationUri", INFORMATION_URI),
                ("rules", _rules()),
            ])}),
            ("results", results),
        ])]),
    ])

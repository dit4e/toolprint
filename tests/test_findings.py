"""The findings engine and findings.json.

The two-run test lives here too: findings.json is the contract everything else
renders from, so instability in it corrupts every downstream comparison.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from toolprint import connect, context, discover
from toolprint.findings import engine, library
from toolprint.render import findings_json
from tests.fixtures import build as fixture

READ_TOOL = {"name": "list_items", "description": "List items",
             "inputSchema": {"type": "object", "properties": {}}}
DELETE_TOOL = {"name": "delete_item", "description": "Delete an item permanently",
               "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}}}
SEND_TOOL = {"name": "send_invoice", "description": "Email an invoice",
             "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}}}}
MISLABELLED_TOOL = {"name": "upload_asset", "description": "Upload an asset",
                    "annotations": {"readOnlyHint": True}}


class EngineCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.home = self.tmp / "home"
        self.project = self.home / "work" / "proj"
        fixture.build(self.home, self.project)
        self.inv = discover.collect(home=self.home, project_patterns=[str(self.project)])
        self.contexts = context.resolve_all(self.inv)
        self.by_key = {s.key: s for s in self.inv.servers}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def give(self, key, tools):
        """Attach tools to a server as though --connect had retrieved them."""
        from toolprint import tokens

        server = self.by_key[key]
        server.tools = tools
        server.fetch_status = "ok"
        server.tool_tokens, server.token_total, server.token_method = tokens.count_tools(tools)

    def run_engine(self, window=200000, price=None):
        return engine.analyse(self.inv, self.contexts, window, price)

    def ids(self, report):
        return {f.id for f in report.findings}

    def find(self, report, finding_id):
        return [f for f in report.findings if f.id == finding_id][0]


class TestAuthFindings(EngineCase):
    def test_unauthenticated_remote_with_destructive_tools_is_critical(self):
        self.give("claude_code/user/wide-open", [DELETE_TOOL, READ_TOOL])
        report = self.run_engine()
        finding = self.find(report, "AUTH-001")
        self.assertEqual(finding.severity, library.CRITICAL)
        self.assertEqual([a["tool"] for a in finding.affected], ["delete_item"])

    def test_local_stdio_with_no_credential_is_not_flagged(self):
        """A local subprocess has no credential because it needs none.

        Flagging every filesystem server as critically unauthenticated is the
        alert fatigue that ends with users passing --fail-on none.
        """
        self.give("claude_code/local/local-github", [DELETE_TOOL])
        self.assertNotIn("AUTH-001", self.ids(self.run_engine()))

    def test_static_credential_with_destructive_tools_is_high(self):
        self.give("claude_code/user/user-remote", [DELETE_TOOL, SEND_TOOL])
        finding = self.find(self.run_engine(), "AUTH-002")
        self.assertEqual(finding.severity, library.HIGH)
        self.assertEqual(len(finding.affected), 2)

    def test_read_only_server_raises_no_auth_finding(self):
        self.give("claude_code/user/wide-open", [READ_TOOL])
        ids = self.ids(self.run_engine())
        self.assertNotIn("AUTH-001", ids)
        self.assertNotIn("AUTH-002", ids)

    def test_headers_helper_is_reported(self):
        self.assertIn("AUTH-003", self.ids(self.run_engine()))


class TestEffectFindings(EngineCase):
    def test_mislabelled_tools_are_reported_with_evidence(self):
        self.give("claude_code/user/user-remote", [MISLABELLED_TOOL])
        finding = self.find(self.run_engine(), "EFFECT-002")
        self.assertEqual(finding.severity, library.MEDIUM)
        self.assertTrue(finding.evidence)

    def test_capability_profile_is_informational(self):
        self.give("claude_code/user/user-remote", [READ_TOOL, DELETE_TOOL, SEND_TOOL])
        finding = self.find(self.run_engine(), "EFFECT-001")
        self.assertEqual(finding.severity, library.INFO)
        self.assertEqual(finding.evidence["high_consequence"], 2)


class TestCostFindings(EngineCase):
    def test_severity_scales_with_window_share(self):
        self.give("claude_code/user/user-remote", [DELETE_TOOL] * 1)
        tokens = self.by_key["claude_code/user/user-remote"].token_total
        for window, expected in [
            (tokens * 2, library.HIGH),      # 50%
            (tokens * 4, library.MEDIUM),    # 25%
            (tokens * 10, library.LOW),      # 10%
            (tokens * 100, library.INFO),    # 1%
        ]:
            self.assertEqual(self.find(self.run_engine(window), "COST-001").severity,
                             expected, window)

    def test_cost_is_reported_for_the_heaviest_context_only(self):
        self.give("claude_code/user/user-remote", [READ_TOOL])
        report = self.run_engine()
        self.assertEqual(report.summary["heaviest_context"],
                         self.find(report, "COST-001").evidence["context"])

    def test_price_is_omitted_rather_than_guessed(self):
        self.give("claude_code/user/user-remote", [READ_TOOL])
        self.assertIsNone(self.run_engine().summary["est_cost_per_conversation_usd"])
        self.assertIsNotNone(self.run_engine(price=3.0).summary["est_cost_per_conversation_usd"])

    def test_breakdown_is_ranked_by_cost(self):
        self.give("claude_code/user/user-remote", [READ_TOOL, DELETE_TOOL, SEND_TOOL])
        rows = [r["tokens"] for r in self.run_engine().cost_breakdown]
        self.assertEqual(rows, sorted(rows, reverse=True))


class TestHygieneFindings(EngineCase):
    def test_literal_credentials_are_high(self):
        self.assertEqual(self.find(self.run_engine(), "HYG-002").severity, library.HIGH)

    def test_shadowing_splits_by_whether_the_endpoint_differs(self):
        report = self.run_engine()
        self.assertEqual(self.find(report, "HYG-003").severity, library.LOW)
        self.assertEqual(self.find(report, "HYG-004").severity, library.MEDIUM)

    def test_unreachable_servers_are_reported(self):
        server = self.by_key["claude_code/user/wide-open"]
        server.fetch_status = "unreachable"
        server.fetch_detail = "connection refused"
        self.assertIn("HYG-001", self.ids(self.run_engine()))


class TestOrderingAndThresholds(EngineCase):
    def test_findings_are_sorted_most_severe_first(self):
        self.give("claude_code/user/wide-open", [DELETE_TOOL])
        severities = [library.SEVERITY_ORDER[f.severity] for f in self.run_engine().findings]
        self.assertEqual(severities, sorted(severities, reverse=True))

    def test_fail_on_threshold(self):
        self.assertTrue(library.at_or_above("critical", "high"))
        self.assertTrue(library.at_or_above("high", "high"))
        self.assertFalse(library.at_or_above("medium", "high"))

    def test_every_finding_has_a_library_definition(self):
        self.give("claude_code/user/wide-open", [DELETE_TOOL, MISLABELLED_TOOL])
        for finding in self.run_engine().findings:
            spec = library.definition(finding.id)
            self.assertEqual(finding.title, spec.title)
            self.assertEqual(finding.fix, spec.fix)
            self.assertTrue(finding.detail)


class TestFindingsJsonDeterminism(EngineCase):
    def build(self):
        inv = discover.collect(home=self.home, project_patterns=[str(self.project)])
        contexts = context.resolve_all(inv)
        for key, tools in [("claude_code/user/wide-open", [DELETE_TOOL, READ_TOOL]),
                           ("claude_code/user/user-remote", [SEND_TOOL, MISLABELLED_TOOL])]:
            from toolprint import tokens

            server = {s.key: s for s in inv.servers}[key]
            server.tools = tools
            server.fetch_status = "ok"
            server.tool_tokens, server.token_total, server.token_method = tokens.count_tools(tools)
        report = engine.analyse(inv, contexts, 200000)
        return json.dumps(findings_json.build(inv, report, "FIXED"), indent=2)

    def test_two_runs_are_byte_identical(self):
        self.assertEqual(self.build(), self.build())

    def test_schema_shape(self):
        document = json.loads(self.build())
        for key in ("schema_version", "generated_at", "generator", "heuristics_version",
                    "mode", "summary", "contexts", "servers", "cost_breakdown",
                    "findings", "drift", "benchmark"):
            self.assertIn(key, document)
        self.assertEqual(document["schema_version"], findings_json.SCHEMA_VERSION)
        self.assertIsNone(document["drift"])       # M5
        self.assertIsNone(document["benchmark"])   # M6

    def test_generated_at_is_the_only_varying_field(self):
        first = json.loads(self.build())
        second = json.loads(self.build())
        first["generated_at"] = second["generated_at"] = None
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()


class TestSummaryConsistency(EngineCase):
    """Every number in `summary` must describe the same thing: the heaviest context.

    effect_counts was originally computed across all entries while tool_count
    described one context, so a server registered in two clients made the two
    disagree in the same block of output.
    """

    def test_effect_counts_sum_to_tool_count(self):
        self.give("claude_code/user/wide-open", [READ_TOOL, DELETE_TOOL, SEND_TOOL])
        self.give("claude_code/user/user-remote", [MISLABELLED_TOOL])
        summary = self.run_engine().summary
        self.assertEqual(sum(summary["effect_counts"].values()), summary["tool_count"])

    def test_mislabelled_count_is_scoped_to_the_same_context(self):
        self.give("claude_code/user/user-remote", [MISLABELLED_TOOL])
        report = self.run_engine()
        top = {c.key: c for c in report.contexts}[report.summary["heaviest_context"]]
        expected = sum(
            1
            for server in top.servers
            for info in report.effects_by_server.get(server.key, {}).values()
            if info["mislabelled"]
        )
        self.assertEqual(report.summary["mislabelled_tools"], expected)

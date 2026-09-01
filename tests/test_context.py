"""Context resolution and connect planning.

The unit that matters is a client in a project, because that is what a single
conversation loads. These tests pin the precedence rules verified on 2026-08-31
and the shadowing they imply.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from mcpdrift import connect, context, discover
from tests.fixtures import build as fixture


class ContextCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.home = self.tmp / "home"
        self.project = self.home / "work" / "proj"
        fixture.build(self.home, self.project)
        self.project_key = str(self.project.resolve())
        self.inv = discover.collect(home=self.home, project_patterns=[str(self.project)])
        self.contexts = context.resolve_all(self.inv)
        self.by_key = {c.key: c for c in self.contexts}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def ctx(self, client, project=None):
        return self.by_key["{}::{}".format(client, project or "-")]


class TestPrecedence(ContextCase):
    def test_local_beats_project_beats_user(self):
        resolved = {s.name: s for s in self.ctx("claude_code", self.project_key).servers}
        # local scope defines local-github; .mcp.json also does. Local wins.
        self.assertEqual(resolved["local-github"].scope, "local")
        # project scope defines user-remote; ~/.claude.json also does. Project wins.
        self.assertEqual(resolved["user-remote"].scope, "project")
        # only user scope defines these
        self.assertEqual(resolved["oauth-server"].scope, "user")

    def test_baseline_context_uses_user_scope_only(self):
        baseline = self.ctx("claude_code")
        self.assertTrue(all(s.scope == "user" for s in baseline.servers))
        self.assertEqual(baseline.shadowed, [])
        # In a directory with no project config, the user-scope definition loads.
        resolved = {s.name: s for s in baseline.servers}
        self.assertEqual(resolved["user-remote"].url_host, "mcp.example.com")

    def test_one_name_resolves_to_exactly_one_server(self):
        for ctx in self.contexts:
            names = [s.name for s in ctx.servers]
            self.assertEqual(len(names), len(set(names)), ctx.label)


class TestShadowing(ContextCase):
    def test_shadowed_entries_are_reported(self):
        shadowed = {s.loser.name for s in self.ctx("claude_code", self.project_key).shadowed}
        self.assertEqual(shadowed, {"local-github", "user-remote"})

    def test_endpoint_differs_flags_only_the_dangerous_one(self):
        by_name = {s.loser.name: s for s in self.ctx("claude_code", self.project_key).shadowed}
        # Same command, different scope: benign duplication.
        self.assertFalse(by_name["local-github"].endpoint_differs)
        # Same name, different host: which definition loads changes the destination.
        self.assertTrue(by_name["user-remote"].endpoint_differs)

    def test_all_shadowed_deduplicates_across_contexts(self):
        everything = context.all_shadowed(self.contexts)
        identities = {(s.loser.source_path, s.loser.name) for s in everything}
        self.assertEqual(len(everything), len(identities))


class TestConnectPlan(ContextCase):
    def test_fetches_each_distinct_server_once(self):
        plan = connect.plan(self.contexts)
        identities = [connect.fetch_identity(s) for s in plan.targets]
        self.assertEqual(len(identities), len(set(identities)))

    def test_entries_shadowed_in_every_context_are_never_contacted(self):
        """Shadowing is per-context, not global.

        claude_code/user/user-remote loses to the project-scope definition inside
        the project, but wins in a directory with no project config - so it does
        load, and must be contacted. The invariant is narrower than "never fetch
        a shadowed entry": an entry is only skipped when it loses *everywhere*.
        """
        plan = connect.plan(self.contexts)
        self.assertGreater(plan.skipped_shadowed, 0)

        winners = {id(s) for ctx in self.contexts for s in ctx.servers}
        always_lost = [
            item.loser for item in context.all_shadowed(self.contexts)
            if id(item.loser) not in winners
        ]
        self.assertTrue(always_lost, "fixture no longer covers this case")
        planned = {id(s) for s in plan.targets}
        for loser in always_lost:
            self.assertNotIn(id(loser), planned, loser.key)

    def test_an_entry_that_wins_somewhere_is_still_contacted(self):
        plan = connect.plan(self.contexts)
        hosts = {s.url_host for s in plan.targets if s.url_host}
        # Both definitions of user-remote load, in different contexts.
        self.assertIn("mcp.example.com", hosts)
        self.assertIn("other.example.com", hosts)

    def test_unsupported_transport_is_skipped_not_attempted(self):
        plan = connect.plan(self.contexts)
        self.assertEqual([s.name for s in plan.skipped_unsupported], ["ws-server"])

    def test_disabled_servers_are_not_contacted(self):
        plan = connect.plan(self.contexts)
        self.assertNotIn("disabled-one", [s.name for s in plan.targets])

    def test_plan_description_names_every_spawn(self):
        text = connect.plan(self.contexts).describe()
        for server in connect.plan(self.contexts).targets:
            if server.transport == "stdio":
                self.assertIn(server.command or "", text)
        self.assertIn("once each", text)

    def test_plan_is_deterministic(self):
        first = [s.key for s in connect.plan(self.contexts).targets]
        second = [s.key for s in connect.plan(self.contexts).targets]
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()

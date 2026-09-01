"""Discovery across every container shape the registry describes."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from mcpdrift import discover
from mcpdrift.model import (
    AUTH_ENV_VAR, AUTH_HELPER_COMMAND, AUTH_LITERAL_SECRET, AUTH_NONE, AUTH_OAUTH,
)
from tests.fixtures import build as fixture


class DiscoveryCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.home = self.tmp / "home"
        self.project = self.tmp / "home" / "work" / "proj"
        fixture.build(self.home, self.project)
        # Paths are normalised to their resolved form so one project is always
        # one context; on macOS the temp dir is reached via a /var symlink.
        self.project_key = str(self.project.resolve())
        self.inv = discover.collect(home=self.home, project_patterns=[str(self.project)])
        self.by_key = {s.key: s for s in self.inv.servers}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestContainerShapes(DiscoveryCase):
    def test_claude_code_both_scopes_from_one_file(self):
        user = [s for s in self.inv.servers if s.client == "claude_code" and s.scope == "user"]
        local = [s for s in self.inv.servers if s.client == "claude_code" and s.scope == "local"]
        self.assertEqual(len(user), 6)
        self.assertEqual(len(local), 1)
        # The wildcard step records which project the local-scope server belongs to.
        self.assertEqual(discover.normalise_root(local[0].scope_detail), self.project_key)

    def test_vscode_uses_servers_key_not_mcpservers(self):
        vscode = [s for s in self.inv.servers if s.client == "vscode"]
        self.assertEqual([s.name for s in vscode], ["vscode-local"])

    def test_project_scope_files_found_via_project_root(self):
        names = {s.name for s in self.inv.servers}
        self.assertIn("proj-time", names)      # <project>/.mcp.json
        self.assertIn("proj-cursor", names)    # <project>/.cursor/mcp.json

    def test_gemini_settings_nested_key(self):
        self.assertIn("gemini_cli/user/gem", self.by_key)

    def test_project_roots_derived_from_claude_code(self):
        roots = discover.claude_code_project_roots(self.home)
        self.assertEqual([str(r) for r in roots], [self.project_key])


class TestTransport(DiscoveryCase):
    def test_declared_and_inferred(self):
        self.assertEqual(self.by_key["claude_code/user/ws-server"].transport, "ws")
        self.assertEqual(self.by_key["claude_code/user/wide-open"].transport, "http")
        self.assertEqual(self.by_key["claude_code/local/local-github"].transport, "stdio")
        self.assertEqual(self.by_key["vscode/workspace/vscode-local"].transport, "stdio")

    def test_disabled_server_recorded_not_dropped(self):
        self.assertFalse(self.by_key["claude_code/user/disabled-one"].enabled)


class TestPostureOnRealShapes(DiscoveryCase):
    def test_postures(self):
        expected = {
            "claude_code/user/user-remote": AUTH_ENV_VAR,
            "claude_code/user/helper-auth": AUTH_HELPER_COMMAND,
            "claude_code/user/oauth-server": AUTH_OAUTH,
            "claude_code/user/wide-open": AUTH_NONE,
            "claude_code/local/local-github": AUTH_LITERAL_SECRET,
            "cursor/user/context7": AUTH_LITERAL_SECRET,
            "cursor/user/task-runner": AUTH_NONE,
            "gemini_cli/user/gem": AUTH_LITERAL_SECRET,
        }
        for key, posture in expected.items():
            self.assertEqual(self.by_key[key].auth_method, posture, key)

    def test_unauthenticated_remote_is_visible(self):
        # The AUTH-001 case in M2: a remote server with no credential at all.
        server = self.by_key["claude_code/user/wide-open"]
        self.assertEqual((server.transport, server.auth_method), ("http", AUTH_NONE))


class TestFailuresAreData(DiscoveryCase):
    def test_malformed_json_recorded_not_raised(self):
        malformed = [e for e in self.inv.errors if e.kind == "malformed"]
        self.assertEqual(len(malformed), 1)
        self.assertEqual(malformed[0].client, "windsurf")


class TestRedactionAccessors(DiscoveryCase):
    def test_command_basename_and_url_host(self):
        server = self.by_key["claude_code/local/local-github"]
        self.assertEqual(server.command_basename, "npx")
        remote = self.by_key["claude_code/user/user-remote"]
        self.assertEqual(remote.url_host, "mcp.example.com")


if __name__ == "__main__":
    unittest.main()

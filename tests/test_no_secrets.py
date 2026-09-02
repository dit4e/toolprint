"""The redaction boundary, asserted rather than assumed.

Spec section 16 calls for an automated secret grep. This is it, running against
every renderer. It is a test rather than a review checklist because the failure
mode - a new field added to a renderer that happens to carry a value - is exactly
the kind a human reading a diff misses.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from toolprint import discover
from toolprint.render import jsonout, text
from tests.fixtures import build as fixture

# Raw fields exist on the model for M4's bundle redaction, but must never appear
# in rendered output under these names.
FORBIDDEN_JSON_KEYS = {"command", "args", "url", "env", "headers", "headersHelper"}


class TestNoSecretsLeak(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        home = self.tmp / "home"
        project = home / "work" / "proj"
        fixture.build(home, project)
        self.inv = discover.collect(home=home, project_patterns=[str(project)])
        self.text_out = text.render(self.inv)
        self.json_out = json.dumps(jsonout.inventory_dict(self.inv), indent=2)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_fixture_actually_contains_secrets(self):
        # Guard against the test passing because the fixture is empty.
        self.assertGreaterEqual(len(self.inv.servers), 10)
        flagged = [s for s in self.inv.servers if s.secret_locations]
        self.assertGreaterEqual(len(flagged), 4)

    def test_no_secret_value_in_text_output(self):
        for secret in fixture.FAKE_SECRETS:
            self.assertNotIn(secret, self.text_out, secret[:12])

    def test_no_secret_value_in_json_output(self):
        for secret in fixture.FAKE_SECRETS:
            self.assertNotIn(secret, self.json_out, secret[:12])

    def test_env_and_header_values_absent_entirely(self):
        # Names are emitted, values never are.
        self.assertIn("GITHUB_TOKEN", self.json_out)
        self.assertNotIn("hunter2", self.json_out)
        self.assertNotIn("hunter2", self.text_out)

    def test_full_command_path_reduced_to_basename(self):
        self.assertIn("server.js", self.json_out)
        self.assertNotIn("/Users/someone/private", self.json_out)

    def test_url_query_string_never_emitted(self):
        self.assertIn("mcp.example.com", self.json_out)
        self.assertNotIn("tenant=acme", self.json_out)
        self.assertNotIn("/v1/mcp", self.json_out)

    def test_json_has_no_raw_value_carrying_keys(self):
        for server in jsonout.inventory_dict(self.inv)["servers"]:
            leaked = FORBIDDEN_JSON_KEYS & set(server.keys())
            self.assertEqual(leaked, set(), "renderer exposed raw fields: {}".format(leaked))


if __name__ == "__main__":
    unittest.main()


class TestCredentialsInServerOutput(unittest.TestCase):
    """A server's own error message is an exfiltration path.

    Servers quote their configuration when they fail to start, and that text
    reaches findings.json and watchlist observations that may be committed to a
    public repository. Confirmed by running a server that prints its key.
    """

    def server(self, detail, env=None, headers=None):
        from toolprint.model import Server

        s = Server(name="s", client="c", scope="user", scope_detail=None,
                   source_path="/p", transport="stdio", command="npx")
        s.raw_env = env or {}
        s.raw_headers = headers or {}
        s.fetch_detail = detail
        return s

    def test_env_value_is_redacted_from_stderr(self):
        secret = "sk-live-SUPERSECRET-abcdef1234567890"
        s = self.server("FATAL: key={} rejected".format(secret), env={"API_KEY": secret})
        self.assertNotIn(secret, s.safe_detail)
        self.assertIn("<redacted:API_KEY>", s.safe_detail)

    def test_header_value_is_redacted(self):
        secret = "Bearer abcdefghijklmnop1234"
        s = self.server("sent {}".format(secret), headers={"Authorization": secret})
        self.assertNotIn("abcdefghijklmnop1234", s.safe_detail)

    def test_expanded_value_is_redacted_not_just_the_reference(self):
        # The config says ${WATCH_TOKEN}; the server saw the expanded value, and
        # the expanded value is what appears in its error message.
        import os

        os.environ["WATCH_TOKEN"] = "ghp_" + "A" * 36
        try:
            s = self.server("auth failed for {}".format(os.environ["WATCH_TOKEN"]),
                            env={"WATCH_TOKEN": "${WATCH_TOKEN}"})
            self.assertNotIn("ghp_", s.safe_detail)
        finally:
            del os.environ["WATCH_TOKEN"]

    def test_unknown_credentials_are_caught_by_shape(self):
        # A token this tool never held: fetched by the server, or ambient.
        s = self.server("upstream said ghp_" + "B" * 36 + " is invalid")
        self.assertNotIn("ghp_", s.safe_detail)
        self.assertIn("<redacted>", s.safe_detail)

    def test_short_values_are_left_alone(self):
        # Redacting a three-character value would mangle the message it exists
        # to keep readable.
        s = self.server("could not connect to port 8080", env={"PORT": "8080"})
        self.assertIn("8080", s.safe_detail)

    def test_the_message_stays_useful(self):
        secret = "sk-live-SUPERSECRET-abcdef1234567890"
        s = self.server("command not found: npx (key={})".format(secret),
                        env={"API_KEY": secret})
        self.assertIn("command not found", s.safe_detail)

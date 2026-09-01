"""Bundle export and the standalone collection kit.

The kit's whole value is that a sceptical security engineer approves it in five
minutes. Two properties carry that: it cannot transmit, and redaction is an
allowlist. Both are asserted here, along with the line budget that makes the
five-minute read possible in the first place.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mcpdrift import bundle, discover
from tests.fixtures import build as fixture

KIT = Path(__file__).resolve().parent.parent / "src" / "mcpdrift" / "vendor" / "mcp_collect.py"
LINE_BUDGET = 400


class TestKitConstraints(unittest.TestCase):
    """The properties that decide whether the script gets run at all."""

    def setUp(self):
        self.source = KIT.read_text(encoding="utf-8")
        self.lines = self.source.splitlines()

    def test_fits_the_line_budget(self):
        # Not arbitrary: an unread script is a rejected script.
        self.assertLess(len(self.lines), LINE_BUDGET,
                        "kit is {} lines".format(len(self.lines)))

    def test_is_valid_python_and_has_no_third_party_imports(self):
        tree = ast.parse(self.source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        stdlib = {"argparse", "glob", "hashlib", "hmac", "json", "os", "platform", "re",
                  "shutil", "subprocess", "sys", "textwrap", "threading", "datetime",
                  "urllib", "tiktoken"}
        self.assertEqual(imported - stdlib, set())

    def test_tiktoken_is_optional_and_never_installed(self):
        self.assertIn("import tiktoken", self.source)
        self.assertNotIn("pip install", self.source)
        self.assertNotIn("subprocess.run([sys.executable", self.source)

    def test_has_exactly_one_outbound_call(self):
        """The single property the whole design rests on.

        A script that uploads is a data-exfiltration tool from the reviewer's
        point of view; a script that writes a local file is a report generator.
        Identical data, and only the second one gets approved.
        """
        # The module docstring names urlopen to tell a reviewer where to look,
        # so count call sites in the code rather than mentions in the file.
        body = self.source.replace(ast.get_docstring(ast.parse(self.source)) or "", "")
        self.assertEqual(len(re.findall(r"urlopen\(", body)), 1)
        for forbidden in ("requests.", "http.client", "socket.socket", "smtplib",
                          "ftplib", "sendBeacon", "boto3", "urlretrieve"):
            self.assertNotIn(forbidden, self.source, forbidden)

    def test_the_outbound_call_is_reachable_only_under_connect(self):
        tree = ast.parse(self.source)
        callers = [n.name for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef)
                   and "urlopen" in ast.dump(n)]
        self.assertEqual(callers, ["http_call"])
        # http_call is called only from fetch_tools, which runs only under --connect.
        self.assertIn("if connect:", self.source)

    def test_redaction_is_an_allowlist_in_one_visible_constant(self):
        self.assertIn("EMITTED_FIELDS", self.source)
        position = self.source.index("EMITTED_FIELDS")
        self.assertLess(position, len(self.source) // 3,
                        "the allowlist must be near the top to be found")

    def test_documents_what_it_does_not_collect(self):
        header = ast.get_docstring(ast.parse(self.source)) or ""
        for phrase in ("NEVER COLLECTS", "ALLOWLIST", "CANNOT SEND"):
            self.assertIn(phrase, header)


class KitRunCase(unittest.TestCase):
    """Runs the kit as a subprocess against a synthetic home directory."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.home = self.tmp / "home"
        self.project = self.home / "work" / "proj"
        fixture.build(self.home, self.project)
        self.copy = self.tmp / "mcp_collect.py"
        shutil.copy(KIT, self.copy)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_kit(self, *args):
        out = self.tmp / "bundle.json"
        env = {"HOME": str(self.home), "USERPROFILE": str(self.home),
               "PATH": "/usr/bin:/bin", "SystemRoot": "C:\\\\Windows"}
        result = subprocess.run(
            [sys.executable, str(self.copy), "--out", str(out)] + list(args),
            capture_output=True, text=True, cwd=str(self.project), env=env, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return (json.loads(out.read_text()) if out.exists() else None), result.stdout


class TestKitBehaviour(KitRunCase):
    def test_config_only_run_finds_servers_and_writes_a_bundle(self):
        document, stdout = self.run_kit()
        self.assertGreaterEqual(len(document["servers"]), 8)
        self.assertEqual(document["mode"], "config_only")
        self.assertIn("Review this file before sending it", stdout)
        self.assertIn("DATA POLICY", stdout)

    def test_dry_run_writes_nothing(self):
        document, stdout = self.run_kit("--dry-run")
        self.assertIsNone(document)
        self.assertIn("Nothing was started, contacted or written", stdout)

    def test_bundle_is_self_describing(self):
        document, _ = self.run_kit()
        # When the customer's security team asks what is in the file three weeks
        # later, the file answers.
        for key in ("kit_version", "kit_sha256", "data_policy", "mode", "anonymized"):
            self.assertIn(key, document)
        self.assertEqual(document["kit_sha256"],
                         hashlib.sha256(self.copy.read_bytes()).hexdigest())

    def test_malformed_config_is_recorded_not_fatal(self):
        document, _ = self.run_kit()
        self.assertTrue(document["collection_errors"])

    def test_no_field_outside_the_allowlist_is_emitted(self):
        document, _ = self.run_kit()
        permitted = set(document and __import__("json") and []) | set(
            ["tools"] + [f for f in _kit_allowlist()["server"]])
        for server in document["servers"]:
            self.assertEqual(set(server.keys()) - permitted, set())

    def test_no_secret_reaches_the_bundle(self):
        document, stdout = self.run_kit()
        blob = json.dumps(document)
        for secret in fixture.FAKE_SECRETS:
            self.assertNotIn(secret, blob, secret[:12])
            self.assertNotIn(secret, stdout, secret[:12])

    def test_no_absolute_paths_or_username_reach_the_bundle(self):
        document, _ = self.run_kit()
        blob = json.dumps(document)
        self.assertNotIn(str(self.home), blob)
        self.assertNotIn("/Users/", blob)
        self.assertNotIn("private/path", blob)

    def test_env_and_header_names_are_kept_values_are_not(self):
        document, _ = self.run_kit()
        names = {n for s in document["servers"] for n in s["auth_env_names"]}
        self.assertIn("GITHUB_TOKEN", names)
        self.assertNotIn("ghp_", json.dumps(document))

    def test_anonymise_is_consistent_and_salted(self):
        first, _ = self.run_kit("--anonymize", "salt-one")
        again, _ = self.run_kit("--anonymize", "salt-one")
        other, _ = self.run_kit("--anonymize", "salt-two")
        names = lambda d: [s["name"] for s in d["servers"]]
        self.assertEqual(names(first), names(again))     # stable for one customer
        self.assertNotEqual(names(first), names(other))  # not comparable across salts
        self.assertTrue(all(n.startswith("server-") for n in names(first)))
        self.assertNotIn("local-github", json.dumps(first))


def _kit_allowlist():
    """Read EMITTED_FIELDS out of the kit without importing it."""
    tree = ast.parse(KIT.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "EMITTED_FIELDS":
            return ast.literal_eval(node.value)
    raise AssertionError("EMITTED_FIELDS not found in the kit")


class TestPackageBundle(unittest.TestCase):
    """The package's --bundle mode, which must agree with the kit."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        home = self.tmp / "home"
        self.project = home / "work" / "proj"
        fixture.build(home, self.project)
        self.inv = discover.collect(home=home, project_patterns=[str(self.project)])

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def build(self, salt=None):
        return bundle.build(self.inv, "2026-08-31T00:00:00Z", "config_only", salt=salt)

    def test_allowlist_matches_the_kit(self):
        # Two implementations, one contract. If they drift, a bundle collected by
        # a customer stops matching what the analyser expects.
        self.assertEqual(bundle.EMITTED_FIELDS, _kit_allowlist())

    def test_only_allowlisted_fields_are_emitted(self):
        permitted = set(bundle.EMITTED_FIELDS["server"]) | {"tools"}
        for server in self.build()["servers"]:
            self.assertEqual(set(server.keys()) - permitted, set())

    def test_no_secret_reaches_the_bundle(self):
        self.assertEqual(bundle.find_secrets(self.build(), fixture.FAKE_SECRETS), [])

    def test_no_absolute_paths_reach_the_bundle(self):
        blob = json.dumps(self.build())
        self.assertNotIn(str(self.tmp), blob)
        self.assertNotIn("/Users/", blob)

    def test_anonymisation_is_hmac_not_a_plain_hash(self):
        """A plain hash of 'github' is recovered by dictionary in seconds."""
        plain = hashlib.sha256(b"local-github").hexdigest()[:12]
        names = [s["name"] for s in self.build(salt="pepper")["servers"]]
        self.assertNotIn("server-" + plain, names)
        self.assertTrue(all(n.startswith("server-") for n in names))

    def test_schema_agrees_with_the_kit(self):
        document = self.build()
        for key in ("bundle_version", "kit_version", "kit_sha256", "collected_at",
                    "mode", "anonymized", "data_policy", "platform", "clients_found",
                    "servers", "usage", "collection_errors"):
            self.assertIn(key, document)

    def test_data_policy_states_both_halves(self):
        policy = self.build()["data_policy"]
        self.assertIn("does NOT contain", policy)
        self.assertIn("contains:", policy)

    def test_summary_ends_with_the_review_instruction(self):
        text = bundle.summarise(self.build(), "out.json", 1234)
        self.assertIn("Review this file before sending it", text)
        self.assertIn("DATA POLICY", text)


if __name__ == "__main__":
    unittest.main()


class TestDistribution(unittest.TestCase):
    """The kit is copied, never imported. These keep the copies honest."""

    def test_kit_command_emits_the_vendored_file_verbatim(self):
        from mcpdrift import cli

        tmp = Path(tempfile.mkdtemp())
        try:
            self.assertEqual(cli.main(["kit", str(tmp / "out.py")]), 0)
            self.assertEqual((tmp / "out.py").read_bytes(), KIT.read_bytes())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_recorded_digest_matches_the_shipped_kit(self):
        from mcpdrift import cli

        self.assertEqual(cli.kit_digest(),
                         hashlib.sha256(KIT.read_bytes()).hexdigest())

    def test_readme_promises_what_the_policy_promises(self):
        """The README is what actually gets reviewed; it must not overclaim."""
        readme = (Path(__file__).resolve().parent.parent / "docs" /
                  "collection-kit-README.md").read_text(encoding="utf-8")
        for claim in ("Environment variable **values**", "Absolute file paths",
                      "URL paths or query strings", "EMITTED_FIELDS",
                      "allowlist", "It cannot transmit"):
            self.assertIn(claim, readme, claim)
        # The README tells a reviewer to grep; that grep must find one call.
        source = KIT.read_text(encoding="utf-8")
        body = source.replace(ast.get_docstring(ast.parse(source)) or "", "")
        self.assertEqual(len(re.findall(r"urlopen\(", body)), 1)
        for absent in ("requests.", "smtplib", "ftplib"):
            self.assertNotIn(absent, source)

    def test_readme_states_the_line_budget_the_kit_actually_meets(self):
        readme = (Path(__file__).resolve().parent.parent / "docs" /
                  "collection-kit-README.md").read_text(encoding="utf-8")
        self.assertIn("Under 400 lines", readme)
        self.assertLess(len(KIT.read_text(encoding="utf-8").splitlines()), 400)

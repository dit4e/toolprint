"""The two-run test.

Spec section 16 makes this the gate for everything downstream: unstable
serialisation silently corrupts hashing, drift and every comparison built on it.
It arrives here in M0 rather than M2 because retrofitting determinism onto code
that never had it is far harder than keeping it.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from mcpdrift import discover
from mcpdrift.render import jsonout, text
from tests.fixtures import build as fixture


class TestTwoRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.home = self.tmp / "home"
        self.project = self.home / "work" / "proj"
        fixture.build(self.home, self.project)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def scan(self):
        return discover.collect(home=self.home, project_patterns=[str(self.project)])

    def test_json_output_is_byte_identical_across_runs(self):
        first = json.dumps(jsonout.inventory_dict(self.scan()), indent=2)
        second = json.dumps(jsonout.inventory_dict(self.scan()), indent=2)
        self.assertEqual(first, second)

    def test_text_output_is_byte_identical_across_runs(self):
        self.assertEqual(text.render(self.scan()), text.render(self.scan()))

    def test_server_order_is_total_and_stable(self):
        keys = [s.key for s in self.scan().servers]
        self.assertEqual(keys, sorted(keys, key=lambda k: k))
        self.assertEqual(len(keys), len(set(keys)), "server keys must be unique")

    def test_scoped_lists_are_sorted(self):
        for server in self.scan().servers:
            self.assertEqual(server.env_names, sorted(server.env_names))
            self.assertEqual(server.header_names, sorted(server.header_names))


if __name__ == "__main__":
    unittest.main()


class TestVolatileDetailScrubbing(unittest.TestCase):
    """Server stderr carries timestamps and pids that differ every run.

    Found by the two-run test against a real npm-based server whose stderr names
    a timestamped log file. Unscrubbed, it would read as permanent drift in M5.
    """

    def detail(self, raw):
        from mcpdrift.model import Server

        server = Server(name="x", client="c", scope="user", scope_detail=None, source_path="/p")
        server.fetch_detail = raw
        return server.safe_detail

    def test_npm_log_timestamp_is_stable(self):
        template = "npm error log at /Users/x/.npm/_logs/{}-debug-0.log"
        first = self.detail(template.format("2026-09-01T02_14_49_622Z"))
        second = self.detail(template.format("2026-09-01T02_14_58_045Z"))
        self.assertEqual(first, second)
        self.assertIn("<timestamp>", first)

    def test_pid_and_temp_dir_are_stable(self):
        self.assertEqual(self.detail("crash pid 4821"), self.detail("crash pid 991"))
        self.assertEqual(
            self.detail("wrote /var/folders/aa/bbb/T/x1"),
            self.detail("wrote /var/folders/cc/ddd/T/x2"),
        )

    def test_home_directory_is_masked(self):
        import os

        home = os.path.expanduser("~")
        self.assertNotIn(home, self.detail("failed reading {}/secrets".format(home)) or "")

    def test_substantive_text_survives(self):
        self.assertIn("command not found", self.detail("command not found: npx") or "")

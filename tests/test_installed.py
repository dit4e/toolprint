"""Reading what the package manager has on disk.

A server's self-reported version is a claim. The package manager's cache is the
second opinion, and reading it stays offline - it is the local filesystem, not a
registry.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from toolprint import installed


class TestPackageFromArgs(unittest.TestCase):
    def test_strips_the_version_from_a_spec(self):
        for args, expected in [
            (["-y", "@scope/pkg@1.2.3"], "@scope/pkg"),
            (["-y", "@scope/pkg"], "@scope/pkg"),
            (["-y", "pkg@latest"], "pkg"),
            (["pkg==1.2.3"], "pkg"),
            (["pkg>=2"], "pkg"),
            (["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
             "@modelcontextprotocol/server-filesystem"),
        ]:
            self.assertEqual(installed.package_from_args("npx", args), expected, args)

    def test_flags_are_skipped_and_the_first_real_argument_wins(self):
        self.assertEqual(
            installed.package_from_args("npx", ["-y", "--silent", "pkg", "sub", "cmd"]), "pkg")

    def test_no_command_means_no_package(self):
        self.assertIsNone(installed.package_from_args(None, ["pkg"]))


class TestDiskLookup(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._npx, self._uv = installed.NPX_ROOTS, installed.UV_ROOTS
        installed.NPX_ROOTS = (str(self.tmp / "npx"),)
        installed.UV_ROOTS = (str(self.tmp / "uv"),)

    def tearDown(self):
        installed.NPX_ROOTS, installed.UV_ROOTS = self._npx, self._uv
        shutil.rmtree(self.tmp, ignore_errors=True)

    def npx_entry(self, folder, spec, package, version):
        # npm keys the directory by a hash of the spec and records the spec in a
        # package.json at the top; the real version is under node_modules.
        base = self.tmp / "npx" / folder
        (base / "node_modules" / package).mkdir(parents=True)
        (base / "package.json").write_text(json.dumps({"dependencies": {spec: "^1"}}))
        (base / "node_modules" / package / "package.json").write_text(
            json.dumps({"name": package, "version": version}))

    def uv_entry(self, folder, dist, version):
        base = self.tmp / "uv" / folder / "{}-{}.dist-info".format(dist, version)
        base.mkdir(parents=True)

    def test_reads_the_installed_npm_version(self):
        self.npx_entry("aaa", "@scope/pkg", "@scope/pkg", "2.0.2")
        self.assertEqual(installed.versions_on_disk("npx", ["-y", "@scope/pkg"]), ["2.0.2"])

    def test_reports_every_cached_version_rather_than_guessing(self):
        """Two entries mean the cache is ambiguous, and that is worth saying."""
        self.npx_entry("aaa", "pkg", "pkg", "2.0.2")
        self.npx_entry("bbb", "pkg", "pkg", "1.2.1")
        self.assertEqual(sorted(installed.versions_on_disk("npx", ["-y", "pkg"])),
                         ["1.2.1", "2.0.2"])

    def test_a_package_never_run_here_is_absent_not_an_error(self):
        self.assertEqual(installed.versions_on_disk("npx", ["-y", "never-run"]), [])

    def test_reads_uv_dist_info_with_a_normalised_name(self):
        # uv writes mcp-server-time as mcp_server_time-2026.8.18.dist-info
        self.uv_entry("xyz", "mcp_server_time", "2026.8.18")
        self.assertEqual(installed.versions_on_disk("uvx", ["mcp-server-time"]), ["2026.8.18"])

    def test_a_different_distribution_is_not_matched(self):
        self.uv_entry("xyz", "mcp", "1.29.1")          # the SDK, not the server
        self.assertEqual(installed.versions_on_disk("uvx", ["mcp-server-time"]), [])

    def test_unknown_runners_are_left_alone(self):
        self.npx_entry("aaa", "pkg", "pkg", "2.0.2")
        self.assertEqual(installed.versions_on_disk("docker", ["run", "pkg"]), [])

    def test_a_full_path_to_npx_still_resolves(self):
        self.npx_entry("aaa", "pkg", "pkg", "2.0.2")
        self.assertEqual(installed.versions_on_disk("/opt/homebrew/bin/npx", ["-y", "pkg"]),
                         ["2.0.2"])

    def test_a_corrupt_cache_entry_is_skipped_not_fatal(self):
        base = self.tmp / "npx" / "broken"
        base.mkdir(parents=True)
        (base / "package.json").write_text("{not json")
        self.npx_entry("good", "pkg", "pkg", "2.0.2")
        self.assertEqual(installed.versions_on_disk("npx", ["-y", "pkg"]), ["2.0.2"])


if __name__ == "__main__":
    unittest.main()

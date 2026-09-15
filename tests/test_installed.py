"""Reading what the package manager has on disk.

A server's self-reported version is a claim. The package manager's cache is the
second opinion, and reading it stays offline - it is the local filesystem, not a
registry.
"""

from __future__ import annotations

import json
import os
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


class TestRelocatedCaches(unittest.TestCase):
    """CI moves these caches, and a hardcoded path finds nothing there.

    A GitHub runner with astral-sh/setup-uv exports UV_CACHE_DIR into a temp
    path. The first run of this feature on a runner reported no cached copy for
    all 36 servers, because it was looking under ~/.cache/uv.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._env = {k: os.environ.get(k) for k in
                     ("npm_config_cache", "NPM_CONFIG_CACHE", "UV_CACHE_DIR", "XDG_CACHE_HOME",
                      "HOME")}
        for key in self._env:
            os.environ.pop(key, None)
        # An empty HOME. Without it these tests pass or fail depending on what
        # the developer's own ~/.cache/uv and ~/.npm happen to hold - which is
        # how reading the union of every cache location went unnoticed.
        self.home = self.tmp / "home"
        self.home.mkdir()
        os.environ["HOME"] = str(self.home)

    def tearDown(self):
        for key, value in self._env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_npm_cache_environment_variable_is_honoured(self):
        base = self.tmp / "relocated" / "_npx" / "aaa"
        (base / "node_modules" / "pkg").mkdir(parents=True)
        (base / "package.json").write_text(json.dumps({"dependencies": {"pkg": "^1"}}))
        (base / "node_modules" / "pkg" / "package.json").write_text(
            json.dumps({"version": "9.9.9"}))
        os.environ["npm_config_cache"] = str(self.tmp / "relocated")
        self.assertEqual(installed.versions_on_disk("npx", ["-y", "pkg"]), ["9.9.9"])

    def test_uv_cache_environment_variable_is_honoured(self):
        (self.tmp / "uvrel" / "archive-v0" / "zzz" / "pkg_name-4.5.6.dist-info").mkdir(parents=True)
        os.environ["UV_CACHE_DIR"] = str(self.tmp / "uvrel")
        self.assertEqual(installed.versions_on_disk("uvx", ["pkg-name"]), ["4.5.6"])

    def test_a_configured_uv_cache_is_the_only_one_read(self):
        """uv uses UV_CACHE_DIR exclusively when it is set. A copy in the
        default location is not what uv would run, so it must not be listed."""
        (self.home / ".cache" / "uv" / "archive-v0" / "old" / "pkg_name-1.0.0.dist-info").mkdir(parents=True)
        (self.tmp / "ci" / "archive-v0" / "new" / "pkg_name-2.0.0.dist-info").mkdir(parents=True)
        os.environ["UV_CACHE_DIR"] = str(self.tmp / "ci")
        self.assertEqual(installed.versions_on_disk("uvx", ["pkg-name"]), ["2.0.0"])

    def test_uv_honours_xdg_when_no_cache_dir_is_set(self):
        (self.home / ".cache" / "uv" / "archive-v0" / "old" / "pkg_name-1.0.0.dist-info").mkdir(parents=True)
        (self.tmp / "xdg" / "uv" / "archive-v0" / "x" / "pkg_name-3.0.0.dist-info").mkdir(parents=True)
        os.environ["XDG_CACHE_HOME"] = str(self.tmp / "xdg")
        self.assertEqual(installed.versions_on_disk("uvx", ["pkg-name"]), ["3.0.0"])

    def test_npm_ignores_xdg(self):
        """Verified against npm 10.8: XDG_CACHE_HOME does not move its cache.
        An earlier version searched $XDG_CACHE_HOME/npm regardless."""
        base = self.home / ".npm" / "_npx" / "aaa"
        (base / "node_modules" / "pkg").mkdir(parents=True)
        (base / "package.json").write_text(json.dumps({"dependencies": {"pkg": "^1"}}))
        (base / "node_modules" / "pkg" / "package.json").write_text(json.dumps({"version": "5.0.0"}))
        decoy = self.tmp / "xdg" / "npm" / "_npx" / "bbb"
        (decoy / "node_modules" / "pkg").mkdir(parents=True)
        (decoy / "package.json").write_text(json.dumps({"dependencies": {"pkg": "^1"}}))
        (decoy / "node_modules" / "pkg" / "package.json").write_text(json.dumps({"version": "9.0.0"}))
        os.environ["XDG_CACHE_HOME"] = str(self.tmp / "xdg")
        self.assertEqual(installed.versions_on_disk("npx", ["-y", "pkg"]), ["5.0.0"])

    def test_a_missing_relocated_directory_is_not_fatal(self):
        os.environ["UV_CACHE_DIR"] = str(self.tmp / "does-not-exist")
        self.assertEqual(installed.versions_on_disk("uvx", ["pkg"]), [])


class TestReadAgainAfterTheServerRuns(unittest.TestCase):
    """Discovery reads the cache before anything has started.

    On a fresh CI runner the package is not there yet: astral-sh/setup-uv prunes
    unpacked wheels out of the cache it restores. Every uvx server on the public
    collector came back with no installed version, including four reporting
    their SDK's 1.30.0 while running 2026.8.18 - the exact mismatch HYG-006
    exists to catch.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._env = {k: os.environ.get(k) for k in ("UV_CACHE_DIR", "XDG_CACHE_HOME", "HOME")}
        os.environ["HOME"] = str(self.tmp / "home")
        os.environ["UV_CACHE_DIR"] = str(self.tmp / "uv")
        os.environ.pop("XDG_CACHE_HOME", None)

    def tearDown(self):
        for key, value in self._env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(self.tmp, ignore_errors=True)

    def server(self, scope="user"):
        from toolprint.model import Server
        return Server(name="mcp-time", client="c", scope=scope, scope_detail=None,
                      source_path="/p", transport="stdio", command="uvx",
                      args=["mcp-server-time"])

    def run_execute(self, servers, lands):
        """Run connect.execute with a fetch that unpacks the wheel, as uvx does."""
        from toolprint import connect, context, protocol
        from toolprint.model import Inventory

        def fake_fetch(server, **kw):
            if lands:
                (self.tmp / "uv" / "archive-v0" / "e" / "mcp_server_time-2026.8.18.dist-info").mkdir(
                    parents=True, exist_ok=True)
            server.fetch_status, server.tools = "ok", [{"name": "get_current_time"}]
            server.server_version = "1.30.0"

        original = protocol.fetch
        protocol.fetch = fake_fetch
        try:
            inventory = Inventory(servers=servers)
            contexts = context.resolve_all(inventory)
            connect.execute(connect.plan(contexts), contexts)
        finally:
            protocol.fetch = original

    def test_the_version_is_found_once_the_server_has_run(self):
        server = self.server()
        self.assertEqual(server.installed_versions, [])       # as discovery found it
        self.run_execute([server], lands=True)
        self.assertEqual(server.installed_versions, ["2026.8.18"])

    def test_nothing_found_after_a_run_keeps_what_discovery_found(self):
        server = self.server()
        server.installed_versions = ["2025.1.1"]
        self.run_execute([server], lands=False)
        self.assertEqual(server.installed_versions, ["2025.1.1"])

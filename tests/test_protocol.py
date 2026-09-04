"""Protocol negotiation, driven by a scripted transport so tests stay offline.

Every scenario here was observed against a real server during M1.
"""

from __future__ import annotations

import unittest
from typing import Any, Dict, List

from toolprint import protocol
from toolprint.transport import TransportError


class FakeTransport:
    """Replays scripted responses and records what was asked."""

    def __init__(self, responses: List[Any]):
        self.responses = list(responses)
        self.calls: List[Dict[str, Any]] = []
        self.notifications: List[str] = []
        self.protocol_version = protocol.PROTOCOL_VERSION
        self.closed = False

    def request(self, method, params, timeout=15.0):
        self.calls.append({"method": method, "params": params,
                           "header_version": self.protocol_version})
        if not self.responses:
            raise TransportError("error", "no scripted response")
        nxt = self.responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    def notify(self, method, params):
        self.notifications.append(method)

    def close(self):
        self.closed = True


def discover_result(versions):
    return {"jsonrpc": "2.0", "id": 1, "result": {"supportedVersions": versions}}


def unsupported_version(supported):
    return {"jsonrpc": "2.0", "id": 1, "error": {
        "code": -32022,
        "message": "Unsupported protocol version",
        "data": {"requested": protocol.PROTOCOL_VERSION, "supported": supported}}}


class TestEra(unittest.TestCase):
    def test_era_is_a_property_of_the_version(self):
        self.assertEqual(protocol.era_for("2026-07-28"), "modern")
        self.assertEqual(protocol.era_for("2027-03-01"), "modern")  # future revisions
        self.assertEqual(protocol.era_for("2025-11-25"), "legacy")
        self.assertEqual(protocol.era_for("2024-11-05"), "legacy")


class TestNegotiate(unittest.TestCase):
    def test_modern_server(self):
        t = FakeTransport([discover_result(["2026-07-28"])])
        self.assertEqual(protocol.negotiate(t, 1), ("modern", "2026-07-28"))

    def test_modern_error_code_but_only_legacy_versions_supported(self):
        # Observed against mcp.sanity.io: a correct -32022 whose `supported` list
        # is entirely pre-stateless. Treating "modern error" as "modern era" sends
        # tools/list with no handshake and the server rejects it.
        t = FakeTransport([unsupported_version(["2025-11-25", "2025-06-18", "2024-11-05"])])
        era, version = protocol.negotiate(t, 1)
        self.assertEqual(era, "legacy")
        self.assertEqual(version, "2025-11-25")

    def test_modern_error_code_with_a_modern_version_stays_modern(self):
        t = FakeTransport([unsupported_version(["2026-07-28"])])
        self.assertEqual(protocol.negotiate(t, 1), ("modern", "2026-07-28"))

    def test_unrecognised_jsonrpc_error_falls_back_to_legacy(self):
        # The spec forbids keying the fallback to one specific code.
        for code in (-32601, -32602, -32000):
            t = FakeTransport([{"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": "?"}}])
            self.assertEqual(protocol.negotiate(t, 1)[0], "legacy", code)

    def test_non_jsonrpc_response_is_not_mcp(self):
        # Observed against mcp.vercel.com, which answers with a redirect envelope.
        t = FakeTransport([{"redirect": "/somewhere", "status": "308"}])
        with self.assertRaises(TransportError) as caught:
            protocol.negotiate(t, 1)
        self.assertEqual(caught.exception.status, "not_mcp")

    def test_picks_newest_supported_when_ours_is_absent(self):
        t = FakeTransport([discover_result(["2025-03-26", "2025-11-25", "2025-06-18"])])
        self.assertEqual(protocol.negotiate(t, 1)[1], "2025-11-25")


class TestLegacyHandshake(unittest.TestCase):
    def test_header_version_tracks_the_body_version(self):
        # Regression: the header stayed pinned at the newest version while the
        # body asked for an older one, and servers validate the header.
        t = FakeTransport([
            unsupported_version(["2025-11-25"]),
            {"jsonrpc": "2.0", "id": 2, "result": {"protocolVersion": "2025-11-25"}},
        ])
        protocol.initialize_legacy(t, "2025-11-25", 1)
        init_call = [c for c in t.calls if c["method"] == "initialize"][0]
        self.assertEqual(init_call["header_version"], "2025-11-25")
        self.assertEqual(init_call["params"]["protocolVersion"], "2025-11-25")

    def test_sends_initialized_notification(self):
        t = FakeTransport([{"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-11-25"}}])
        protocol.initialize_legacy(t, "2025-11-25", 1)
        self.assertEqual(t.notifications, ["notifications/initialized"])

    def test_no_duplicate_version_attempts(self):
        t = FakeTransport([{"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "no"}}] * 6)
        with self.assertRaises(TransportError) as caught:
            protocol.initialize_legacy(t, "2025-11-25", 1)
        methods = [c["params"]["protocolVersion"] for c in t.calls]
        self.assertEqual(len(methods), len(set(methods)), "a version was retried")
        self.assertIn("2025-11-25", str(caught.exception))


class TestListTools(unittest.TestCase):
    def test_follows_pagination(self):
        t = FakeTransport([
            {"result": {"tools": [{"name": "a"}], "nextCursor": "p2"}},
            {"result": {"tools": [{"name": "b"}], "nextCursor": "p3"}},
            {"result": {"tools": [{"name": "c"}]}},
        ])
        tools = protocol.list_tools(t, "modern", protocol.PROTOCOL_VERSION, 1)
        self.assertEqual([x["name"] for x in tools], ["a", "b", "c"])
        self.assertEqual(t.calls[1]["params"]["cursor"], "p2")

    def test_breaks_on_looping_cursor(self):
        t = FakeTransport([{"result": {"tools": [{"name": "a"}], "nextCursor": "same"}}] * 10)
        tools = protocol.list_tools(t, "modern", protocol.PROTOCOL_VERSION, 1)
        self.assertEqual(len(tools), 2)  # first page, then the repeat is detected

    def test_modern_sends_meta_legacy_does_not(self):
        t = FakeTransport([{"result": {"tools": []}}])
        protocol.list_tools(t, "modern", protocol.PROTOCOL_VERSION, 1)
        self.assertIn("_meta", t.calls[0]["params"])
        t = FakeTransport([{"result": {"tools": []}}])
        protocol.list_tools(t, "legacy", "2025-11-25", 1)
        self.assertNotIn("_meta", t.calls[0]["params"])

    def test_error_result_raises_transport_error(self):
        t = FakeTransport([{"error": {"code": -32602, "message": "bad"}}])
        with self.assertRaises(TransportError):
            protocol.list_tools(t, "modern", protocol.PROTOCOL_VERSION, 1)


if __name__ == "__main__":
    unittest.main()


class TestStartupTimeout(unittest.TestCase):
    """First contact with a stdio server is a different operation from the rest.

    The package manager may still be downloading the server before anything can
    start. Charging both to one timeout reports servers as unreachable when they
    were merely slow to arrive - observed on a CI runner where 23 of 36 reported
    "timed out after 60s" while every one of them worked locally.
    """

    def server(self, transport="stdio"):
        from toolprint.model import Server

        return Server(name="s", client="c", scope="user", scope_detail=None,
                      source_path="/p", transport=transport,
                      command="npx" if transport == "stdio" else None,
                      url=None if transport == "stdio" else "https://x.example/mcp")

    def timeouts_used(self, srv, **kw):
        """Record the timeout given to each request."""
        seen = []
        fake = FakeTransport([
            discover_result(["2026-07-28"]),
            {"result": {"tools": []}},
        ])
        original = fake.request

        def spy(method, params, timeout=15.0):
            seen.append((method, timeout))
            return original(method, params, timeout)

        fake.request = spy
        protocol.build_transport = lambda *a, **k: fake      # noqa: patched below
        try:
            protocol.fetch(srv, **kw)
        finally:
            pass
        return seen

    def setUp(self):
        self._build = protocol.build_transport

    def tearDown(self):
        protocol.build_transport = self._build

    def test_first_stdio_request_gets_the_startup_allowance(self):
        seen = self.timeouts_used(self.server("stdio"), timeout=15.0, startup_timeout=90.0)
        self.assertEqual(seen[0][0], "server/discover")
        self.assertEqual(seen[0][1], 90.0)          # download plus boot plus reply
        self.assertEqual(seen[1][1], 15.0)          # just a reply

    def test_remote_transports_have_nothing_to_download(self):
        seen = self.timeouts_used(self.server("http"), timeout=15.0, startup_timeout=90.0)
        self.assertEqual(seen[0][1], 15.0)

    def test_a_larger_timeout_is_never_reduced(self):
        seen = self.timeouts_used(self.server("stdio"), timeout=120.0, startup_timeout=90.0)
        self.assertEqual(seen[0][1], 120.0)

    def test_absent_startup_timeout_changes_nothing(self):
        seen = self.timeouts_used(self.server("stdio"), timeout=15.0)
        self.assertEqual(seen[0][1], 15.0)

"""The HTML viewer: self-containment, injection safety, and print readiness.

The viewer's whole value rests on one claim - that it cannot transmit the report
it displays - so that claim is asserted here rather than left to a manual check.
"""

from __future__ import annotations

import json
import re
import unittest

from mcpdrift import demo
from mcpdrift.render import html

# Anything that could reach the network or execute markup from the report.
NETWORK_CALLS = re.compile(
    r"\b(fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts|"
    r"navigator\.sendBeacon)\s*\(")
EXTERNAL_URL = re.compile(r"""(?:src|href)\s*=\s*["']\s*(?:https?:)?//""")
MARKUP_SINKS = re.compile(r"\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write)\s*[=(]")


class TestTemplate(unittest.TestCase):
    def setUp(self):
        self.template = html.read_template()

    def test_has_the_data_placeholder(self):
        self.assertIn(html.PLACEHOLDER, self.template)

    def test_no_external_resources(self):
        self.assertEqual(EXTERNAL_URL.findall(self.template), [])
        self.assertNotIn("@import", self.template)
        self.assertNotIn("cdn.", self.template)
        self.assertNotIn("fonts.googleapis", self.template)

    def test_no_network_primitives(self):
        self.assertEqual(NETWORK_CALLS.findall(self.template), [])

    def test_no_markup_sinks(self):
        """Tool descriptions come from the servers being assessed.

        A report that executed markup supplied by a server it was reporting on
        would be a fine joke at our expense.
        """
        self.assertEqual(MARKUP_SINKS.findall(self.template), [])

    def test_csp_blocks_connections(self):
        self.assertIn("Content-Security-Policy", self.template)
        for directive in ("default-src 'none'", "connect-src 'none'",
                          "form-action 'none'", "font-src 'none'"):
            self.assertIn(directive, self.template)

    def test_print_rules_exist(self):
        self.assertIn("@media print", self.template)
        self.assertIn("@page", self.template)
        self.assertIn("break-inside: avoid", self.template)

    def test_renders_the_narrative_field(self):
        # This is how one renderer serves both the free report and a paid one.
        self.assertIn("narrative", self.template)


class TestEmbedding(unittest.TestCase):
    def payload(self, document):
        page = html.embed(document)
        match = re.search(
            r'<script type="application/json" id="findings-data">(.*?)</script>',
            page, re.S)
        self.assertIsNotNone(match, "data block missing from output")
        return match.group(1)

    def test_round_trips(self):
        document = demo.document()
        self.assertEqual(json.loads(self.payload(document))["summary"],
                         json.loads(json.dumps(document))["summary"])

    def test_placeholder_is_consumed(self):
        self.assertNotIn(html.PLACEHOLDER, html.embed(demo.document()))

    def test_script_close_in_data_cannot_break_out(self):
        """The payload may carry the *text* of an attack; it may not carry a tag.

        What matters is that no `<` survives into the data block, so no element
        can be formed. Asserting the attack text is absent would test the wrong
        property - it is present, inertly, as escaped JSON, and must be, because
        the reader needs to see what the server actually said.
        """
        attack = "</script><script>alert(1)</script> and </SCRIPT > too"
        hostile = demo.document()
        hostile["findings"][0]["detail"] = attack
        page = html.embed(hostile)

        # Exactly the two script tags the template itself carries.
        self.assertEqual(len(re.findall(r"<script", page, re.I)), 2)
        payload = self.payload(hostile)
        self.assertNotIn("<", payload)
        self.assertNotIn(">", payload)
        self.assertIn("\\u003c", payload)
        # The original text survives intact for the reader.
        self.assertEqual(json.loads(payload)["findings"][0]["detail"], attack)

    def test_line_separators_are_escaped(self):
        # U+2028 and U+2029 are valid inside a JSON string but terminate a
        # JavaScript line, which would break the block they are embedded in.
        original = "before" + chr(0x2028) + "middle" + chr(0x2029) + "end"
        hostile = demo.document()
        hostile["findings"][0]["detail"] = original
        payload = self.payload(hostile)
        self.assertNotIn(chr(0x2028), payload)
        self.assertNotIn(chr(0x2029), payload)
        self.assertEqual(json.loads(payload)["findings"][0]["detail"], original)


    def test_embedded_page_stays_self_contained(self):
        page = html.embed(demo.document())
        self.assertEqual(EXTERNAL_URL.findall(page), [])
        self.assertEqual(NETWORK_CALLS.findall(page), [])
        self.assertEqual(MARKUP_SINKS.findall(page), [])

    def test_missing_placeholder_is_an_error_not_a_silent_pass(self):
        with self.assertRaises(ValueError):
            html.embed(demo.document(), template="<html>no placeholder</html>")


class TestDemo(unittest.TestCase):
    def test_exercises_every_severity(self):
        severities = {f["severity"] for f in demo.document()["findings"]}
        self.assertEqual(severities, {"critical", "high", "medium", "low", "info"})

    def test_exercises_sections_the_free_tool_cannot_yet_produce(self):
        document = demo.document()
        self.assertTrue(document["drift"])       # M5
        self.assertTrue(document["benchmark"])   # M6
        self.assertTrue(any(f["narrative"] for f in document["findings"]))

    def test_context_lists_its_servers_so_the_table_renders(self):
        document = demo.document()
        keys = {s["key"] for s in document["servers"]}
        listed = set(document["contexts"][0]["servers"])
        self.assertTrue(listed)
        self.assertTrue(listed <= keys, "context names servers that do not exist")

    def test_is_obviously_synthetic(self):
        self.assertIn("demo", demo.document()["generator"])


if __name__ == "__main__":
    unittest.main()

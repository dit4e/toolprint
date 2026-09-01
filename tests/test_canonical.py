"""Canonicalisation and hashing.

The rule this whole module protects: normalise structure, never content. If any
test here starts failing because someone added Unicode normalisation to make
hashes "cleaner", the fix is to remove that, not to change the test.
"""

from __future__ import annotations

import unittest

from toolprint import canonical as c


class TestJCS(unittest.TestCase):
    def test_keys_are_sorted(self):
        self.assertEqual(c.jcs({"b": 1, "a": 2}), '{"a":2,"b":1}')

    def test_no_whitespace(self):
        self.assertEqual(c.jcs([1, {"a": "b"}]), '[1,{"a":"b"}]')

    def test_literals_and_numbers(self):
        self.assertEqual(c.jcs({"t": True, "f": False, "n": None}), '{"f":false,"n":null,"t":true}')
        self.assertEqual(c.jcs(1.0), "1")       # integral floats lose the .0
        self.assertEqual(c.jcs(1.5), "1.5")
        self.assertEqual(c.jcs(-0.0), "0")

    def test_control_characters_escaped_but_text_is_not_altered(self):
        self.assertEqual(c.jcs("a\nb"), '"a\\nb"')
        # Zero-width and bidi characters pass through literally. Escaping or
        # stripping them here would hide the attack this tool exists to surface.
        self.assertIn("​", c.jcs("a​b"))
        self.assertIn("‮", c.jcs("a‮b"))

    def test_key_order_uses_utf16_code_units(self):
        # An astral character is two surrogate code units, which sort BELOW
        # U+E000-U+FFFF. Sorting by code point would order these the other way
        # and disagree with every conforming implementation.
        out = c.jcs({"\U0001f600": 1, "": 2})
        self.assertLess(out.index("\U0001f600"), out.index(""))

    def test_rejects_non_finite_numbers(self):
        with self.assertRaises(ValueError):
            c.jcs(float("nan"))


class TestNeverNormaliseContent(unittest.TestCase):
    """The single most important property in this file."""

    def test_homoglyph_changes_the_hash(self):
        latin = c.hash_tool({"name": "pay", "description": "transfer funds"})
        cyril = c.hash_tool({"name": "pay", "description": "transfеr funds"})
        self.assertNotEqual(latin["description_hash"], cyril["description_hash"])

    def test_zero_width_insertion_changes_the_hash(self):
        plain = c.hash_tool({"name": "x", "description": "delete"})
        split = c.hash_tool({"name": "x", "description": "de​lete"})
        self.assertNotEqual(plain["description_hash"], split["description_hash"])

    def test_compatibility_equivalents_are_not_folded(self):
        # NFKC would collapse these to "fi"; that must not happen.
        a = c.hash_tool({"name": "x", "description": "ﬁle"})
        b = c.hash_tool({"name": "x", "description": "file"})
        self.assertNotEqual(a["description_hash"], b["description_hash"])


class TestStructuralNormalisation(unittest.TestCase):
    def test_transport_noise_is_stripped(self):
        # ttlMs and cacheScope became REQUIRED on tools/list in 2026-07-28, so
        # without this every scan would report drift.
        self.assertEqual(
            c.strip_noise({"a": 1, "ttlMs": 5, "cacheScope": "public", "_meta": {},
                           "io.modelcontextprotocol/serverInfo": {}}),
            {"a": 1})

    def test_noise_is_stripped_at_every_depth(self):
        self.assertEqual(c.strip_noise({"o": {"p": [{"ttlMs": 1, "k": 2}]}}),
                         {"o": {"p": [{"k": 2}]}})

    def test_nulls_are_dropped(self):
        self.assertEqual(c.drop_nulls({"a": 1, "b": None}), {"a": 1})

    def test_unordered_arrays_are_sorted(self):
        out = c.sort_unordered({"required": ["b", "a"], "enum": [3, 1, 2]})
        self.assertEqual(out["required"], ["a", "b"])
        self.assertEqual(out["enum"], [1, 2, 3])

    def test_composition_keywords_are_never_sorted(self):
        """anyOf/oneOf/allOf order decides which error a validator reports."""
        original = [{"z": 1}, {"a": 2}]
        for key in ("anyOf", "oneOf", "allOf"):
            self.assertEqual(c.sort_unordered({key: list(original)})[key], original, key)

    def test_type_as_array_is_sorted_but_type_as_string_survives(self):
        self.assertEqual(c.sort_unordered({"type": ["string", "null"]})["type"],
                         ["null", "string"])
        self.assertEqual(c.sort_unordered({"type": "string"})["type"], "string")


class TestRefResolution(unittest.TestCase):
    """SEP-2106 let schemas use $ref, so the same schema has two spellings."""

    def test_ref_and_inline_hash_identically(self):
        inline = {"type": "object", "properties": {"x": {"type": "string", "minLength": 1}}}
        via_ref = {"type": "object", "properties": {"x": {"$ref": "#/$defs/S"}},
                   "$defs": {"S": {"type": "string", "minLength": 1}}}
        self.assertEqual(c.hash_tool({"name": "t", "inputSchema": inline})["schema_hash"],
                         c.hash_tool({"name": "t", "inputSchema": via_ref})["schema_hash"])

    def test_unused_defs_do_not_change_the_hash(self):
        bare = {"type": "object", "properties": {"x": {"type": "string"}}}
        padded = dict(bare, **{"$defs": {"Unused": {"type": "number"}}})
        self.assertEqual(c.hash_tool({"name": "t", "inputSchema": bare})["schema_hash"],
                         c.hash_tool({"name": "t", "inputSchema": padded})["schema_hash"])

    def test_cycles_are_detected_not_hung(self):
        cyclic = {"$defs": {"Node": {"properties": {"next": {"$ref": "#/$defs/Node"}}}},
                  "properties": {"root": {"$ref": "#/$defs/Node"}}}
        _, status = c.resolve_refs(cyclic)
        self.assertEqual(status, c.CYCLE)

    def test_external_refs_are_never_fetched(self):
        # Following a URL supplied by the server being assessed would be its own
        # vulnerability, and this runs offline.
        _, status = c.resolve_refs({"properties": {"x": {"$ref": "https://evil.example/s.json"}}})
        self.assertEqual(status, c.UNRESOLVED_EXTERNAL)

    def test_resolution_status_is_recorded_on_the_tool(self):
        hashes = c.hash_tool({"name": "t", "inputSchema":
                              {"properties": {"x": {"$ref": "https://x.example/s"}}}})
        self.assertEqual(hashes["schema_resolution"], c.UNRESOLVED_EXTERNAL)


class TestComponentHashes(unittest.TestCase):
    def test_components_are_independent(self):
        base = {"name": "t", "description": "d", "inputSchema": {"type": "object"},
                "annotations": {"readOnlyHint": True}}
        changed_desc = dict(base, description="d2")
        changed_schema = dict(base, inputSchema={"type": "string"})

        a, b, cc = c.hash_tool(base), c.hash_tool(changed_desc), c.hash_tool(changed_schema)
        # The rug-pull signature: description moved, schema did not.
        self.assertNotEqual(a["description_hash"], b["description_hash"])
        self.assertEqual(a["schema_hash"], b["schema_hash"])
        # And the converse.
        self.assertEqual(a["description_hash"], cc["description_hash"])
        self.assertNotEqual(a["schema_hash"], cc["schema_hash"])
        # Composite moves with either.
        self.assertNotEqual(a["composite_hash"], b["composite_hash"])
        self.assertNotEqual(a["composite_hash"], cc["composite_hash"])

    def test_title_is_part_of_the_injection_surface(self):
        a = c.hash_tool({"name": "t", "description": "d"})
        b = c.hash_tool({"name": "t", "description": "d", "title": "Do the thing"})
        self.assertNotEqual(a["description_hash"], b["description_hash"])

    def test_renaming_a_tool_changes_only_the_composite(self):
        a = c.hash_tool({"name": "a", "description": "d"})
        b = c.hash_tool({"name": "b", "description": "d"})
        self.assertEqual(a["description_hash"], b["description_hash"])
        self.assertNotEqual(a["composite_hash"], b["composite_hash"])

    def test_hashing_is_stable_across_calls(self):
        tool = {"name": "t", "description": "d", "inputSchema": {"properties": {"b": {}, "a": {}}}}
        self.assertEqual(c.hash_tool(tool), c.hash_tool(dict(tool)))

    def test_toolset_hash_ignores_tool_order(self):
        one = [{"name": "a", "description": "x"}, {"name": "b", "description": "y"}]
        self.assertEqual(c.hash_server(one)["toolset_hash"],
                         c.hash_server(list(reversed(one)))["toolset_hash"])


if __name__ == "__main__":
    unittest.main()

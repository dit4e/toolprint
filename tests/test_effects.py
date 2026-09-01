"""Effect-class inference.

The annotation cases come from real tool definitions on mcp.sanity.io, including
three that an earlier version of this file accused of mislabelling when they were
correctly annotated.
"""

from __future__ import annotations

import unittest

from toolprint import effects


def classify(name, annotations=None, schema=None):
    tool = {"name": name}
    if annotations is not None:
        tool["annotations"] = annotations
    if schema is not None:
        tool["inputSchema"] = schema
    return effects.classify(tool)


class TestLexical(unittest.TestCase):
    def test_verbs_map_to_classes(self):
        for name, expected in [
            ("list_files", effects.READ), ("get_user", effects.READ),
            ("create_issue", effects.WRITE), ("createIssue", effects.WRITE),
            ("delete_repo", effects.IRREVERSIBLE), ("purge_cache", effects.IRREVERSIBLE),
            ("send_email", effects.EXTERNAL), ("charge_card", effects.EXTERNAL),
        ]:
            self.assertEqual(classify(name)["effect"], expected, name)

    def test_matches_whole_tokens_across_separators(self):
        for name in ("github__issues.create", "issues-create", "IssuesCreate"):
            self.assertEqual(classify(name)["effect"], effects.WRITE, name)

    def test_unknown_verb_defaults_to_read(self):
        self.assertEqual(classify("frobnicate")["effect"], effects.READ)

    def test_highest_class_wins(self):
        self.assertEqual(classify("get_and_delete")["effect"], effects.IRREVERSIBLE)


class TestSchemaHints(unittest.TestCase):
    def test_dangerous_parameter_raises_the_class(self):
        result = classify("cleanup", schema={"properties": {"force": {"type": "boolean"}}})
        self.assertEqual(result["effect"], effects.IRREVERSIBLE)

    def test_ordinary_parameters_do_not(self):
        result = classify("lookup", schema={"properties": {"query": {"type": "string"}}})
        self.assertEqual(result["effect"], effects.READ)


class TestAnnotationFloorAndCeiling(unittest.TestCase):
    """A floor says 'at least this'; a ceiling says 'at most this'.

    Only a ceiling can be contradicted. Conflating the two produced three false
    mislabelling accusations against a correctly-annotated real server.
    """

    def test_read_only_true_is_a_ceiling_and_can_be_contradicted(self):
        # Genuine: the server says read-only, the tool uploads.
        self.assertTrue(classify("dataset_assets_upload", {"readOnlyHint": True})["mislabelled"])
        self.assertTrue(classify("delete_account", {"readOnlyHint": True})["mislabelled"])

    def test_read_only_false_is_a_floor_and_cannot_be_contradicted(self):
        # "Not read-only" is true of a write, an external call and a delete
        # alike. The annotation vocabulary cannot say "external", so inferring
        # external here is not a contradiction.
        for name in ("deploy_schema", "deploy_studio", "publish_documents"):
            result = classify(name, {"readOnlyHint": False, "destructiveHint": False})
            self.assertEqual(result["effect"], effects.EXTERNAL, name)
            self.assertFalse(result["mislabelled"], name)

    def test_destructive_false_is_contradicted_by_an_irreversible_verb(self):
        self.assertTrue(classify("delete_everything", {"destructiveHint": False})["mislabelled"])

    def test_destructive_false_is_not_contradicted_by_external(self):
        self.assertFalse(classify("send_email", {"destructiveHint": False})["mislabelled"])

    def test_read_only_false_raises_the_floor_for_an_uninformative_name(self):
        self.assertEqual(classify("run_task", {"readOnlyHint": False})["effect"], effects.WRITE)

    def test_destructive_true_raises_the_floor(self):
        self.assertEqual(classify("apply", {"destructiveHint": True})["effect"], effects.IRREVERSIBLE)

    def test_annotations_never_lower_the_result(self):
        # A server asserting read-only on a delete tool is making a claim, not
        # providing evidence.
        self.assertEqual(classify("delete_all", {"readOnlyHint": True})["effect"],
                         effects.IRREVERSIBLE)

    def test_no_annotations_means_no_mislabelling(self):
        self.assertFalse(classify("delete_everything")["mislabelled"])

    def test_correctly_annotated_read_tool_is_clean(self):
        result = classify("get_schema", {"readOnlyHint": True, "destructiveHint": False})
        self.assertEqual(result["effect"], effects.READ)
        self.assertFalse(result["mislabelled"])


class TestEvidenceAndCounts(unittest.TestCase):
    def test_evidence_explains_the_verdict(self):
        evidence = classify("delete_account", {"readOnlyHint": True})["evidence"]
        self.assertTrue(any("readOnlyHint" in line for line in evidence))
        self.assertTrue(any("delete" in line for line in evidence))

    def test_counts_cover_every_class(self):
        tally = effects.counts([classify(n) for n in ("get_x", "create_x", "send_x", "delete_x")])
        self.assertEqual(tally, {effects.READ: 1, effects.WRITE: 1,
                                 effects.EXTERNAL: 1, effects.IRREVERSIBLE: 1})

    def test_heuristics_version_is_recorded(self):
        self.assertEqual(classify("get_x")["heuristics_version"], effects.HEURISTICS_VERSION)


if __name__ == "__main__":
    unittest.main()

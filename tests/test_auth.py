"""Auth classification. Every case here came from a real config or a real bug."""

from __future__ import annotations

import unittest

from toolprint import auth
from toolprint.model import (
    AUTH_ENV_VAR, AUTH_HELPER_COMMAND, AUTH_LITERAL_SECRET, AUTH_NONE, AUTH_OAUTH,
)


class TestCredentialNames(unittest.TestCase):
    def test_token_based_not_substring(self):
        for name in ("CONTEXT7_API_KEY", "GITHUB_TOKEN", "apiKey", "Authorization",
                     "x-api-key", "GEM_PASSWORD", "DART_TOKEN"):
            self.assertTrue(auth.is_credential_name(name), name)

    def test_rejects_incidental_word_matches(self):
        # "MONKEY" contains "KEY"; a substring test would flag these.
        for name in ("X-Monkey-Id", "CACHE_DIR", "Content-Type", "TASK_MODE",
                     "DONKEY_COUNT", "Accept"):
            self.assertFalse(auth.is_credential_name(name), name)


class TestSecretDetection(unittest.TestCase):
    def test_issuer_prefix_is_anchored(self):
        # Regression: an unanchored "sk-" test matched inside ordinary strings.
        self.assertIsNone(auth.looks_like_secret("disk-cache-sk-mode", False))
        self.assertIsNone(auth.looks_like_secret("task-runner-mcp", False))
        self.assertIsNotNone(auth.looks_like_secret("ghp_" + "A" * 36, False))

    def test_prefix_behind_auth_scheme(self):
        self.assertIsNotNone(auth.looks_like_secret("Bearer ghp_" + "A" * 36, False))

    def test_vendor_key_embedding_a_known_prefix(self):
        # ctx7sk-... is a real credential but does not start with a known prefix.
        # It must still be caught, via the credential-named-field rule.
        value = "ctx7sk-11112222-3333-4444-5555-666677778888"
        self.assertIsNone(auth.looks_like_secret(value, False))
        self.assertIsNotNone(auth.looks_like_secret(value, True))

    def test_env_reference_is_not_a_secret(self):
        for value in ("${SANITY_TOKEN}", "Bearer ${TOKEN}", "${API_KEY:-fallback}", "$TOKEN"):
            self.assertIsNone(auth.looks_like_secret(value, True), value)

    def test_short_literal_in_credential_field_is_not_flagged(self):
        self.assertIsNone(auth.looks_like_secret("abc", True))

    def test_locations_never_carry_values(self):
        secret = "ghp_" + "A" * 36
        found = auth.scan_for_secrets({"Authorization": secret}, None, None, None)
        self.assertEqual(len(found), 1)
        blob = found[0].field + found[0].reason
        self.assertNotIn(secret, blob)

    def test_secret_in_arg_flag(self):
        found = auth.scan_for_secrets(None, None, ["--api-key=sk-ant-api03-" + "Z" * 28], None)
        self.assertEqual([f.field for f in found], ["args[0]"])

    def test_secret_in_url_query(self):
        found = auth.scan_for_secrets(None, None, None,
                                      "https://x.example/mcp?token=" + "Q" * 30)
        self.assertEqual([f.field for f in found], ["url.query.token"])

    def test_benign_url_query_ignored(self):
        self.assertEqual(auth.scan_for_secrets(None, None, None,
                                               "https://x.example/mcp?tenant=acme"), [])


class TestPosture(unittest.TestCase):
    def classify(self, **kw):
        params = dict(secret_locations=[], headers=None, env=None,
                      headers_helper=None, has_oauth=False)
        params.update(kw)
        return auth.classify(**params)[0]

    def test_precedence_worst_first(self):
        from toolprint.model import SecretLocation
        secret = [SecretLocation("headers.Authorization", "x")]
        # A literal secret outranks every mechanism it might accompany.
        self.assertEqual(self.classify(secret_locations=secret, has_oauth=True), AUTH_LITERAL_SECRET)
        self.assertEqual(self.classify(headers_helper="/bin/x", has_oauth=True), AUTH_HELPER_COMMAND)
        self.assertEqual(self.classify(has_oauth=True), AUTH_OAUTH)

    def test_env_reference_is_env_var_posture(self):
        self.assertEqual(self.classify(headers={"Authorization": "Bearer ${T}"}), AUTH_ENV_VAR)
        self.assertEqual(self.classify(env={"GITHUB_TOKEN": "${GITHUB_TOKEN}"}), AUTH_ENV_VAR)

    def test_no_credentials_at_all(self):
        self.assertEqual(self.classify(), AUTH_NONE)
        self.assertEqual(self.classify(env={"CACHE_DIR": "/tmp"}), AUTH_NONE)


if __name__ == "__main__":
    unittest.main()


class TestPrefixedReferences(unittest.TestCase):
    """A credential prefix in front of a ${VAR} is a correct config, not a leak.

    Found by pointing toolprint at its own watchlist: "xoxb-${WATCH_PLACEHOLDER}"
    was reported as a plaintext credential, which is a false accusation about a
    config doing exactly the right thing.
    """

    def test_prefix_plus_reference_is_hygienic(self):
        for value in ("xoxb-${SLACK_TOKEN}", "fc-${FIRECRAWL_KEY}",
                      "tvly-${TAVILY_KEY}", "sk-${OPENAI_KEY}",
                      "Bearer ghp_${GH_TOKEN}"):
            self.assertIsNone(auth.looks_like_secret(value, True), value)

    def test_a_real_token_beside_a_reference_is_still_flagged(self):
        # Residue long enough to be a credential in its own right.
        self.assertIsNotNone(
            auth.looks_like_secret("ghp_" + "A" * 36 + "${SUFFIX}", True))

    def test_bare_prefix_with_a_real_body_is_still_flagged(self):
        self.assertIsNotNone(auth.looks_like_secret("xoxb-" + "A" * 30, True))

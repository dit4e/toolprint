"""Auth posture classification and literal-credential detection.

Client configs support variable expansion (`${VAR}`, `${VAR:-default}`), so a
header of `Bearer ${API_KEY}` is hygienic while the same header holding the token
itself is a plaintext credential sitting in a dotfile. Telling those apart is a
string test, which means we get it for free in --no-connect mode. It becomes
finding HYG-002 in M2.

Everything here reports *locations*, never values. A detector that quotes the
secret it found has recreated the problem it was looking for.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

from .model import (
    AUTH_ENV_VAR,
    AUTH_HELPER_COMMAND,
    AUTH_LITERAL_SECRET,
    AUTH_NONE,
    AUTH_OAUTH,
    SecretLocation,
)

# ${VAR}, ${VAR:-default} and bare $VAR expansions.
ENV_REF = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*")

# Auth scheme words that legitimately sit next to a reference and are not secrets.
SCHEME_WORDS = re.compile(r"\b(bearer|basic|token|apikey|api_key|key)\b", re.I)

# Field names that are credential-carrying by convention.
CREDENTIAL_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-goog-api-key",
    "token",
    "secret",
}
CREDENTIAL_WORDS = frozenset({
    "TOKEN", "KEY", "APIKEY", "SECRET", "PASSWORD", "PASSWD", "PASS",
    "CREDENTIAL", "CREDENTIALS", "AUTH", "PAT", "SESSION", "BEARER", "SIGNATURE",
})

# Split on separators and camelCase, so CONTEXT7_API_KEY and apiKey both yield a
# "KEY" token while X-Monkey-Id does not. A substring test would match "MONKEY".
_NAME_TOKENS = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")

# High-precision issuer prefixes. These identify a credential regardless of what
# the surrounding field is called, which catches secrets in oddly-named fields.
SECRET_PREFIXES = (
    "sk-ant-",
    "sk-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "AKIA",
    "ASIA",
    "AIza",
    "npm_",
    "dop_v1_",
    "hf_",
    "pk_live_",
    "rk_live_",
    "eyJ",  # JWT
)

# A credential-shaped residue this long is a token, not a scheme word or a path.
MIN_SECRET_RESIDUE = 12


def _residue(value: str) -> str:
    """What is left of a value once expansions and scheme words are removed."""
    without_refs = ENV_REF.sub("", value)
    without_scheme = SCHEME_WORDS.sub("", without_refs)
    return re.sub(r"[^A-Za-z0-9]", "", without_scheme)


def has_env_reference(value: str) -> bool:
    return bool(ENV_REF.search(value))


# Auth schemes a token may legitimately sit behind: "Authorization: Bearer ghp_...".
SCHEME_PREFIX = re.compile(r"^(?:bearer|basic|token|apikey)\s+", re.I)


def _has_issuer_prefix(value: str) -> bool:
    """True if the value *starts* with a known credential prefix.

    Anchored deliberately. An unanchored substring test matches "sk-" inside
    ordinary strings such as "task-runner" or "disk-cache", and it also misfires
    on vendor keys that merely embed a known prefix (Context7's "ctx7sk-..." is
    a real credential, but it is caught by the credential-named-field rule below
    with an accurate reason rather than by a bogus prefix match).
    """
    candidate = SCHEME_PREFIX.sub("", value.strip())
    return any(candidate.startswith(prefix) for prefix in SECRET_PREFIXES)


def looks_like_secret(value: object, credential_field: bool) -> Optional[str]:
    """Return a reason string if this value looks like a literal credential."""
    if not isinstance(value, str) or not value.strip():
        return None
    stripped = value.strip()
    if _has_issuer_prefix(stripped):
        return "value begins with a recognised credential prefix"
    if credential_field and len(_residue(stripped)) >= MIN_SECRET_RESIDUE:
        return "credential-named field holds a literal value, not a ${VAR} reference"
    return None


def is_credential_name(name: str) -> bool:
    """True if a header or env var name conventionally carries a credential.

    Token-based rather than substring-based: CONTEXT7_API_KEY and apiKey are
    credentials, X-Monkey-Id and CACHE_DIR are not.
    """
    if name.lower() in CREDENTIAL_HEADERS:
        return True
    tokens = {t.upper() for t in _NAME_TOKENS.split(name) if t}
    return bool(tokens & CREDENTIAL_WORDS)


def scan_for_secrets(
    headers: Optional[dict],
    env: Optional[dict],
    args: Optional[list],
    url: Optional[str],
) -> List[SecretLocation]:
    """Locate literal credentials. Records field paths only, never values."""
    found: List[SecretLocation] = []

    for name, value in (headers or {}).items():
        reason = looks_like_secret(value, is_credential_name(name))
        if reason:
            found.append(SecretLocation("headers.{}".format(name), reason))

    for name, value in (env or {}).items():
        reason = looks_like_secret(value, is_credential_name(name))
        if reason:
            found.append(SecretLocation("env.{}".format(name), reason))

    for index, value in enumerate(args or []):
        if not isinstance(value, str):
            continue
        # Both "--token=VALUE" and a bare token positional.
        flag_match = re.match(r"--?([A-Za-z0-9_-]*(?:key|token|secret|password|auth)[A-Za-z0-9_-]*)=(.+)$", value, re.I)
        if flag_match:
            reason = looks_like_secret(flag_match.group(2), True)
        else:
            reason = looks_like_secret(value, False)
        if reason:
            found.append(SecretLocation("args[{}]".format(index), reason))

    if url:
        try:
            query = urlsplit(url).query
        except ValueError:
            query = ""
        for name, value in parse_qsl(query, keep_blank_values=True):
            credential_field = is_credential_name(name)
            reason = looks_like_secret(value, credential_field)
            if reason:
                found.append(
                    SecretLocation("url.query.{}".format(name), reason)
                )
    return found


def classify(
    secret_locations: List[SecretLocation],
    headers: Optional[dict],
    env: Optional[dict],
    headers_helper: Optional[str],
    has_oauth: bool,
) -> Tuple[str, List[str]]:
    """Return (auth_method, notes). Worst posture wins; see model.py for order."""
    notes: List[str] = []

    if secret_locations:
        return AUTH_LITERAL_SECRET, notes
    if headers_helper:
        notes.append("auth headers are minted by an external command; posture is not statically determinable")
        return AUTH_HELPER_COMMAND, notes
    if has_oauth:
        return AUTH_OAUTH, notes

    referenced = [n for n, v in (headers or {}).items() if isinstance(v, str) and has_env_reference(v)]
    credential_env = [n for n in (env or {}) if is_credential_name(n)]
    if referenced or credential_env:
        return AUTH_ENV_VAR, notes

    if headers:
        # Headers present but none credential-shaped: informational, not auth.
        notes.append("headers present but none carry a credential")
    return AUTH_NONE, notes

"""Data model for collected MCP configuration.

Everything downstream (findings engine, renderers, bundle export) reads these
objects. Collection never renders and rendering never re-parses.

Redaction note: these objects hold *raw* values because M4's bundle export needs
one place to redact, not many. Anything that emits - renderer, JSON writer,
bundle - must go through the helpers here rather than touching raw fields.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Credential shapes to strip from server output even when this tool never held
# the value: a token the server fetched for itself, or one already in the
# ambient environment. The exact-value pass above is the reliable one; this only
# catches what that cannot see.
_SECRET_SHAPED = re.compile(
    r"\b(?:sk-[A-Za-z0-9_\-]{16,}|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[bapsr]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_\-]{16,}|AKIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_\-]{30,}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})")

# Fragments of server stderr that change between otherwise identical runs.
_VOLATILE = (
    # ISO-8601-ish timestamps, including npm's filename-safe underscore form.
    (re.compile(r"\d{4}-\d{2}-\d{2}[T_ ]\d{2}[:_]\d{2}[:_]\d{2}(?:[.,_]\d+)?Z?"), "<timestamp>"),
    (re.compile(r"\b(pid|PID)[= ]\d+"), r"\1=<pid>"),
    (re.compile(r"/var/folders/[^\s'\"]+"), "<tmp>"),
    (re.compile(r"/tmp/[A-Za-z0-9_.-]+"), "<tmp>"),
    (re.compile(r"\b0x[0-9a-fA-F]{6,}\b"), "<addr>"),
)

# Auth posture, worst-first. Order is significant: classify() returns the first
# that applies, so a literal secret outranks the mechanism it is used with.
AUTH_LITERAL_SECRET = "literal_secret"
AUTH_HELPER_COMMAND = "helper_command"
AUTH_OAUTH = "oauth"
AUTH_ENV_VAR = "env_var"
AUTH_NONE = "none"
AUTH_UNKNOWN = "unknown"

TRANSPORTS = ("stdio", "http", "sse", "ws", "unknown")


@dataclass
class SecretLocation:
    """Where a literal credential appears. Never carries the value itself."""

    field: str  # "headers.Authorization", "env.DART_TOKEN", "args[3]", "url.query"
    reason: str


@dataclass
class Server:
    name: str
    client: str  # registry client id, e.g. "claude_code"
    scope: str  # "user" | "local" | "project" | "workspace"
    scope_detail: Optional[str]  # e.g. the project path for Claude Code local scope
    source_path: str  # config file this came from
    # Which project this entry applies to. None means user scope: it applies to
    # every project of that client. Context resolution depends on this.
    project_root: Optional[str] = None

    transport: str = "unknown"
    command: Optional[str] = None  # raw; use command_basename to emit
    args: List[str] = field(default_factory=list)
    url: Optional[str] = None  # raw; use url_host to emit
    env_names: List[str] = field(default_factory=list)  # names only, ever
    header_names: List[str] = field(default_factory=list)  # names only, ever
    headers_helper: Optional[str] = None
    # Raw credential-bearing values, kept because --connect must actually
    # authenticate. NEVER emitted: renderers read the safe accessors above, and
    # tests/test_no_secrets.py fails the build if these names reach any output.
    raw_headers: Dict[str, str] = field(default_factory=dict)
    raw_env: Dict[str, str] = field(default_factory=dict)
    has_oauth: bool = False
    enabled: bool = True

    auth_method: str = AUTH_UNKNOWN
    secret_locations: List[SecretLocation] = field(default_factory=list)
    parse_notes: List[str] = field(default_factory=list)

    # M1 fills these in.
    fetch_status: str = "not_attempted"
    fetch_detail: Optional[str] = None
    protocol_version: Optional[str] = None
    protocol_era: Optional[str] = None  # "modern" | "legacy"
    tools: List[Dict[str, Any]] = field(default_factory=list)
    token_total: Optional[int] = None
    token_method: Optional[str] = None
    # Kept alongside the tools rather than inside them: M5 must hash the tool
    # definition exactly as the server sent it, so nothing may be added to it.
    tool_tokens: Dict[str, int] = field(default_factory=dict)

    @property
    def command_basename(self) -> Optional[str]:
        """Basename only. Full command lines leak paths, usernames and tokens."""
        if not self.command:
            return None
        return self.command.replace("\\", "/").rstrip("/").split("/")[-1]

    @property
    def url_host(self) -> Optional[str]:
        """Host only. Tokens hide in both paths and query strings."""
        if not self.url:
            return None
        from urllib.parse import urlsplit

        try:
            return urlsplit(self.url).netloc or None
        except ValueError:
            return None

    @property
    def safe_detail(self) -> Optional[str]:
        """Failure detail, masked and de-volatilised.

        fetch_detail quotes a server's stderr, which brings two problems.

        Privacy: it routinely contains absolute paths - npm log locations,
        virtualenv prefixes - carrying the username and project names. Masked
        here rather than at each call site, alongside the other accessors.

        Stability: stderr also carries timestamps and pids. npm's "log can be
        found in .../2026-09-01T02_14_49_622Z-debug-0.log" changes on every run,
        which broke the two-run test and would surface as permanent phantom drift
        in M5 for anyone with a failing npm-based server. Volatile fragments are
        replaced with fixed placeholders so the detail stays informative and the
        output stays comparable.
        """
        if not self.fetch_detail:
            return None
        detail = self.redact_credentials(self.fetch_detail)
        detail = detail.replace(os.path.expanduser("~"), "~")
        for pattern, replacement in _VOLATILE:
            detail = pattern.sub(replacement, detail)
        return detail[:200]

    def redact_credentials(self, text: str) -> str:
        """Remove this server's own credentials from text it produced.

        Servers quote their configuration in startup errors - "could not
        authenticate with key=..." is an ordinary thing for one to print - and
        that text lands in fetch_detail, which is written to findings.json and
        to a watchlist observation that may be committed to a public repository.

        The redaction is exact rather than heuristic: these are the values this
        process passed to that server, both as written and as expanded, so there
        is no guessing about what a secret looks like. A pattern backstop
        follows for credentials the tool never saw - one the server fetched for
        itself, or one inherited from the ambient environment.
        """
        from .transport import expand

        for name, raw in list(self.raw_env.items()) + list(self.raw_headers.items()):
            if not isinstance(raw, str):
                continue
            candidates = {raw}
            try:
                candidates.add(expand(raw))
            except Exception:
                pass
            for candidate in candidates:
                stripped = candidate.strip()
                # Short values are words, not secrets, and blind-replacing them
                # would mangle the message it is trying to keep readable.
                if len(stripped) >= 8 and stripped in text:
                    text = text.replace(stripped, "<redacted:{}>".format(name))
        return _SECRET_SHAPED.sub("<redacted>", text)

    @property
    def key(self) -> str:
        """Stable identity across runs: same server in two clients is two entries."""
        return "{}/{}/{}".format(self.client, self.scope, self.name)


@dataclass
class CollectionError:
    """Failures are data, not exceptions. 'Three servers unreachable' is a finding."""

    path: str
    client: Optional[str]
    kind: str  # "unreadable" | "malformed" | "unexpected_shape"
    detail: str


@dataclass
class Inventory:
    servers: List[Server] = field(default_factory=list)
    errors: List[CollectionError] = field(default_factory=list)
    clients_found: List[str] = field(default_factory=list)
    paths_scanned: List[str] = field(default_factory=list)

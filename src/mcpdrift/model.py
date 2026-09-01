"""Data model for collected MCP configuration.

Everything downstream (findings engine, renderers, bundle export) reads these
objects. Collection never renders and rendering never re-parses.

Redaction note: these objects hold *raw* values because M4's bundle export needs
one place to redact, not many. Anything that emits - renderer, JSON writer,
bundle - must go through the helpers here rather than touching raw fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

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

    transport: str = "unknown"
    command: Optional[str] = None  # raw; use command_basename to emit
    args: List[str] = field(default_factory=list)
    url: Optional[str] = None  # raw; use url_host to emit
    env_names: List[str] = field(default_factory=list)  # names only, ever
    header_names: List[str] = field(default_factory=list)  # names only, ever
    headers_helper: Optional[str] = None
    has_oauth: bool = False
    enabled: bool = True

    auth_method: str = AUTH_UNKNOWN
    secret_locations: List[SecretLocation] = field(default_factory=list)
    parse_notes: List[str] = field(default_factory=list)

    # M1 fills these in.
    fetch_status: str = "not_attempted"
    protocol_version: Optional[str] = None
    tools: List[Dict[str, Any]] = field(default_factory=list)

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

"""MCP protocol negotiation and tool retrieval.

The 2026-07-28 revision removed the initialize handshake: the protocol is
stateless, and every request carries its own version and capabilities in _meta.
`server/discover` is MUST-implement on modern servers and is the correct era
probe. Its three outcomes, per the spec:

  * DiscoverResult                  -> modern; pick a mutually supported version
  * a recognised modern JSON-RPC error -> modern, wrong version; do NOT fall back
  * anything else, or a timeout     -> legacy; fall back to initialize

That middle case is the one worth getting right. Falling back on any error would
downgrade a modern server to legacy semantics and quietly produce a wrong answer,
and the spec is explicit that the fallback must not be keyed to a single code.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from . import TOOL_NAME, __version__
from .model import Server
from .transport import (
    PROTOCOL_VERSION,
    HttpTransport,
    StdioTransport,
    Transport,
    TransportError,
)

# Error codes a modern server uses. Seeing one of these proves the server speaks a
# modern revision, so the legacy fallback must be skipped.
MODERN_ERROR_CODES = {
    -32020,  # HeaderMismatch
    -32021,  # MissingRequiredClientCapability
    -32022,  # UnsupportedProtocolVersion
}
# Newest first: the version we negotiate down to when a server rejects ours.
LEGACY_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26")

# The revision that removed the initialize handshake. Revision ids are ISO dates,
# so lexical comparison also covers revisions published after this build.
FIRST_STATELESS_VERSION = "2026-07-28"


def era_for(version: str) -> str:
    """Era is a property of the negotiated *version*, not of the error code.

    This distinction is load-bearing and easy to get wrong. The spec says a
    recognised modern JSON-RPC error proves the server is modern and that you
    must not fall back to initialize on it - true, but it means the server knows
    about the modern spec, not that it speaks a stateless version of it.

    Observed in the wild: mcp.sanity.io answers server/discover with a correct
    -32022 UnsupportedProtocolVersion whose `supported` list is entirely
    pre-2026-07-28. Treating "modern error code" as "modern era" sends tools/list
    with no handshake, and the server rejects it for a missing session id. Decide
    on the version you actually negotiated.
    """
    return "modern" if version >= FIRST_STATELESS_VERSION else "legacy"

CLIENT_INFO = {"name": TOOL_NAME, "version": __version__}
MAX_PAGES = 50  # pagination backstop; a server looping cursors must not hang us


def meta(version: str = PROTOCOL_VERSION) -> Dict[str, Any]:
    return {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientInfo": CLIENT_INFO,
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    }


def _looks_like_jsonrpc(message: Dict[str, Any]) -> bool:
    return "jsonrpc" in message or "result" in message or "error" in message


def _error_code(message: Dict[str, Any]) -> Optional[int]:
    error = message.get("error")
    if isinstance(error, dict) and isinstance(error.get("code"), int):
        return error["code"]
    return None


def negotiate(transport: Transport, timeout: float) -> Tuple[str, str]:
    """Return (era, protocol_version). Raises TransportError if unreachable."""
    try:
        message = transport.request("server/discover", meta(), timeout)
    except TransportError:
        raise

    result = message.get("result")
    if isinstance(result, dict):
        supported = result.get("supportedVersions")
        if isinstance(supported, list) and supported:
            chosen = PROTOCOL_VERSION if PROTOCOL_VERSION in supported else str(max(supported))
            return era_for(chosen), chosen
        return "modern", PROTOCOL_VERSION

    code = _error_code(message)
    if code in MODERN_ERROR_CODES:
        # The server knows the modern spec, so do not probe blindly for a legacy
        # one - but it may still only *speak* pre-stateless versions. Take the
        # newest version it advertises and let era_for decide how to talk to it.
        data = message.get("error", {}).get("data") or {}
        supported = data.get("supported")
        if isinstance(supported, list) and supported:
            chosen = PROTOCOL_VERSION if PROTOCOL_VERSION in supported else str(max(supported))
            return era_for(chosen), chosen
        return "modern", PROTOCOL_VERSION

    if not _looks_like_jsonrpc(message):
        # Not an MCP endpoint at all. Observed with a host that answers the MCP
        # URL with a JSON redirect envelope. Saying "legacy" here would produce a
        # misleading "initialize rejected for every known version".
        raise TransportError(
            "not_mcp",
            "endpoint did not return a JSON-RPC message (keys: {})".format(
                ", ".join(sorted(message.keys()))[:80]),
        )

    # A JSON-RPC error we do not recognise: legacy, per the spec's instruction not
    # to key the fallback to any single error code.
    return "legacy", LEGACY_VERSIONS[0]


def initialize_legacy(transport: Transport, version: str, timeout: float) -> str:
    """The pre-2026-07-28 handshake, used only when the era probe says legacy."""
    tried = []
    for candidate in (version,) + LEGACY_VERSIONS:
        if candidate in tried:
            continue
        tried.append(candidate)
        # Keep the transport's advertised version in step with the body, or an
        # HTTP server validates the header and rejects every attempt identically.
        if hasattr(transport, "protocol_version"):
            transport.protocol_version = candidate  # type: ignore[attr-defined]
        message = transport.request(
            "initialize",
            {
                "protocolVersion": candidate,
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            },
            timeout,
        )
        result = message.get("result")
        if isinstance(result, dict):
            negotiated = str(result.get("protocolVersion") or candidate)
            if hasattr(transport, "protocol_version"):
                transport.protocol_version = negotiated  # type: ignore[attr-defined]
            notify = getattr(transport, "notify", None)
            if callable(notify):
                notify("notifications/initialized", {})
            return negotiated
    raise TransportError(
        "error", "initialize rejected for versions: {}".format(", ".join(tried))
    )


def list_tools(transport: Transport, era: str, version: str, timeout: float) -> List[Dict[str, Any]]:
    """Retrieve tools/list, following pagination cursors."""
    tools: List[Dict[str, Any]] = []
    cursor: Optional[str] = None
    seen_cursors = set()

    for _ in range(MAX_PAGES):
        params: Dict[str, Any] = dict(meta(version)) if era == "modern" else {}
        if cursor is not None:
            params["cursor"] = cursor
        message = transport.request("tools/list", params, timeout)

        error = message.get("error")
        if isinstance(error, dict):
            raise TransportError("error", str(error.get("message", "tools/list failed"))[:200])

        result = message.get("result")
        if not isinstance(result, dict):
            raise TransportError("error", "tools/list returned no result")
        page = result.get("tools")
        if isinstance(page, list):
            tools.extend(t for t in page if isinstance(t, dict))

        cursor = result.get("nextCursor")
        if not cursor or not isinstance(cursor, str):
            break
        if cursor in seen_cursors:
            break  # server is looping; take what we have
        seen_cursors.add(cursor)

    return tools


def build_transport(server: Server, cwd: Optional[str] = None) -> Transport:
    if server.transport == "stdio":
        if not server.command:
            raise TransportError("error", "stdio server has no command")
        return StdioTransport(server.command, server.args, server.raw_env, cwd)
    if server.transport in ("http", "sse"):
        if not server.url:
            raise TransportError("error", "remote server has no url")
        return HttpTransport(server.url, server.raw_headers)
    raise TransportError("unsupported", "transport {!r} is not supported".format(server.transport))


def fetch(server: Server, timeout: float = 15.0, cwd: Optional[str] = None) -> None:
    """Populate server.tools and fetch_status in place. Never raises."""
    transport: Optional[Transport] = None
    try:
        transport = build_transport(server, cwd)
        era, version = negotiate(transport, timeout)
        if era == "legacy":
            version = initialize_legacy(transport, version, timeout)
        server.protocol_era = era
        server.protocol_version = version
        server.tools = list_tools(transport, era, version, timeout)
        server.fetch_status = "ok"
    except TransportError as exc:
        server.fetch_status = exc.status
        server.fetch_detail = exc.detail
    except Exception as exc:  # a collector that raises produces no report at all
        server.fetch_status = "error"
        server.fetch_detail = "{}: {}".format(type(exc).__name__, exc)[:200]
    finally:
        if transport is not None:
            transport.close()

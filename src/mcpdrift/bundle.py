"""Bundle export: a redacted description of an MCP deployment, for assessment.

The customer runs a collection, reads the file, and sends it. Everything here
serves that review step, which means the governing question is not "what would be
useful to have" but "what can a sceptical security engineer approve in five
minutes".

Redaction is an allowlist, in one visible constant. A denylist - strip anything
that looks like a secret - fails open and cannot be verified by reading; an
allowlist fails closed and a reviewer can check it in thirty seconds. If a field
is not named in EMITTED_FIELDS it never reaches the bundle, including fields
added to the model later.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import platform
import sys
import textwrap
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .model import Inventory, Server

BUNDLE_VERSION = 1

# ---------------------------------------------------------------------------
# Everything this export will emit. Nothing else leaves the machine.
# ---------------------------------------------------------------------------
EMITTED_FIELDS = {
    "server": ["name", "source_client", "scope", "transport", "command_basename",
               "auth_method", "auth_env_names", "auth_header_names", "url_host",
               "fetch_status", "protocol_version", "protocol_era"],
    "tool": ["name", "title", "description", "inputSchema", "outputSchema",
             "annotations", "token_estimate", "token_method"],
    # No "usage" entry: neither this exporter nor mcp_collect.py collects call
    # counts yet, and an allowlist naming a field nothing emits misleads the
    # person reading it. It comes back when --usage lands.
}

DATA_POLICY = (
    "This bundle contains: MCP server names, which client they were configured in, "
    "transport type, the basename of any command (for example 'npx'), the hostname "
    "of any remote server, the NAMES of environment variables and HTTP headers used "
    "for authentication, and the full tool definitions each server advertises - tool "
    "names, descriptions and JSON schemas.\n"
    "It does NOT contain: environment variable values, HTTP header values, API keys, "
    "tokens or passwords of any kind; full command lines or arguments; absolute file "
    "paths; URL paths or query strings; usernames or hostnames of your machine; or "
    "the contents of any file, request or response.\n"
    "Tool definitions are included in full because they are the substance of the "
    "assessment, and because they are already what the language model sees on every "
    "request."
)


def _digest(salt: str, value: str) -> str:
    """Stable, salted, non-reversible identifier.

    HMAC rather than a plain hash: server and tool names are drawn from a small
    public vocabulary, so an unsalted hash of 'github' is recovered instantly by
    dictionary. The customer keeps the salt, so they can re-identify their own
    bundle and nobody else can.
    """
    return hmac.new(salt.encode("utf-8"), value.encode("utf-8"),
                    hashlib.sha256).hexdigest()[:12]


class Anonymiser:
    """Replaces identifiers consistently, so the bundle stays analysable."""

    def __init__(self, salt: Optional[str]):
        self.salt = salt

    @property
    def active(self) -> bool:
        return bool(self.salt)

    def name(self, value: Optional[str], prefix: str) -> Optional[str]:
        if not value or not self.salt:
            return value
        return "{}-{}".format(prefix, _digest(self.salt, value))


def _tool(tool: Dict[str, Any], tokens: Dict[str, int], method: Optional[str]) -> Dict[str, Any]:
    name = tool.get("name")
    out: "OrderedDict[str, Any]" = OrderedDict()
    for field in EMITTED_FIELDS["tool"]:
        if field == "token_estimate":
            out[field] = tokens.get(name) if isinstance(name, str) else None
        elif field == "token_method":
            out[field] = method
        elif field in tool:
            out[field] = tool[field]
    return out


def _server(server: Server, anon: Anonymiser) -> Dict[str, Any]:
    # Built field by field from the allowlist, so a new attribute on Server
    # cannot silently start appearing in bundles.
    values = {
        "name": anon.name(server.name, "server") if anon.active else server.name,
        "source_client": server.client,
        "scope": server.scope,
        "transport": server.transport,
        "command_basename": server.command_basename,
        "auth_method": server.auth_method,
        "auth_env_names": server.env_names,
        "auth_header_names": server.header_names,
        "url_host": anon.name(server.url_host, "host") if anon.active else server.url_host,
        "fetch_status": server.fetch_status,
        "protocol_version": server.protocol_version,
        "protocol_era": server.protocol_era,
    }
    out: "OrderedDict[str, Any]" = OrderedDict(
        (field, values[field]) for field in EMITTED_FIELDS["server"])
    out["tools"] = [_tool(t, server.tool_tokens, server.token_method) for t in server.tools]
    return out


def build(
    inventory: Inventory,
    collected_at: str,
    mode: str,
    salt: Optional[str] = None,
    usage: Optional[Sequence[Dict[str, Any]]] = None,
    kit_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    anon = Anonymiser(salt)
    servers = sorted(inventory.servers, key=lambda s: s.key)
    return OrderedDict([
        ("bundle_version", BUNDLE_VERSION),
        ("kit_version", __version__),
        ("kit_sha256", kit_sha256),
        ("collected_at", collected_at),
        ("mode", mode),
        ("anonymized", anon.active),
        ("data_policy", DATA_POLICY),
        ("platform", OrderedDict([
            ("os", sys.platform),
            ("python", platform.python_version()),
        ])),
        ("clients_found", inventory.clients_found),
        ("servers", [_server(s, anon) for s in servers]),
        ("usage", list(usage or [])),
        # Failures are data. "Three servers were unreachable" is a finding.
        ("collection_errors", [
            OrderedDict([("kind", e.kind), ("client", e.client),
                         ("detail", e.detail)])
            for e in inventory.errors
        ]),
    ])


def summarise(document: Dict[str, Any], path: str, size: int) -> str:
    """What the user sees after a bundle is written. Ends with the review order."""
    servers = document.get("servers", [])
    tools = sum(len(s.get("tools", [])) for s in servers)
    failed = [s for s in servers if s.get("fetch_status") not in ("ok", "not_attempted")]
    lines = [
        "",
        "Bundle written: {} ({:,} bytes)".format(path, size),
        "  {} server(s), {} tool definition(s) captured".format(len(servers), tools),
        "  mode: {}{}".format(document.get("mode"),
                              ", anonymized" if document.get("anonymized") else ""),
    ]
    if failed:
        lines.append("  {} server(s) could not be reached (recorded in the bundle)".format(
            len(failed)))
    errors = document.get("collection_errors") or []
    if errors:
        lines.append("  {} config file(s) could not be parsed (recorded in the bundle)".format(
            len(errors)))
    lines += ["", "DATA POLICY", ""]
    for paragraph in document.get("data_policy", "").split("\n"):
        lines.append(textwrap.fill(paragraph, 78, initial_indent="  ",
                                   subsequent_indent="  "))
    lines += [
        "",
        "Review this file before sending it. It contains exactly what is listed",
        "above and nothing else.",
        "",
    ]
    return "\n".join(lines)


def find_secrets(document: Dict[str, Any], needles: Sequence[str]) -> List[str]:
    """Test helper: does any known secret appear anywhere in the bundle?"""
    blob = json.dumps(document)
    return sorted({n for n in needles if n and n in blob})

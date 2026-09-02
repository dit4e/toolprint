"""Table-driven registry of MCP client configuration locations.

Adding or fixing a client is a data edit to CLIENTS below, never a code change.
Client config paths move between releases - verify against current docs rather
than trusting this table indefinitely. Last verified: 2026-08-31.

Two things the naive design gets wrong, both found during verification:

  1. The top-level key is not always "mcpServers". VS Code uses "servers".
  2. One file can hold more than one scope. Claude Code keeps user-scope servers
     at ~/.claude.json["mcpServers"] and local-scope servers at
     ~/.claude.json["projects"]["<abs path>"]["mcpServers"].

So a source describes *where in the JSON* the servers live, not just the path.
The container is a tuple of keys where "*" means "every key here is a separate
container, and its name is the scope detail".
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Container shapes, named so the table below reads as data.
AT_MCPSERVERS = ("mcpServers",)
AT_SERVERS = ("servers",)
AT_CLAUDE_PROJECTS = ("projects", "*", "mcpServers")

HOME = "home"  # pattern is relative to the user's home directory
PROJECT = "project"  # pattern is relative to a project root


@dataclass
class Source:
    where: str  # HOME or PROJECT
    pattern: str  # may contain glob wildcards
    scope: str  # user | local | project | workspace
    container: Tuple[str, ...]
    platforms: Optional[Tuple[str, ...]] = None  # None means all
    note: str = ""


@dataclass
class Client:
    id: str
    name: str
    sources: List[Source] = field(default_factory=list)
    # Scope precedence, lowest rank wins. Verified 2026-08-31 for all three
    # multi-scope clients; all agree that the more specific scope wins, that the
    # *whole* entry from the winning scope is used, and that there is no field
    # merging. A losing entry does not partially apply - it does not apply at all,
    # which is what makes shadowed config invisible to the person who wrote it.
    precedence: Dict[str, int] = field(default_factory=dict)

    def rank(self, scope: str) -> int:
        # Unranked scopes sort last but stay deterministic.
        return self.precedence.get(scope, 99)


CLIENTS: List[Client] = [
    Client(
        id="claude_code",
        name="Claude Code",
        sources=[
            Source(HOME, ".claude.json", "user", AT_MCPSERVERS),
            # Same file, different scope. Each project path is its own container.
            Source(HOME, ".claude.json", "local", AT_CLAUDE_PROJECTS),
            Source(PROJECT, ".mcp.json", "project", AT_MCPSERVERS),
        ],
        precedence={"local": 0, "project": 1, "user": 2},
    ),
    Client(
        id="claude_desktop",
        name="Claude Desktop",
        sources=[
            Source(
                HOME,
                "Library/Application Support/Claude/claude_desktop_config.json",
                "user",
                AT_MCPSERVERS,
                ("darwin",),
                # Verified present on macOS 2026-08-31 but carrying no mcpServers key;
                # Desktop appears to have moved MCP to extensions/connectors. If that
                # is confirmed, the fix is a new Source here, not new code.
                note="verified 2026-08-31 as present but carrying no mcpServers key",
            ),
            Source(
                HOME,
                "AppData/Roaming/Claude/claude_desktop_config.json",
                "user",
                AT_MCPSERVERS,
                ("win32",),
            ),
            Source(
                HOME,
                ".config/Claude/claude_desktop_config.json",
                "user",
                AT_MCPSERVERS,
                ("linux",),
            ),
        ],
    ),
    Client(
        id="cursor",
        name="Cursor",
        sources=[
            Source(HOME, ".cursor/mcp.json", "user", AT_MCPSERVERS),
            Source(PROJECT, ".cursor/mcp.json", "project", AT_MCPSERVERS),
        ],
        precedence={"project": 0, "user": 1},
    ),
    Client(
        id="vscode",
        name="VS Code",
        sources=[
            # Note the container: VS Code uses "servers", not "mcpServers".
            Source(PROJECT, ".vscode/mcp.json", "workspace", AT_SERVERS),
            # User-level config lives in the active profile folder, so this needs a
            # glob rather than a fixed path.
            Source(
                HOME,
                "Library/Application Support/Code/User/mcp.json",
                "user",
                AT_SERVERS,
                ("darwin",),
            ),
            Source(
                HOME,
                "Library/Application Support/Code/User/profiles/*/mcp.json",
                "user",
                AT_SERVERS,
                ("darwin",),
            ),
            Source(HOME, ".config/Code/User/mcp.json", "user", AT_SERVERS, ("linux",)),
            Source(
                HOME,
                ".config/Code/User/profiles/*/mcp.json",
                "user",
                AT_SERVERS,
                ("linux",),
            ),
            Source(
                HOME, "AppData/Roaming/Code/User/mcp.json", "user", AT_SERVERS, ("win32",)
            ),
            Source(
                HOME,
                "AppData/Roaming/Code/User/profiles/*/mcp.json",
                "user",
                AT_SERVERS,
                ("win32",),
            ),
        ],
        precedence={"workspace": 0, "user": 1},
    ),
    Client(
        id="copilot",
        name="Copilot Agent Host",
        sources=[Source(HOME, ".copilot/mcp-config.json", "user", AT_MCPSERVERS)],
    ),
    Client(
        id="windsurf",
        name="Windsurf",
        sources=[
            Source(HOME, ".codeium/windsurf/mcp_config.json", "user", AT_MCPSERVERS)
        ],
    ),
    Client(
        id="gemini_cli",
        name="Gemini CLI",
        sources=[Source(HOME, ".gemini/settings.json", "user", AT_MCPSERVERS)],
    ),
]

CLIENT_IDS = [c.id for c in CLIENTS]


def platform_id() -> str:
    """darwin | win32 | linux, matching the Source.platforms values."""
    if sys.platform.startswith("win"):
        return "win32"
    if sys.platform == "darwin":
        return "darwin"
    return "linux"


def applies_here(source: Source) -> bool:
    return source.platforms is None or platform_id() in source.platforms

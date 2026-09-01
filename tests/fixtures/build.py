"""Build a synthetic home directory covering every container shape in the registry.

Values here are fake but shaped like the real thing. FAKE_SECRETS is the list the
no-secrets test greps for: if any of these strings reaches rendered output, the
redaction boundary has been broken.
"""

from __future__ import annotations

import json
from pathlib import Path

FAKE_SECRETS = [
    "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "ctx7sk-11112222-3333-4444-5555-666677778888",
    "sk-ant-api03-ZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
    "hunter2-not-really-a-password-but-long",
    "/Users/someone/private/path/to/server.js",
]


def build(home: Path, project: Path) -> None:
    home.mkdir(parents=True, exist_ok=True)
    project.mkdir(parents=True, exist_ok=True)

    # Claude Code: user scope and local scope in one file, plus a known project.
    (home / ".claude.json").write_text(json.dumps({
        "projects": {
            str(project): {
                "mcpServers": {
                    "local-github": {
                        "command": "/opt/homebrew/bin/npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                        "env": {"GITHUB_TOKEN": FAKE_SECRETS[0], "CACHE_DIR": "/tmp"},
                    },
                },
            },
        },
        "mcpServers": {
            "user-remote": {
                "type": "http",
                "url": "https://mcp.example.com/v1/mcp?tenant=acme",
                "headers": {"Authorization": "Bearer ${SANITY_TOKEN}"},
            },
            "helper-auth": {
                "type": "http",
                "url": "https://helper.example.com/mcp",
                "headersHelper": "/usr/local/bin/mint-headers.sh",
            },
            "oauth-server": {
                "type": "http",
                "url": "https://oauth.example.com/mcp",
                "oauth": {"clientId": "abc", "callbackPort": 8080},
            },
            "wide-open": {"type": "http", "url": "https://open.example.com/mcp"},
            "ws-server": {"type": "ws", "url": "wss://socket.example.com/mcp"},
            "disabled-one": {"command": "uvx", "args": ["thing"], "disabled": True},
        },
    }), encoding="utf-8")

    # Claude Code project scope.
    (project / ".mcp.json").write_text(json.dumps({
        "mcpServers": {
            "proj-time": {"command": "uvx", "args": ["mcp-server-time"]},
        },
    }), encoding="utf-8")

    # Cursor: user and project.
    (home / ".cursor").mkdir(exist_ok=True)
    (home / ".cursor" / "mcp.json").write_text(json.dumps({
        "mcpServers": {
            "context7": {
                "type": "http",
                "url": "https://mcp.context7.com/mcp",
                # Vendor key that embeds "sk-" mid-string: must be caught by the
                # credential-named-field rule, not by an unanchored prefix match.
                "headers": {"CONTEXT7_API_KEY": FAKE_SECRETS[1]},
            },
            "task-runner": {
                # Contains "sk-" as a substring. Must NOT be flagged.
                "command": "npx",
                "args": ["-y", "task-runner-mcp", "--mode=disk-cache"],
                "env": {"TASK_MODE": "disk-cache-sk-mode", "X-Monkey-Id": "monkey-1234567890"},
            },
        },
    }), encoding="utf-8")
    (project / ".cursor").mkdir(exist_ok=True)
    (project / ".cursor" / "mcp.json").write_text(json.dumps({
        "mcpServers": {
            "proj-cursor": {"command": "npx", "args": ["-y", "thing", "--api-key=" + FAKE_SECRETS[2]]},
        },
    }), encoding="utf-8")

    # VS Code workspace: note the "servers" key, not "mcpServers".
    (project / ".vscode").mkdir(exist_ok=True)
    (project / ".vscode" / "mcp.json").write_text(json.dumps({
        "servers": {
            "vscode-local": {"type": "stdio", "command": FAKE_SECRETS[4]},
        },
    }), encoding="utf-8")

    # Gemini CLI.
    (home / ".gemini").mkdir(exist_ok=True)
    (home / ".gemini" / "settings.json").write_text(json.dumps({
        "theme": "dark",
        "mcpServers": {
            "gem": {"command": "uvx", "args": ["gem-mcp"],
                    "env": {"GEM_PASSWORD": FAKE_SECRETS[3]}},
        },
    }), encoding="utf-8")

    # A malformed file: must be recorded as an error, not raised.
    (home / ".codeium" / "windsurf").mkdir(parents=True, exist_ok=True)
    (home / ".codeium" / "windsurf" / "mcp_config.json").write_text("{not json", encoding="utf-8")

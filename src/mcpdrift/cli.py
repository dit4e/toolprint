"""Command-line entry point.

M0 implements `scan --no-connect` only. --connect arrives in M1 and is rejected
here rather than silently ignored, so nobody mistakes a config-only inventory for
a live one.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import TOOL_NAME, __version__, discover, registry
from .render import jsonout, text

EXIT_OK = 0
EXIT_FINDINGS = 1  # reserved for --fail-on in M2
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Offline MCP assessment: inventory, context cost, capability risk.",
    )
    parser.add_argument("--version", action="version", version="{} {}".format(TOOL_NAME, __version__))
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="discover MCP servers and report on them")
    scan.add_argument("--config", action="append", default=[], metavar="PATH",
                      help="explicit config file (repeatable); disables auto-discovery")
    scan.add_argument("--client", action="append", default=[], metavar="NAME",
                      choices=registry.CLIENT_IDS,
                      help="restrict to named clients: " + ", ".join(registry.CLIENT_IDS))
    scan.add_argument("--project", action="append", default=[], metavar="PATH",
                      help="project root to search for workspace configs (repeatable, globbable)")
    scan.add_argument("--no-project-autodetect", action="store_true",
                      help="do not derive project roots from Claude Code's known projects")
    scan.add_argument("--no-connect", action="store_true", default=True,
                      help="parse configs only; never start or contact servers (default)")
    scan.add_argument("--connect", dest="no_connect", action="store_false",
                      help="retrieve live tools/list (not implemented until M1)")
    scan.add_argument("--format", choices=["text", "json"], default="text")
    scan.add_argument("--out", metavar="PATH", help="write output to a file instead of stdout")

    sub.add_parser("clients", help="list the client config locations this build knows about")
    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    if not args.no_connect:
        sys.stderr.write(
            "--connect is not implemented yet (arrives in M1). Re-run without it for a\n"
            "config-only inventory, which needs no network and spawns no processes.\n"
        )
        return EXIT_ERROR

    inventory = discover.collect(
        clients=args.client or None,
        explicit_configs=args.config or None,
        project_patterns=args.project or None,
        use_claude_projects=not args.no_project_autodetect,
    )

    if args.format == "json":
        output = json.dumps(jsonout.inventory_dict(inventory), indent=2) + "\n"
    else:
        output = text.render(inventory, TOOL_NAME) + "\n"

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        sys.stderr.write("wrote {}\n".format(args.out))
    else:
        sys.stdout.write(output)
    return EXIT_OK


def cmd_clients(_: argparse.Namespace) -> int:
    for client in registry.CLIENTS:
        print("{}  ({})".format(client.id, client.name))
        for source in client.sources:
            if not registry.applies_here(source):
                continue
            base = "~" if source.where == registry.HOME else "<project>"
            note = "   # {}".format(source.note) if source.note else ""
            print("    {:<9} {}/{}  -> {}{}".format(
                source.scope, base, source.pattern, ".".join(source.container), note))
    return EXIT_OK


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "clients":
            return cmd_clients(args)
    except KeyboardInterrupt:
        return EXIT_ERROR
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

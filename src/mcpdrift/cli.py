"""Command-line entry point.

M0 implements `scan --no-connect` only. --connect arrives in M1 and is rejected
here rather than silently ignored, so nobody mistakes a config-only inventory for
a live one.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path

from . import TOOL_NAME, __version__, bundle, connect, context, demo, discover, registry
from .findings import engine, library
from .render import findings_json, html as html_render, jsonout, text

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
                      help="retrieve live tools/list; spawns stdio servers (see --dry-run)")
    scan.add_argument("--dry-run", action="store_true",
                      help="with --connect, print exactly what would be started or contacted, then stop")
    scan.add_argument("--window", type=int, default=200000, metavar="N",
                      help="context window used for %% calculations (default 200000)")
    scan.add_argument("--timeout", type=float, default=15.0, metavar="SECONDS",
                      help="per-request timeout when connecting (default 15)")
    scan.add_argument("--yes", action="store_true",
                      help="skip the confirmation prompt before contacting servers")
    scan.add_argument("--format", choices=["text", "json"], default="text")
    scan.add_argument("--findings", metavar="PATH",
                      help="write findings.json (the contract every renderer consumes)")
    scan.add_argument("--bundle", metavar="PATH",
                      help="write a redacted bundle for assessment; allowlist redaction, "
                           "no credential values, no paths (see mcp_collect.py)")
    scan.add_argument("--anonymize", metavar="SALT",
                      help="with --bundle, hash server names and hostnames using SALT")
    scan.add_argument("--html", metavar="PATH",
                      help="write a self-contained HTML report; opens offline, makes no "
                           "network requests, prints cleanly to PDF")
    scan.add_argument("--fail-on", choices=library.SEVERITIES + ["none"], default="high",
                      metavar="LEVEL",
                      help="exit 1 when a finding at or above LEVEL is present "
                           "(info|low|medium|high|critical|none; default high)")
    scan.add_argument("--price-per-mtok", type=float, metavar="USD",
                      help="price per million input tokens, to estimate cost per "
                           "conversation; omitted rather than guessed by default")
    scan.add_argument("--out", metavar="PATH", help="write output to a file instead of stdout")

    sub.add_parser("clients", help="list the client config locations this build knows about")

    viewer = sub.add_parser(
        "viewer", help="write the empty HTML viewer; drop a findings.json onto it")
    viewer.add_argument("out", metavar="PATH")

    kit = sub.add_parser(
        "kit", help="write the standalone mcp_collect.py for a customer to run")
    kit.add_argument("out", metavar="PATH")

    demo_cmd = sub.add_parser(
        "demo", help="write a demo report with synthetic findings, to show the output")
    demo_cmd.add_argument("out", metavar="PATH")
    return parser


def kit_digest() -> str:
    """SHA-256 of the vendored collection kit, recorded in every bundle.

    The kit is copied into the package, never imported: the package having one
    source of truth is a maintenance property, but the kit being a standalone
    readable file is what gets it approved. Recording the hash is how a customer
    confirms the script they were sent is the one that produced their bundle.
    """
    return hashlib.sha256(
        Path(html_render.template_path()).parent.parent.joinpath(
            "vendor", "mcp_collect.py").read_bytes()).hexdigest()


def cmd_scan(args: argparse.Namespace) -> int:
    inventory = discover.collect(
        clients=args.client or None,
        explicit_configs=args.config or None,
        project_patterns=args.project or None,
        use_claude_projects=not args.no_project_autodetect,
    )
    contexts = context.resolve_all(inventory)

    if not args.no_connect:
        plan = connect.plan(contexts)
        # Say exactly what will happen before anything happens. This notice is
        # the whole basis on which a security reviewer approves --connect.
        sys.stderr.write(plan.describe() + "\n\n")
        if args.dry_run:
            sys.stderr.write("--dry-run: nothing was started or contacted.\n")
            return EXIT_OK
        if not plan.targets:
            sys.stderr.write("Nothing to contact.\n")
        elif not args.yes and sys.stdin.isatty():
            try:
                if input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
                    sys.stderr.write("Declined. Re-run without --connect for a config-only inventory.\n")
                    return EXIT_OK
            except EOFError:
                return EXIT_OK
        if plan.targets:
            def progress(server):
                sys.stderr.write("  contacting {}...\n".format(server.key))
            connect.execute(plan, contexts, timeout=args.timeout, progress=progress)
            sys.stderr.write("\n")

    report = engine.analyse(inventory, contexts, args.window, args.price_per_mtok)

    if args.bundle:
        collected_at = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        document = bundle.build(
            inventory, collected_at,
            "connect" if not args.no_connect else "config_only",
            salt=args.anonymize, kit_sha256=kit_digest())
        Path(args.bundle).write_text(
            json.dumps(document, indent=2) + "\n", encoding="utf-8")
        sys.stderr.write(bundle.summarise(
            document, args.bundle, Path(args.bundle).stat().st_size))

    if args.findings or args.html:
        generated_at = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        document = findings_json.build(inventory, report, generated_at)
        if args.findings:
            Path(args.findings).write_text(
                json.dumps(document, indent=2) + "\n", encoding="utf-8")
            sys.stderr.write("wrote {}\n".format(args.findings))
        if args.html:
            Path(args.html).write_text(html_render.embed(document), encoding="utf-8")
            sys.stderr.write("wrote {}\n".format(args.html))

    if args.format == "json":
        output = json.dumps(jsonout.inventory_dict(inventory, contexts), indent=2) + "\n"
    else:
        output = text.render(inventory, contexts, args.window, TOOL_NAME, report) + "\n"

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        sys.stderr.write("wrote {}\n".format(args.out))
    else:
        sys.stdout.write(output)

    if args.fail_on != "none":
        triggered = [f for f in report.findings if library.at_or_above(f.severity, args.fail_on)]
        if triggered:
            sys.stderr.write("{} finding(s) at or above {}\n".format(len(triggered), args.fail_on))
            return EXIT_FINDINGS
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
        if args.command == "kit":
            source = Path(html_render.template_path()).parent.parent / "vendor" / "mcp_collect.py"
            Path(args.out).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
            sys.stderr.write("wrote {} (sha256 {})\n".format(args.out, kit_digest()))
            return EXIT_OK
        if args.command == "demo":
            Path(args.out).write_text(
                html_render.embed(demo.document()), encoding="utf-8")
            sys.stderr.write("wrote {} (synthetic data)\n".format(args.out))
            return EXIT_OK
        if args.command == "viewer":
            Path(args.out).write_text(html_render.read_template(), encoding="utf-8")
            sys.stderr.write("wrote {}\n".format(args.out))
            return EXIT_OK
    except KeyboardInterrupt:
        return EXIT_ERROR
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

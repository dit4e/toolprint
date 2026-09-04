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

from . import (TOOL_NAME, __version__, baseline as baseline_mod, bundle, connect,
               context, demo, discover, drift, registry)
from . import effects
from .findings import engine, library
from .render import findings_json, html as html_render, jsonout, sarif, text

EXIT_OK = 0
EXIT_FINDINGS = 1  # reserved for --fail-on in M2
EXIT_ERROR = 2
EXIT_NO_BASELINE = 3  # baseline missing or schema mismatch


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
    scan.add_argument("--startup-timeout", type=float, default=90.0, metavar="SECONDS",
                      help="allowance for a stdio server's FIRST reply, which also "
                           "covers the package manager downloading it (default 90). "
                           "A ceiling, not a delay: a fast server is still fast")
    scan.add_argument("--yes", action="store_true",
                      help="skip the confirmation prompt before contacting servers")
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
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

    for name, help_text in [
        ("baseline", "record the current tool surface as approved"),
        ("check", "compare the current tool surface against the baseline (CI mode)"),
        ("approve", "accept current state into the baseline"),
    ]:
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("--baseline", default=baseline_mod.DEFAULT_PATH, metavar="PATH")
        cmd.add_argument("--config", action="append", default=[], metavar="PATH",
                         help="explicit config file (repeatable); disables auto-discovery. "
                              "Use this to watch a list of servers you do not have installed.")
        cmd.add_argument("--project", action="append", default=[], metavar="PATH")
        cmd.add_argument("--client", action="append", default=[], metavar="NAME",
                         choices=registry.CLIENT_IDS)
        cmd.add_argument("--timeout", type=float, default=15.0, metavar="SECONDS")
        cmd.add_argument("--startup-timeout", type=float, default=90.0, metavar="SECONDS",
                         help="allowance for a stdio server's first reply, covering "
                              "the package manager downloading it (default 90)")
        cmd.add_argument("--yes", action="store_true",
                         help="skip the confirmation prompt before contacting servers")
        # Accepted and ignored. These commands cannot work without live tool
        # definitions, so they always connect - but --connect is the obvious
        # thing to type, and rejecting it turns a correct mental model into a
        # usage error.
        cmd.add_argument("--connect", action="store_true",
                         help="accepted for symmetry with `scan`; these commands "
                              "always retrieve live tool definitions")
        if name == "baseline":
            cmd.add_argument("--force", action="store_true",
                             help="write a baseline even though the current state looks "
                                  "suspicious (see the objections it prints first)")
            cmd.add_argument("--by", metavar="WHO", help="who approved this baseline")
            cmd.add_argument("--note", metavar="TEXT", help="why")
        if name == "check":
            cmd.add_argument("--format", choices=["text", "json", "sarif"], default="text")
            cmd.add_argument("--fail-on", choices=library.SEVERITIES + ["none"],
                             default="high", metavar="LEVEL")
            cmd.add_argument("--min-coverage", type=float, default=80.0, metavar="PCT",
                             help="fail when fewer than PCT%% of baselined servers "
                                  "could be reached (default 80; 0 disables). A check "
                                  "that could not reach the servers has not verified "
                                  "that nothing changed")
            cmd.add_argument("--out", metavar="PATH")
            cmd.add_argument("--findings", metavar="PATH",
                             help="write findings.json with the drift block populated")
            cmd.add_argument("--html", metavar="PATH",
                             help="write a self-contained HTML report including drift")
        if name == "approve":
            cmd.add_argument("--tool", action="append", default=[], metavar="ID",
                             help="approve only this server or server/tool (repeatable); "
                                  "default approves everything currently drifting")
            cmd.add_argument("--by", metavar="WHO")
            cmd.add_argument("--note", metavar="TEXT")
            cmd.add_argument("--refresh", action="store_true",
                             help="re-record every server from the current live "
                                  "state, not only the ones that drifted. Use after "
                                  "a toolprint upgrade adds fields an older baseline "
                                  "does not carry. This accepts any outstanding drift, "
                                  "so read the check output first")

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
            connect.execute(plan, contexts, timeout=args.timeout, progress=progress,
                            startup_timeout=args.startup_timeout)
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

    if args.format == "sarif":
        output = json.dumps(sarif.build(report, inventory), indent=2) + "\n"
    elif args.format == "json":
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


def _collect_live(args: argparse.Namespace):
    """Discover, resolve contexts, and retrieve live tool definitions.

    baseline, check and approve all need the live surface: hashing a config file
    says nothing about what a server actually advertises.
    """
    inventory = discover.collect(
        clients=getattr(args, "client", None) or None,
        explicit_configs=getattr(args, "config", None) or None,
        project_patterns=getattr(args, "project", None) or None,
    )
    contexts = context.resolve_all(inventory)
    plan = connect.plan(contexts)
    sys.stderr.write(plan.describe() + "\n\n")
    if plan.targets and not args.yes and sys.stdin.isatty():
        try:
            if input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
                sys.stderr.write("Declined.\n")
                return inventory, contexts, False
        except EOFError:
            return inventory, contexts, False
    if plan.targets:
        connect.execute(plan, contexts, timeout=args.timeout,
                        startup_timeout=getattr(args, "startup_timeout", None))
    return inventory, contexts, True


def _live_tools(inventory) -> dict:
    """Tool definitions, keyed the way the baseline keys servers."""
    out: dict = {}
    for server in inventory.servers:
        if server.fetch_status == "ok" and server.tools:
            identity = baseline_mod.server_identity(server)
            out.setdefault(identity, {}).update(
                {t["name"]: t for t in server.tools if isinstance(t.get("name"), str)})
    return out


def cmd_baseline(args: argparse.Namespace) -> int:
    inventory, _, proceeded = _collect_live(args)
    if not proceeded:
        return EXIT_OK

    # Trust on first use blesses whatever is there, so refuse to bless a state
    # that already looks tampered with: recording an attack as approved would
    # guarantee it is never reported again.
    objections = baseline_mod.first_baseline_objections(inventory)
    if objections and not args.force:
        sys.stderr.write(
            "Refusing to write a baseline: the current state already looks suspicious.\n"
            "This detects change, not initial badness, so approving now would record\n"
            "the following as normal and never report it again:\n\n")
        for line in objections[:20]:
            sys.stderr.write("  " + line + "\n")
        if len(objections) > 20:
            sys.stderr.write("  ... and {} more\n".format(len(objections) - 20))
        sys.stderr.write("\nInvestigate, or re-run with --force if this is expected.\n")
        return EXIT_FINDINGS

    document = baseline_mod.build(inventory, args.by, args.note)
    if objections:
        document["forced"] = True
        document["objections_at_creation"] = objections
    baseline_mod.save(args.baseline, document)
    servers = document["servers"]
    sys.stderr.write("wrote {}: {} server(s), {} tool(s){}\n".format(
        args.baseline, len(servers),
        sum(len(v["tools"]) for v in servers.values()),
        " (forced over {} objection(s))".format(len(objections)) if objections else ""))
    return EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    document, error = baseline_mod.load(args.baseline)
    if document is None:
        sys.stderr.write("{}\nRun `{} baseline` first.\n".format(error, TOOL_NAME))
        return EXIT_NO_BASELINE

    if document.get("heuristics_version") != effects.HEURISTICS_VERSION:
        # Bumping the verb lists reclassifies tools, which would otherwise be
        # indistinguishable from real drift. Treat it as a re-approval event.
        sys.stderr.write(
            "Baseline was written with heuristics version {}; this build uses {}.\n"
            "Effect classifications may differ for reasons unrelated to the servers.\n"
            "Review and re-run `{} baseline`.\n".format(
                document.get("heuristics_version"), effects.HEURISTICS_VERSION, TOOL_NAME))
        return EXIT_NO_BASELINE

    inventory, contexts, proceeded = _collect_live(args)
    if not proceeded:
        return EXIT_OK

    recorded_platform = document.get("platform")
    if recorded_platform and recorded_platform != sys.platform:
        sys.stderr.write(
            "Note: this baseline was recorded on {!r} and you are checking on {!r}.\n"
            "Some servers describe themselves differently per platform, so a\n"
            "description-only change (DRIFT-003) may be environmental rather than\n"
            "real. Baseline in the environment you check from.\n\n".format(
                recorded_platform, sys.platform))

    active, expired = baseline_mod.active_exceptions(document)
    current = baseline_mod.snapshot(inventory)
    changes = drift.compare(document, current, _live_tools(inventory), active)
    report = engine.analyse(inventory, contexts)
    # Membership changes are not drift - nobody's definitions moved - but they
    # must be visible, because an unbaselined server is being watched against
    # nothing at all.
    new_servers = sorted(set(current) - set(document.get("servers") or {}))
    gone_servers = baseline_mod.dropped(document, current)

    # Unreachable servers produce no drift, because a server missing from one
    # side is skipped rather than compared. So a run that reached almost nothing
    # reports zero changes and exits clean - a green build that verified nothing,
    # which is worse than a red one. Observed live: 22 of 36 servers failed to
    # start during an npm incident and the check passed.
    baselined = len(document.get("servers") or {})
    reached = baselined - len(gone_servers)
    coverage = (100.0 * reached / baselined) if baselined else 100.0

    if args.findings or args.html:
        generated_at = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        document = findings_json.build(inventory, report, generated_at, changes)
        if args.findings:
            Path(args.findings).write_text(
                json.dumps(document, indent=2) + "\n", encoding="utf-8")
            sys.stderr.write("wrote {}\n".format(args.findings))
        if args.html:
            Path(args.html).write_text(html_render.embed(document), encoding="utf-8")
            sys.stderr.write("wrote {}\n".format(args.html))

    if args.format == "sarif":
        output = json.dumps(sarif.build(report, inventory, changes), indent=2) + "\n"
    elif args.format == "json":
        output = json.dumps({
            "baseline": args.baseline,
            "changes": [_change_dict(c) for c in changes],
            "new_servers": new_servers,
            "unwatched_or_unreachable": gone_servers,
            "baselined_servers": baselined,
            "servers_reached": reached,
            "coverage_pct": round(coverage, 1),
            "expired_exceptions": expired,
        }, indent=2) + "\n"
    else:
        output = _render_changes(changes, expired, args.baseline,
                                 new_servers, gone_servers,
                                 recorded_platform, coverage, reached, baselined) + "\n"

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        sys.stderr.write("wrote {}\n".format(args.out))
    else:
        sys.stdout.write(output)

    if args.min_coverage > 0 and coverage < args.min_coverage:
        sys.stderr.write(
            "Only {}/{} baselined servers were reachable ({:.0f}%, below the {:.0f}% "
            "minimum).\nUnreachable servers produce no drift, so this run has not "
            "verified that nothing\nchanged - it has verified almost nothing. Treat "
            "it as inconclusive, not as a pass.\n".format(
                reached, baselined, coverage, args.min_coverage))
        return EXIT_FINDINGS

    if args.fail_on != "none":
        triggered = [c for c in changes
                     if not c.excepted and library.at_or_above(c.severity, args.fail_on)]
        if triggered:
            sys.stderr.write("{} change(s) at or above {}\n".format(
                len(triggered), args.fail_on))
            return EXIT_FINDINGS
    return EXIT_OK


def cmd_approve(args: argparse.Namespace) -> int:
    document, error = baseline_mod.load(args.baseline)
    if document is None:
        sys.stderr.write("{}\n".format(error))
        return EXIT_NO_BASELINE

    inventory, _, proceeded = _collect_live(args)
    if not proceeded:
        return EXIT_OK

    current = baseline_mod.snapshot(inventory)
    active, _ = baseline_mod.active_exceptions(document)
    changes = drift.compare(document, current, _live_tools(inventory), active)

    if args.refresh:
        # A baseline written by an older build carries older fields. server_version
        # arrived in 0.2.0 and stayed empty on existing baselines, because approve
        # only rewrites servers that drifted and there had been no drift. Refresh
        # re-records everything, which necessarily accepts any outstanding drift -
        # hence the explicit flag rather than doing it silently on a version change.
        stamp = baseline_mod.now()
        for identity, record in current.items():
            document.setdefault("servers", {})[identity] = record
        document["generator"] = "toolprint/{}".format(__version__)
        document["heuristics_version"] = effects.HEURISTICS_VERSION
        document["approved_at"] = stamp
        document["approved_by"] = args.by
        baseline_mod.save(args.baseline, document)
        sys.stderr.write(
            "refreshed {} server record(s) into {}{}\n".format(
                len(current), args.baseline,
                "; this accepted {} outstanding change(s)".format(len(changes))
                if changes else ""))
        return EXIT_OK

    if not changes and not baseline_mod.adopt_new(dict(document), current):
        sys.stderr.write("Nothing to approve: no drift against {}.\n".format(args.baseline))
        return EXIT_OK

    selectors = args.tool or []
    stamp = baseline_mod.now()
    approved, skipped = [], []

    for change in changes:
        target = "{}/{}".format(change.server, change.tool) if change.tool else change.server
        if selectors and not any(
                sel in (target, change.server, change.tool) for sel in selectors):
            skipped.append(target)
            continue

        # Approve at the granularity of the change. Replacing the whole server
        # record would silently bless every other change on that server - so
        # approving one benign rename would also approve a concurrent rug pull
        # sitting beside it, with no indication that it had happened.
        stored = document.setdefault("servers", {}).setdefault(change.server, {})
        live = current.get(change.server) or {}

        if change.tool is None:
            for key in ("instructions_hash", "toolset_hash", "transport", "auth_method"):
                if key in live:
                    stored[key] = live[key]
        else:
            tools = stored.setdefault("tools", {})
            if change.rule == "DRIFT-010":
                tools.pop(change.tool, None)      # the tool is gone; forget it
            else:
                record = (live.get("tools") or {}).get(change.tool)
                if record is None:
                    skipped.append(target)
                    continue
                record = dict(record)
                record["approved_at"] = stamp
                record["approved_by"] = args.by
                record["note"] = args.note
                tools[change.tool] = record
        approved.append(target)

    # The toolset hash covers the whole set, so it is only accurate once every
    # change on that server has been accepted.
    for identity in {c.server for c in changes}:
        outstanding = [c for c in changes
                       if c.server == identity and
                       ("{}/{}".format(c.server, c.tool) if c.tool else c.server) not in approved]
        if not outstanding and identity in current:
            document["servers"][identity]["toolset_hash"] = current[identity]["toolset_hash"]

    adopted = baseline_mod.adopt_new(document, current, stamp)
    document["approved_at"] = stamp
    document["approved_by"] = args.by
    baseline_mod.save(args.baseline, document)
    sys.stderr.write("approved {} of {} change(s) into {}\n".format(
        len(approved), len(changes), args.baseline))
    if adopted:
        sys.stderr.write("  adopted {} newly watched server(s): {}\n".format(
            len(adopted), ", ".join(a.split("@")[0] for a in adopted[:6])))
    if skipped:
        sys.stderr.write("  {} change(s) left unapproved and still reported\n".format(
            len(skipped)))
    return EXIT_OK


def _change_dict(change) -> dict:
    return {
        "rule": change.rule, "severity": change.severity, "title": change.title,
        "server": change.server, "tool": change.tool, "detail": change.detail,
        "evidence": change.evidence, "excepted": bool(change.excepted),
        "exception_reason": (change.excepted or {}).get("reason"),
    }


def _render_changes(changes, expired, path: str, new_servers=(), gone_servers=(),
                    recorded_platform=None, coverage=None, reached=None,
                    baselined=None) -> str:
    lines = ["{} {} — drift against {}".format(TOOL_NAME, __version__, path), ""]
    if coverage is not None and baselined and coverage < 100.0:
        lines.append("  Reached {} of {} baselined servers ({:.0f}%). Unreachable servers".format(
            reached, baselined, coverage))
        lines.append("  produce no drift, so anything they changed is invisible to this run.")
        lines.append("")
    if recorded_platform and recorded_platform != sys.platform:
        lines.append("  Baseline recorded on {}; checking on {}. A description-only".format(
            recorded_platform, sys.platform))
        lines.append("  change may reflect the platform rather than the server.")
        lines.append("")
    if not changes:
        # No early return. The informational sections below matter most on a
        # quiet day: a server being watched against nothing looks exactly like a
        # server that has not changed, and only one of those is fine.
        lines.append("  No drift. The tool surface matches the approved baseline.")
        lines.append("")
    live = [c for c in changes if not c.excepted]
    if changes:
        tally: dict = {}
        for change in live:
            tally[change.severity] = tally.get(change.severity, 0) + 1
        lines.append("  {} change(s): {}".format(
            len(live), " · ".join("{} {}".format(n, s) for s, n in sorted(
                tally.items(), key=lambda kv: -library.SEVERITY_ORDER[kv[0]])) or "none active"))
        lines.append("")
        for change in changes:
            mark = "   (accepted exception)" if change.excepted else ""
            lines.append("  [{}] {}  {}{}".format(
                change.severity.upper(), change.rule, change.title, mark))
            lines.append("      {}{}".format(
                change.server, "/" + change.tool if change.tool else ""))
            lines.append("      {}".format(change.detail))
            if change.excepted:
                lines.append("      reason: {} (expires {})".format(
                    change.excepted.get("reason", "-"), change.excepted.get("expires", "-")))
            else:
                lines.append("      fix: {}".format(
                    drift.REMEDIATION.get(change.rule, "").split(". ")[0] + "."))
            lines.append("")
    if new_servers:
        lines.append("  {} server(s) newly watched, not yet in the baseline:".format(
            len(new_servers)))
        for identity in new_servers:
            lines.append("    {}".format(identity))
        lines.append("    Run `approve` to adopt them; until then they are compared")
        lines.append("    against nothing.")
        lines.append("")
    if gone_servers:
        lines.append("  {} baselined server(s) not seen in this run:".format(len(gone_servers)))
        for identity in gone_servers:
            lines.append("    {}".format(identity))
        lines.append("")
    if expired:
        lines.append("  {} exception(s) expired and no longer suppress anything:".format(
            len(expired)))
        for item in expired:
            lines.append("    {} {} — expired {}".format(
                item.get("rule"), item.get("server"), item.get("expires")))
        lines.append("")
    return "\n".join(lines)


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
        if args.command == "baseline":
            return cmd_baseline(args)
        if args.command == "check":
            return cmd_check(args)
        if args.command == "approve":
            return cmd_approve(args)
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

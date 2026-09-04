# toolprint

**What your agent's tool surface costs, and what it can do.**

Point it at a laptop and get back the number of tokens your MCP tools consume on
every request before you type anything, how many of them can delete, send or
spend, and how many of those sit behind no authentication.

Offline. No account. Nothing is transmitted.

```bash
uvx toolprint scan                    # inventory, no network, no subprocesses
uvx toolprint scan --connect          # retrieve live tool definitions
uvx toolprint scan --connect --html report.html
```

---

## Why the numbers are per-context

A conversation loads exactly one client in exactly one project. That pairing is
the only unit in which "what do my tools cost per conversation" has an answer.

Scope precedence is real and mostly invisible: Claude Code resolves local over
project over user, Cursor and VS Code resolve project over user, and in every
case the *whole* entry from the winning scope is used — nothing is merged. So a
machine with 19 configured entries may resolve to 11 distinct servers, of which
one context loads 8. The other 11 entries are not a conservative overestimate;
they describe no state the system is ever in. Entries that lose are reported as
shadowed configuration, because editing one has no effect and produces no
warning.

## What it reports

| | |
|---|---|
| **Cost** | Per-tool and per-context token counts, as a share of your window |
| **Capability** | Every tool classified `read` / `write` / `external` / `irreversible` |
| **Mislabelled tools** | Tools whose safety annotation their own name or schema contradicts |
| **Auth posture** | `none`, `env_var`, `literal_secret`, `helper_command`, `oauth` |
| **Hygiene** | Credentials stored literally in config files, shadowed entries, unreachable servers |
| **Versions** | Which servers your config pins, and what each one claims to be — `npx -y pkg` runs whatever was cached, not the latest release. The claim often disagrees with the package |

Findings carry stable ids (`AUTH-001`, `COST-001`, `HYG-002`, …) with fixed
titles and standard remediation, so two reports are comparable.

## Output

Everything renders from `findings.json`; nothing renders from raw collected data.

```bash
toolprint scan --connect --findings findings.json --html report.html
toolprint viewer report.html      # empty viewer; drop any findings.json on it
toolprint demo demo.html          # synthetic report, to see the output first
```

The HTML report is a single self-contained file. All CSS and JS inline, no CDN,
no fonts, no analytics, and a Content-Security-Policy of `default-src 'none'`
with `connect-src 'none'` — it has no capability to transmit what it displays.
It opens from `file://` and prints cleanly to PDF.

## Drift

Once a baseline exists, `check` reports what changed without anyone reviewing it.

```bash
toolprint baseline --connect --by "$USER" --note "reviewed"
toolprint check --connect --fail-on high
toolprint approve --tool contact_delete --by "$USER" --note "expected in 4.2"
```

Ten rules, most severe first: effect-class escalation and revoked safety
annotations are `critical`; a description that changed while its schema did not
is `high`, because that is the rug-pull signature — an attacker rewriting a
tool's instructions has to leave the schema alone or the tool stops working.
Invisible characters and cross-server references appearing in text are `high`
too. Breaking schema changes and new tools are `medium`; additive changes and
removals are `low`.

**Baselines refuse to bless a suspicious state.** Trust-on-first-use means a
baseline approves whatever is in front of it, so `baseline` inspects the current
surface for invisible characters, homoglyphs and cross-server shadowing first,
and will not write a clean baseline over any of them without `--force`.

**Exceptions require a reason and an expiry.** A suppression that cannot lapse
becomes permanent by neglect, and then nobody reads the report at all. Expired
exceptions stop suppressing and say so in the output.

Hashes are per component — description, schema, annotations — rather than one
blob, because only that split shows the description-moved-schema-didn't
correlation. Canonicalisation normalises structure and never content:
`transfer` and `transfеr` (Cyrillic е) hash differently on purpose, so a
homoglyph substitution is caught rather than normalised away.

## CI

```bash
toolprint scan --format json --fail-on high
toolprint check --format sarif --out toolprint.sarif
```

Exit `0` below the threshold, `1` at or above it, `2` on execution error, `3`
when the baseline is missing or was written by a different heuristics version.

SARIF drops into GitHub code scanning, so findings land as annotations on the
pull request. There is a ready-made action — see
[docs/github-action.md](docs/github-action.md).

## Assessment bundles

`toolprint kit mcp_collect.py` writes a standalone, dependency-free script under
400 lines that someone else can run on their own machine to produce a redacted
bundle. It has exactly one outbound call — reachable only under `--connect`, and
only to their own MCP servers. Redaction is an allowlist in one visible
constant. See [docs/collection-kit-README.md](docs/collection-kit-README.md).

## What it catches, and what it does not

**Catches:** context cost and its distribution · unauthenticated servers exposing
destructive capability · mislabelled tools · credentials in config files ·
shadowed configuration · servers that fail to start.

**Does not catch:** a server that is malicious from the first scan — this
detects change and misconfiguration, not initial badness · a server doing
exactly what it advertises · runtime behaviour that changes without the tool
definition changing · whether a description will actually manipulate a given
model.

It composes with scanners that address the first case rather than replacing
them.

## Install

```bash
uvx toolprint scan          # no install
pipx install toolprint
pip install "toolprint[tokens]"   # optional tiktoken for exact token counts
```

Python 3.9+. The core has no required dependencies. Without `tiktoken`, token
counts use a character ratio calibrated against real tool definitions (4.55
chars/token, ~4% median error), and the method used is recorded per server.

## Why it reports what it reports

[DESIGN.md](DESIGN.md) covers the decisions most likely to surprise you: why
cost is per context, why annotations give a floor and a ceiling, why
canonicalisation refuses to normalise Unicode, and why the drift rules are
ordered as they are.

## Does drift actually happen?

[dit4e/toolprint-watch](https://github.com/dit4e/toolprint-watch) checks 27
public MCP servers daily against an approved baseline and commits what changed,
so the git history of that baseline is an open record of how often tool
definitions move. It is a separate repository so a year of observation commits
does not bury this one.

Worth knowing what it cannot see: of 18 well-known public remote MCP endpoints,
**two** served `tools/list` without credentials. Remote servers are the category
where a definition change is least visible to the people using them — no package
update, no lockfile line — and also the category nobody outside the vendor can
audit. That is an argument for running `toolprint check` in your own CI, where
you already hold the credentials, rather than waiting for someone else to notice.

## Status

Early, but complete through drift. `scan`, `check`, baselines, approvals,
bundles, the HTML viewer and SARIF are built and dogfooded. Opt-in peer
benchmarking is next; `findings.json` already carries the `benchmark` field it
will populate.

## Licence

Apache-2.0.

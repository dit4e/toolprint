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

## CI

```bash
toolprint scan --format json --fail-on high
```

Exit `0` below the threshold, `1` at or above it, `2` on execution error.

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

## Status

Early. `scan`, `report`, bundles and the HTML viewer are built and dogfooded.
Baselines, drift detection and SARIF are next; `findings.json` already carries
the `drift` and `benchmark` fields they will populate.

## Licence

Apache-2.0.

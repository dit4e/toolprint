# The watchlist

A fixed set of public MCP servers, checked daily against an approved baseline.

**The git history of `baseline.json` is the dataset.** Every commit that touches
it is a definition change, with a timestamp and a diff:

```bash
git log -p --follow watchlist/baseline.json
```

`observations.csv` carries the denominator — how many server-days produced no
drift — because a drift rate needs both halves and "we saw three rug pulls" is
meaningless without "out of how many observations".

## How servers were selected

Every entry was verified against the npm or PyPI registry and then **probed**:
it is here only because it actually starts and serves `tools/list` with no
credentials. Nothing was included on the strength of a package name appearing in
a directory.

Deliberately not padded. A larger list built from npm keyword search fills up
with abandoned single-author packages that will never change, which inflates the
denominator and teaches nothing. 27 servers people actually run beats 60 that
include 30 dead ones.

Three groups, on purpose:

| Group | Why |
|---|---|
| Actively published reference servers | `filesystem`, `memory`, `everything`, `sequential-thinking`, `git`, `time`, `fetch`. Released frequently, so they set the baseline rate for routine churn. |
| Archived, frozen reference servers | `puppeteer`, `github`, `postgres`. Last published 2024–2025. **Controls: if these drift, something is wrong.** |
| Vendor and community servers | Where a real rug pull would most plausibly appear. |

## The finding that shaped this list

Of 18 well-known public remote MCP endpoints probed, **two** served `tools/list`
without credentials — DeepWiki and Context7. The other sixteen returned 401 or
403: Linear, Notion, Stripe, Vercel, Sentry, GitHub, Cloudflare, Hugging Face,
PayPal, Grafana, Neon, Prisma, Semgrep, Webflow, Sanity, GitMCP.

That matters more than it first looks. Remote servers are the category where a
definition change is **completely invisible** to the people using them: no
package update, no lockfile line, no local signal at all. And they are also the
category nobody outside the vendor can audit, because `tools/list` is behind
OAuth. The people best placed to detect a remote rug pull are the customers who
already hold credentials — which is an argument for `toolprint check` running in
their CI, not for a public observatory.

So the watchlist is stdio-weighted by necessity, not by preference. That is a
limitation of the dataset and should be stated whenever it is cited.

## Protocol versions observed

Of the servers that responded, one spoke `2026-07-28`, most spoke `2025-11-25`,
and two still spoke `2024-11-05`. The ecosystem is spread across three protocol
eras, twenty months apart.

## Running it by hand

```bash
toolprint baseline --connect --yes --config watchlist/servers.json \
                   --baseline watchlist/baseline.json
toolprint check    --connect --yes --config watchlist/servers.json \
                   --baseline watchlist/baseline.json
```

## Caveats

- Runs on a GitHub-hosted runner, so `npx -y pkg` resolves the latest published
  version each day. Package churn and definition churn are therefore the same
  signal here; distinguishing them needs a pinned second run.
- Only tool *definitions* are observed. A server whose runtime behaviour changes
  without its definitions changing — the postmark-mcp case — is invisible to
  this, and to the tool generally.
- No credentials are used, so servers that gate `tools/list` are absent.

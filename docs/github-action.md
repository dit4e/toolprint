# Running toolprint in CI

SARIF output drops straight into GitHub code scanning, so findings appear as
annotations on the pull request that introduced them rather than in a log
nobody opens.

## Pinning

Examples below pin an exact tag rather than a moving major version. That is
deliberate: a tool that reports on supply-chain drift should not ask you to
trust a tag someone can move under you. Pinning to a commit SHA is stronger
still, and Dependabot will keep either up to date:

```yaml
uses: dit4e/toolprint@v0.1.0
```

## Report the current surface

```yaml
name: toolprint
on: [pull_request]

permissions:
  contents: read
  security-events: write   # required to upload SARIF

jobs:
  toolprint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: toolprint
        uses: dit4e/toolprint@v0.1.0
        with:
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.toolprint.outputs.sarif-file }}
      - name: Fail if findings met the threshold
        if: steps.toolprint.outputs.exit-code == '1'
        run: exit 1
```

Note the ordering: the SARIF is uploaded **before** the job is failed. A job
that dies before upload produces no annotations, which defeats the point of
emitting SARIF at all.

## Check against an approved baseline

Commit a baseline, then have CI fail when the tool surface moves without review:

```bash
toolprint baseline --connect --by "$USER" --note "reviewed 2026-09-01"
git add .toolprint-baseline.json && git commit -m "Approve MCP tool surface"
```

```yaml
      - id: toolprint
        uses: dit4e/toolprint@v0.1.0
        with:
          mode: check
          baseline: .toolprint-baseline.json
          fail-on: high
```

Exit `3` means the baseline is missing or was written by a different
heuristics version — treat that as "needs re-approval", not as a pass.

`check` also fails when it could not reach enough of the baselined servers
(`--min-coverage`, default 80%). Unreachable servers produce no drift, so
without that gate a run during an outage reports zero changes and passes having
verified almost nothing.

## About `connect`

By default the action reads configuration only: no network, no subprocesses.
Setting `connect: true` retrieves live tool definitions, which is where drift
detection gets its data — but it starts stdio servers, so only enable it where
that is appropriate. Config-only mode still reports auth posture, shadowed
configuration and credentials committed to config files.

## Suppressing a known change

Add an exception to the baseline rather than lowering `fail-on`. Exceptions
require a reason and an expiry, so a standing suppression cannot become
permanent by neglect:

```json
{
  "exceptions": [
    {
      "server": "crm@http:crm.internal",
      "tool": "contact_export",
      "rule": "DRIFT-009",
      "reason": "pagination params added in the 4.2 release",
      "expires": "2026-12-31"
    }
  ]
}
```

Expired exceptions stop suppressing and are listed in the output, so you find
out they lapsed from the report rather than from an incident.

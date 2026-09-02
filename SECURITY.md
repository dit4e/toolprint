# Security

## Reporting a vulnerability

Report privately through [GitHub Security Advisories](https://github.com/dit4e/toolprint/security/advisories/new).
Please do not open a public issue for a vulnerability.

Expect an acknowledgement within a few working days. This is a small project;
if something is being actively exploited, say so in the subject line.

## What this tool does that is security-relevant

Worth knowing before you run it, and worth stating plainly since the whole
premise is that MCP servers deserve scrutiny.

- **`--connect` starts your MCP servers.** For stdio servers that means running
  the command in your config, the same way your MCP client already does. The
  tool prints exactly what it will start before starting anything, and
  `--dry-run` shows that list without running it. Without `--connect` it reads
  config files only: no network, no subprocesses.
- **It reads credentials to use them.** Connecting to an authenticated server
  means passing the credential from your config or environment to that server.
  It never writes credential values to output: reports carry environment
  variable and header *names* only, and a server's own error text is scanned for
  the values passed to it before anything is written.
- **Reports contain your tool surface.** `findings.json`, bundles and HTML
  reports contain server names, tool names, descriptions and schemas. That is
  the substance of an assessment and it is as sensitive as the deployment it
  describes. The HTML viewer is entirely client-side and has no capability to
  transmit what it displays; check the Content-Security-Policy in its `<head>`.
- **It treats server output as untrusted.** Tool names and descriptions come
  from the party being assessed. They are never executed, never interpolated
  into markup, and never Unicode-normalised — normalising would erase the
  homoglyph and invisible-character attacks the tool exists to surface.

## What is in scope

- A credential, absolute path or other sensitive value reaching any output file
- Any path by which server-supplied content is executed, injected into a
  rendered report, or escapes the JSON data block in the HTML viewer
- The collection kit (`mcp_collect.py`) transmitting anything anywhere; it has
  exactly one outbound call, only under `--connect`, only to your own servers
- Canonicalisation collapsing a difference it should preserve — two materially
  different tool definitions hashing the same

## What is not

- A malicious MCP server doing exactly what it advertises. This detects change
  and misconfiguration, not initial badness.
- Runtime behaviour that changes without the tool definition changing.
- Findings you disagree with. Open an issue instead; false positives are bugs
  worth fixing, but they are not vulnerabilities.

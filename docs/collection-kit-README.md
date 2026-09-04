# `mcp_collect.py` — what it collects, and what it does not

You have been asked to run one Python script on a machine that uses MCP servers.
It writes a single JSON file describing what is configured there. You read that
file, and you decide whether to send it.

This README exists to be reviewed. If your security team reads one thing, make
it the two lists below and the script's own header.

---

## The short version

| | |
|---|---|
| **Language** | Python 3.9+, standard library only. Nothing is installed. |
| **Length** | Under 425 lines including comments. It is meant to be read. |
| **Network** | None by default. With `--connect`, only your own MCP servers. |
| **Can it upload?** | No. There is no code path that sends the output anywhere. |
| **Output** | One JSON file in your working directory. |

---

## What it collects

- MCP server names, and which client each was configured in
- Transport type (`stdio`, `http`, `sse`, `ws`)
- The **basename** of any command — `npx`, `uvx`, `python` — never the full line
- The **hostname** of any remote server — never the path or query string
- The **name and version each server reports for itself**. `npx -y pkg` does not
  mean the latest release, it means whatever the package manager last cached, so
  the config alone says nothing about which build ran. Note this is the server's
  own claim and often disagrees with its package version
- The **names** of environment variables and HTTP headers used for authentication
- Whether authentication is absent, an environment reference, a literal value in
  the config file, OAuth, or produced by a helper command
- With `--connect`: the tool definitions each server advertises — tool names,
  descriptions and JSON schemas
- Any config file it could not read, recorded as an error rather than hidden

## What it never collects

- Environment variable **values**
- HTTP header **values**
- API keys, tokens, passwords or credentials of any kind
- Full command lines or arguments
- Absolute file paths
- URL paths or query strings
- Your username, machine hostname, or any identifier of the machine
- The contents of any file, request, or response

**Why you can check this quickly.** Redaction is an *allowlist*, defined in one
constant called `EMITTED_FIELDS` near the top of the script. Only fields named
there are written. A denylist — "strip anything that looks like a secret" — fails
open and cannot be verified by reading. An allowlist fails closed, and you can
confirm it in thirty seconds by reading one constant.

**Why tool definitions are included in full.** They are the substance of the
assessment, and they are already what the language model sees on every request.
If a tool description contains something sensitive, that is itself a finding.

---

## It cannot transmit

This is an architectural property, not a policy, and you can verify it:

```bash
grep -n "urlopen\|requests\.\|socket\|smtplib\|ftplib" mcp_collect.py
```

There is exactly one outbound call in the file — `urlopen()` inside
`http_call()` — it runs only under `--connect`, and it posts only to the MCP
endpoints already configured on the machine. There is no HTTP POST to us, no
telemetry, no "anonymous usage statistics", no auto-upload.

A script that uploads is a data-exfiltration tool from a reviewer's point of
view. A script that writes a local file is a report generator. The data is
identical; only the second one is approvable. This is the second one.

---

## Running it

```bash
python3 mcp_collect.py
```

Config files only. No network, no subprocesses. This works everywhere and needs
no explanation to anyone.

```bash
python3 mcp_collect.py --connect
```

Additionally asks each server for its tool list. For remote servers this is an
HTTPS request using credentials already present in your environment or config.
For `stdio` servers **this starts the server process** — the same way your MCP
client already starts it, on your own machine, with a server you already chose to
run. The script prints exactly what it will start before starting anything.

```bash
python3 mcp_collect.py --connect --dry-run
```

Prints exactly what *would* be started or contacted, and then stops without
starting, contacting or writing anything. Run this first.

### Other flags

| Flag | Effect |
|---|---|
| `--anonymize SALT` | Replaces server names and hostnames with salted HMACs. You keep the salt; the bundle stays internally consistent for analysis but is not identifying. |
| `--config PATH` | Read an explicit config file. Repeatable. Disables auto-discovery. |
| `--out PATH` | Where to write the bundle. Default `mcp-bundle.json`. |

### If you cannot approve `--connect`

Run it without. You still get the full inventory, transports and authentication
posture, and the assessment still covers everything that does not require
reading tool definitions. Do not treat this as all-or-nothing.

---

## Sample `--dry-run` output

```
--connect will start 4 local server process(es) - the same way your MCP
client already starts them, on this machine, with servers you already chose
to run - and contact 2 remote endpoint(s):

    $ npx -y @modelcontextprotocol/server-filesystem .
    $ npx -y @modelcontextprotocol/server-memory
    $ uvx mcp-server-time --local-timezone=America/New_York
    $ npx -y @upstash/context7-mcp@latest
    HTTP mcp.example.com
    HTTP api.internal.example

--dry-run: 6 server(s) across 2 client(s). Nothing was started, contacted
or written.
```

## What a completed run prints

```
Bundle written: mcp-bundle.json (61,204 bytes)
  6 server(s), 78 tool definition(s)
  mode: connect

DATA POLICY

  This bundle contains: MCP server names, source client, transport type,
  command basenames, remote hostnames, the NAMES of auth environment
  variables and headers, and the full tool definitions each server
  advertises.
  It does NOT contain: environment variable values, header values, API keys,
  tokens or passwords; full command lines or arguments; absolute file paths;
  URL paths or query strings; your username or machine hostname; or the
  contents of any file, request or response.

Review this file before sending it. It contains exactly what is listed
above and nothing else.
```

---

## The bundle describes itself

Every bundle embeds the script's version, the SHA-256 of the exact script that
produced it, the collection mode, and the data policy above — verbatim. When
someone asks three weeks later what was in that file, the file answers.

Verify the script you were sent matches the hash in the bundle:

```bash
shasum -a 256 mcp_collect.py
```

---

## Before you send it

Open the file. It is JSON, and it is meant to be read. Search it for anything
you would not want to share — a token, a username, a path. If you find one, that
is a bug in this script and we want to hear about it before you send anything.

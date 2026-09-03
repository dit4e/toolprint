#!/usr/bin/env python3
"""mcp_collect.py - describe this machine's MCP setup, for assessment.
Reads your MCP client config files and writes ONE local JSON file describing what
is installed. With --connect it also asks each server for its list of tools.
IT CANNOT SEND ANYTHING ANYWHERE. No upload, no telemetry, no phone-home. It
writes a local file; you read it and you decide whether to send it. That is an
architectural fact, not a promise: the only outbound call in this file is the
single urlopen() in http_call(), it runs only under --connect, and it goes only
to YOUR OWN MCP servers. Grep for urlopen - two hits, this line and that call.
COLLECTS  server names, source client, transport, the BASENAME of any command
          ("npx"), the HOSTNAME of any remote server, the NAMES of auth
          environment variables and headers, the name and version each server
          reports for itself, and - with --connect - its tool definitions.
NEVER COLLECTS  environment variable values, header values, API keys, tokens
          or passwords; full command lines or arguments; absolute file paths;
          URL paths or query strings; your username or machine hostname; the
          contents of any file, request or response.
Redaction is an ALLOWLIST: only fields named in EMITTED_FIELDS below are written,
so nothing outside it can reach the output, including fields added later. Read
that one constant and you know the whole story.
USAGE   python3 mcp_collect.py            config only: no network, no subprocesses
        python3 mcp_collect.py --connect  also ask each server for its tools
        --dry-run shows what would run without running it; --anonymize SALT
        hashes names; --config PATH reads a file; --out PATH sets the output.
        Python 3.9+, standard library only, nothing is installed.
"""
import argparse, glob, hashlib, hmac, json, os, platform, re, shutil, subprocess, sys, textwrap, threading
from datetime import datetime
from urllib import error as urlerror, request as urlrequest

KIT_VERSION, BUNDLE_VERSION, TIMEOUT = "0.1.0", 1, 15.0
PROTOCOL_VERSION = "2026-07-28"   # revision that removed the initialize handshake
LEGACY_VERSION = "2025-11-25"     # newest revision that still requires initialize

EMITTED_FIELDS = {
    "server": ["name", "source_client", "scope", "transport", "command_basename",
               "auth_method", "auth_env_names", "auth_header_names", "url_host",
               "fetch_status", "protocol_version", "protocol_era",
               "server_name", "server_version", "version_pinned"],
    "tool": ["name", "title", "description", "inputSchema", "outputSchema",
             "annotations", "token_estimate", "token_method"],
}

DATA_POLICY = (
    "This bundle contains: MCP server names, source client, transport type, command "
    "basenames, remote hostnames, the NAMES of auth environment variables and headers, "
    "the name and version each server reports for itself, and the full tool "
    "definitions each server advertises.\n"
    "It does NOT contain: environment variable values, header values, API keys, tokens "
    "or passwords; full command lines or arguments; absolute file paths; URL paths or "
    "query strings; your username or machine hostname; or the contents of any file, "
    "request or response."
)
# Where each client keeps MCP config, and where in the JSON the servers live; "*"
# fans out over every key. Verified 2026-08-31 - these paths move between client
# releases, so re-check them rather than trusting this list.
CLIENTS = [
    ("claude_code", "~/.claude.json", ["mcpServers"]),
    ("claude_code", "~/.claude.json", ["projects", "*", "mcpServers"]),
    ("claude_code", "./.mcp.json", ["mcpServers"]),
    ("claude_desktop", "~/Library/Application Support/Claude/claude_desktop_config.json", ["mcpServers"]),
    ("claude_desktop", "~/AppData/Roaming/Claude/claude_desktop_config.json", ["mcpServers"]),
    ("claude_desktop", "~/.config/Claude/claude_desktop_config.json", ["mcpServers"]),
    ("cursor", "~/.cursor/mcp.json", ["mcpServers"]),
    ("cursor", "./.cursor/mcp.json", ["mcpServers"]),
    ("vscode", "./.vscode/mcp.json", ["servers"]),          # note: "servers", not "mcpServers"
    ("vscode", "~/Library/Application Support/Code/User/mcp.json", ["servers"]),
    ("vscode", "~/.config/Code/User/mcp.json", ["servers"]),
    ("vscode", "~/AppData/Roaming/Code/User/mcp.json", ["servers"]),
    ("copilot", "~/.copilot/mcp-config.json", ["mcpServers"]),
    ("windsurf", "~/.codeium/windsurf/mcp_config.json", ["mcpServers"]),
    ("gemini_cli", "~/.gemini/settings.json", ["mcpServers"]),
]

CREDENTIAL_WORDS = ("TOKEN", "KEY", "APIKEY", "SECRET", "PASSWORD", "PASS",
                    "CREDENTIAL", "AUTH", "PAT", "SESSION", "BEARER")
NAME_TOKENS = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")
ENV_REF = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*")

def basename(command):
    """'/opt/homebrew/bin/npx' -> 'npx'. Full paths carry usernames."""
    return command.replace("\\", "/").rstrip("/").split("/")[-1] if command else None

def host_only(url):
    """'https://x.io/mcp?token=..' -> 'x.io'. Tokens hide in paths and queries."""
    return url.split("://", 1)[1].split("/", 1)[0].split("@")[-1] \
        if url and "://" in url else None

def is_credential_name(name):
    """True for CONTEXT7_API_KEY and apiKey; false for X-Monkey-Id and CACHE_DIR."""
    if name.lower() in ("authorization", "cookie", "proxy-authorization"):
        return True
    return bool({t.upper() for t in NAME_TOKENS.split(name) if t}.intersection(CREDENTIAL_WORDS))

def auth_method(entry):
    """How this server authenticates. Reads values; emits only the verdict."""
    pairs = [(k, v) for field in ("headers", "env")
             for k, v in (entry.get(field) or {}).items()
             if isinstance(entry.get(field), dict)]
    if entry.get("headersHelper"):
        return "helper_command"
    if isinstance(entry.get("oauth"), dict):
        return "oauth"
    for name, value in pairs:   # names only ever leave this function
        if isinstance(value, str) and is_credential_name(name):
            # "${VAR}" is hygienic; a literal value sitting in a config file is not.
            return "env_var" if ENV_REF.search(value) else "literal_secret"
    return "none"

def expand(value):
    """Resolve ${VAR} / ${VAR:-default} from the environment. --connect only."""
    def sub(m):
        name, _, default = m.group(0).strip("${}").partition(":-")
        return os.environ.get(name, default or m.group(0))
    return ENV_REF.sub(sub, value)

def anonymise(value, salt, prefix):
    """Salted HMAC: an unsalted hash of 'github' falls to a dictionary. You keep the salt."""
    if not value or not salt:
        return value
    mac = hmac.new(salt.encode("utf-8"), value.encode("utf-8"), hashlib.sha256)
    return "{}-{}".format(prefix, mac.hexdigest()[:12])

def walk(doc, steps):
    """Yield each server-group the path selects. '*' fans out over keys."""
    if not isinstance(doc, dict):
        return
    if not steps:
        yield doc
        return
    branches = doc.values() if steps[0] == "*" else ([doc[steps[0]]] if steps[0] in doc else [])
    for branch in branches:
        for found in walk(branch, steps[1:]):
            yield found

def collect_configs(explicit, errors):
    """Return [(client, scope, name, entry)] from every config file found."""
    sources = CLIENTS if not explicit else [
        ("explicit", p, k) for p in explicit for k in (["mcpServers"], ["servers"])]
    found = []
    for client, pattern, steps in sources:
        raw = pattern if explicit else (os.path.join(os.getcwd(), pattern[2:])
              if pattern.startswith("./") else os.path.expanduser(pattern))
        for path in (sorted(glob.glob(raw)) if any(c in raw for c in "*?[") else [raw]):
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    doc = json.load(handle)
            except (OSError, ValueError) as exc:
                # Failures are data: "three configs unreadable" is itself a finding.
                errors.append({"kind": "unreadable_or_malformed", "client": client,
                               "detail": str(exc)[:160]})
                continue
            scope = "project" if pattern.startswith("./") else "user"
            for group in walk(doc, steps):
                for name, entry in group.items():
                    if isinstance(entry, dict):
                        found.append((client, scope, name, entry))
    return found

def transport_of(entry):
    declared = entry.get("type")
    if isinstance(declared, str) and declared.lower() in ("stdio", "http", "sse", "ws"):
        return declared.lower()
    url = entry.get("url") or ""
    return "stdio" if entry.get("command") else (
        "ws" if url.startswith(("ws://", "wss://")) else ("http" if url else "unknown"))

def rpc(method, version, params=None):
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": dict(params or {})}
    if version >= PROTOCOL_VERSION:   # stateless era carries its version in _meta
        body["params"]["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "mcp_collect", "version": KIT_VERSION}}
    return body

def parse_rpc(text):
    """Accept a plain JSON body or an SSE stream; servers may answer with either."""
    text = (text or "").strip()
    blocks = re.split(r"\n\s*\n", text) if text.startswith(("event:", "data:")) else [text]
    for block in blocks:
        data = "".join(l[5:].strip() for l in block.splitlines() if l.startswith("data:")) or block
        try:
            message = json.loads(data)
        except ValueError:
            continue
        if isinstance(message, dict):
            return message
    return {}  # not JSON-RPC at all; the caller records it as a failed fetch

def http_call(url, headers, method, version, params=None, session=None):
    """The ONLY outbound network call in this file, and only to your own server."""
    sent = {k: expand(v) for k, v in (headers or {}).items()}
    # The version header must match the body or servers reject the request.
    sent.update({"Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream",
                 "MCP-Protocol-Version": version, "Mcp-Method": method})
    if session:
        sent["Mcp-Session-Id"] = session
    req = urlrequest.Request(url, data=json.dumps(rpc(method, version, params)).encode("utf-8"),
                             headers=sent, method="POST")
    try:
        with urlrequest.urlopen(req, timeout=TIMEOUT) as response:      # <-- outbound call
            return parse_rpc(response.read().decode("utf-8", "replace")), \
                   response.headers.get("Mcp-Session-Id")
    except urlerror.HTTPError as exc:
        if exc.code in (401, 403):
            raise RuntimeError("auth_required")
        return parse_rpc(exc.read().decode("utf-8", "replace") if exc.fp else ""), None
    except (urlerror.URLError, OSError) as exc:
        raise RuntimeError("unreachable: {}".format(exc)[:120])

class Stdio(object):
    """Runs the server as a subprocess, exactly as your MCP client already does."""
    def __init__(self, command, args, env):
        environ = dict(os.environ, **{k: expand(v) for k, v in (env or {}).items()})
        self.proc = subprocess.Popen([command] + list(args), stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env=environ, text=True, bufsize=1)
        self.err = []
        # Servers log freely to stderr; an unread pipe would deadlock the process.
        threading.Thread(target=lambda: [self.err.append(l.rstrip()) for l in self.proc.stderr],
                         daemon=True).start()
    def request(self, method, version, params=None):
        self.proc.stdin.write(json.dumps(rpc(method, version, params)) + "\n")
        self.proc.stdin.flush()
        result = {}
        def read():
            for line in self.proc.stdout:
                try:                # some servers print non-MCP noise on stdout
                    m = json.loads(line.strip())
                except ValueError:
                    continue
                if isinstance(m, dict) and m.get("id") == 1:
                    return result.update(m)
        reader = threading.Thread(target=read, daemon=True)
        reader.start(); reader.join(TIMEOUT)
        if not result:
            raise RuntimeError((self.err[-1] if self.err else "no response")[:120])
        return result
    def close(self):
        try:                        # closing stdin is the portable shutdown signal
            self.proc.stdin.close()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()

def server_info(message):
    """The server's self-reported identity: in every result's _meta on modern
    revisions, from the initialize handshake on older ones."""
    result = message.get("result") if isinstance(message, dict) else None
    meta = (result.get("_meta") or {}) if isinstance(result, dict) else {}
    info = meta.get("io.modelcontextprotocol/serverInfo") or (
        result.get("serverInfo") if isinstance(result, dict) else None)
    return info if isinstance(info, dict) else {}


def version_is_pinned(args):
    """`npx -y pkg` does not mean latest: the package manager serves a cached
    copy when it has one, so an unpinned config runs whatever it last fetched."""
    return any(isinstance(a, str) and not a.startswith("-") and
               (re.search(r"[=~!<>]=+\s*[0-9]", a) or
                re.match(r"^@?[^@\s]+/?[^@\s]*@(?!latest$|next$|beta$)[0-9]", a))
               for a in args or ())


def negotiate(probe):
    """Pick a version, then let the version decide the era. A server can answer
    server/discover correctly and still speak only pre-2026-07-28 versions, which
    need the initialize handshake; deciding from the error code instead talks to
    such a server as if it were stateless, and it rejects the request."""
    supported = (probe.get("result") or {}).get("supportedVersions") or \
                ((probe.get("error") or {}).get("data") or {}).get("supported") or []
    version = PROTOCOL_VERSION if PROTOCOL_VERSION in supported else (
        max(supported) if supported else LEGACY_VERSION)
    return version, ("modern" if version >= PROTOCOL_VERSION else "legacy")

def fetch_tools(entry, transport):
    """Return (status, version, era, tools, info). Records failures; never raises."""
    conn, info = None, {}
    try:
        url, headers, session = entry.get("url"), entry.get("headers"), None
        if transport == "stdio":
            command = entry.get("command")
            if not command or not (shutil.which(command) or os.path.exists(command)):
                return "unreachable", None, None, [], {}   # command not installed
            conn = Stdio(command, entry.get("args") or [], entry.get("env"))
            probe = conn.request("server/discover", PROTOCOL_VERSION)
        elif transport in ("http", "sse"):
            probe, session = http_call(url, headers, "server/discover", PROTOCOL_VERSION)
        else:
            return "unsupported", None, None, [], {}
        version, era = negotiate(probe)
        info = server_info(probe)
        if era == "legacy":
            params = {"protocolVersion": version, "capabilities": {},
                      "clientInfo": {"name": "mcp_collect", "version": KIT_VERSION}}
            reply = (conn.request("initialize", version, params) if conn else
                     http_call(url, headers, "initialize", version, params, session)[0])
            info = server_info(reply) or info
        reply = conn.request("tools/list", version) if conn else \
            http_call(url, headers, "tools/list", version, None, session)[0]
        result = reply.get("result")
        if not isinstance(result, dict):   # answered, but not with a tools/list
            return "not_mcp", None, None, [], {}
        tools = [t for t in (result.get("tools") or []) if isinstance(t, dict)]
        return "ok", version, era, tools, info
    except RuntimeError as exc:
        return ("auth_required" if str(exc) == "auth_required" else "error"), None, None, [], {}
    except Exception:
        return "error", None, None, [], {}
    finally:
        if conn:
            conn.close()

def token_counter():
    """tiktoken if importable, else a ratio measured against 91 real tool
    definitions: 4.55 chars/token, ~4% median error. Re-measure, do not re-reason."""
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
        return lambda text: (len(enc.encode(text)), "tiktoken")
    except Exception:
        return lambda text: (int(round(len(text) / 4.55)), "approximation")

def tool_record(tool, count):
    """Build one tool entry, from the allowlist only."""
    fields = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
    estimate, method = count(json.dumps({k: tool[k] for k in fields if k in tool},
                                        sort_keys=True, separators=(",", ":")))
    extra = {"token_estimate": estimate, "token_method": method}
    return {f: (extra[f] if f in extra else tool[f])
            for f in EMITTED_FIELDS["tool"] if f in extra or f in tool}

def build(entries, connect, salt, errors):
    """Assemble the bundle. Every server field comes from the allowlist."""
    servers, count = [], token_counter()
    for client, scope, name, entry in sorted(entries, key=lambda e: (e[0], e[1], e[2])):
        transport = transport_of(entry)
        status, version, era, tools, info = ("not_attempted", None, None, [], {})
        if connect:
            status, version, era, tools, info = fetch_tools(entry, transport)
        values = {"name": anonymise(name, salt, "server"), "source_client": client,
                  "scope": scope, "transport": transport, "fetch_status": status,
                  "command_basename": basename(entry.get("command")), "protocol_era": era,
                  "auth_method": auth_method(entry), "protocol_version": version,
                  "auth_env_names": sorted((entry.get("env") or {}).keys()),
                  "auth_header_names": sorted((entry.get("headers") or {}).keys()),
                  "url_host": anonymise(host_only(entry.get("url")), salt, "host"),
                  "server_name": anonymise(info.get("name"), salt, "impl"),
                  "server_version": info.get("version"),
                  "version_pinned": version_is_pinned(entry.get("args"))}
        record = {f: values[f] for f in EMITTED_FIELDS["server"]}
        record["tools"] = [tool_record(t, count) for t in tools]
        servers.append(record)
    with open(os.path.abspath(__file__), "rb") as handle:
        kit_sha = hashlib.sha256(handle.read()).hexdigest()
    return {"bundle_version": BUNDLE_VERSION, "kit_version": KIT_VERSION,
            "kit_sha256": kit_sha, "mode": "connect" if connect else "config_only",
            "collected_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "anonymized": bool(salt), "data_policy": DATA_POLICY,
            "platform": {"os": sys.platform, "python": platform.python_version()},
            "clients_found": sorted({s["source_client"] for s in servers}),
            "servers": servers, "usage": [], "collection_errors": errors}

def main(argv=None):
    parser = argparse.ArgumentParser(description="Describe this machine's MCP setup. "
                                     "Writes a local file; cannot send anything anywhere.")
    add = parser.add_argument
    add("--connect", action="store_true", help="also ask each server for its tools")
    add("--dry-run", action="store_true", help="print what would happen; write nothing")
    add("--anonymize", metavar="SALT", help="hash server names and hostnames")
    add("--config", action="append", default=[], metavar="PATH", help="explicit config file")
    add("--out", default="mcp-bundle.json", metavar="PATH", help="output path")
    args = parser.parse_args(argv)
    errors = []
    entries = collect_configs(args.config, errors)
    if args.connect:
        # Say exactly what will happen before any of it happens.
        spawns = [e for e in entries if transport_of(e[3]) == "stdio"]
        print("--connect will start {} local server process(es) - the same way your MCP\n"
              "client already starts them, on this machine, with servers you already chose\n"
              "to run - and contact {} remote endpoint(s):\n".format(
                  len(spawns), len(entries) - len(spawns)))
        for _, _, _, entry in entries:
            kind = transport_of(entry)
            print("    $ {} {}".format(entry.get("command"), " ".join(entry.get("args") or []))
                  if kind == "stdio" else
                  "    {} {}".format(kind.upper(), host_only(entry.get("url"))))
        print("")
    if args.dry_run:
        print("--dry-run: {} server(s) across {} client(s). Nothing was started, contacted "
              "or written.".format(len(entries), len({e[0] for e in entries})))
        return 0
    bundle = build(entries, args.connect, args.anonymize, errors)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(bundle, handle, indent=2)
        handle.write("\n")
    print("\nBundle written: {} ({:,} bytes)\n  {} server(s), {} tool definition(s)"
          "\n  mode: {}{}{}\n\nDATA POLICY\n".format(
              args.out, os.path.getsize(args.out), len(bundle["servers"]),
              sum(len(s["tools"]) for s in bundle["servers"]), bundle["mode"],
              ", anonymized" if args.anonymize else "",
              "\n  {} config file(s) unreadable (recorded in the bundle)".format(len(errors))
              if errors else ""))
    for line in DATA_POLICY.split("\n"):
        print(textwrap.fill(line, 78, initial_indent="  ", subsequent_indent="  "))
    print("\nReview this file before sending it. It contains exactly what is listed\n"
          "above and nothing else.\n")
    return 0

if __name__ == "__main__":
    sys.exit(main())

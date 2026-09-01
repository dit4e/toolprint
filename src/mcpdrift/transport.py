"""Transports for --connect. Only reached when the user explicitly opts in.

Two implementations behind one tiny interface: send a JSON-RPC request, get a
result or an error back. Everything era- and method-specific lives in protocol.py
so that this file stays about bytes on a wire and process lifecycle.

The 2026-07-28 revision made MCP stateless - no initialize handshake, no session
id, no ping - so a transport here has no connection state to manage beyond the
stdio subprocess itself.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
from typing import Any, Dict, List, Optional, Tuple
from urllib import error as urlerror
from urllib import request as urlrequest

PROTOCOL_VERSION = "2026-07-28"
DEFAULT_TIMEOUT = 15.0

# ${VAR}, ${VAR:-default} and bare $VAR, as supported by Claude Code configs.
_EXPANSION = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")


class TransportError(Exception):
    """Carries a fetch_status so callers record failures as data, not exceptions."""

    def __init__(self, status: str, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def expand(value: str, env: Optional[Dict[str, str]] = None) -> str:
    """Expand ${VAR}, ${VAR:-default} and $VAR from the environment."""
    source = dict(os.environ)
    if env:
        source.update(env)

    def replace(match: "re.Match") -> str:
        name = match.group(1) or match.group(3)
        default = match.group(2)
        if name in source:
            return source[name]
        return default if default is not None else match.group(0)

    return _EXPANSION.sub(replace, value)


class Transport:
    def request(self, method: str, params: Dict[str, Any], timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
        raise NotImplementedError

    def close(self) -> None:
        pass

    @property
    def description(self) -> str:
        raise NotImplementedError


class HttpTransport(Transport):
    """Streamable HTTP, 2026-07-28 shape.

    Every POST carries MCP-Protocol-Version, Mcp-Method and an Accept listing both
    JSON and SSE. The version header must match _meta in the body or the server
    returns -32020. A response may be a single JSON object or an SSE stream even
    for a plain tools/list, so both are handled.
    """

    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None):
        self.url = url
        self.headers = {k: expand(v) for k, v in (headers or {}).items()}
        self._id = 0
        # Removed in 2026-07-28, but legacy servers still mint one on initialize
        # and reject subsequent requests without it.
        self.session_id: Optional[str] = None
        # The version to advertise in the MCP-Protocol-Version header. Legacy
        # `initialize` params carry no _meta, so without this the header stays
        # pinned at the newest version while the body asks for an older one - and
        # servers validate the header. Callers set this as they negotiate down.
        self.protocol_version = PROTOCOL_VERSION

    @property
    def description(self) -> str:
        from urllib.parse import urlsplit

        return "HTTP POST to {}".format(urlsplit(self.url).netloc)

    def request(self, method: str, params: Dict[str, Any], timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
        self._id += 1
        body = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        version = params.get("_meta", {}).get(
            "io.modelcontextprotocol/protocolVersion", self.protocol_version
        )
        headers = dict(self.headers)
        headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": version,
            "Mcp-Method": method,
        })
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        request = urlrequest.Request(
            self.url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST"
        )
        try:
            with urlrequest.urlopen(request, timeout=timeout) as response:
                payload = response.read().decode("utf-8", "replace")
                content_type = response.headers.get("Content-Type", "")
                minted = response.headers.get("Mcp-Session-Id")
                if minted:
                    self.session_id = minted
        except urlerror.HTTPError as exc:
            payload = exc.read().decode("utf-8", "replace") if exc.fp else ""
            if exc.code in (401, 403):
                raise TransportError("auth_required", "HTTP {}".format(exc.code))
            # A modern server uses 400 for real protocol errors; surface the body
            # so the era probe can tell "modern but wrong version" from "legacy".
            parsed = _first_message(payload, "")
            if parsed is not None:
                return parsed
            raise TransportError("error", "HTTP {}".format(exc.code))
        except urlerror.URLError as exc:
            raise TransportError("unreachable", str(exc.reason))
        except OSError as exc:
            raise TransportError("unreachable", str(exc))

        message = _first_message(payload, content_type)
        if message is None:
            raise TransportError("error", "no JSON-RPC message in response")
        return message


    def notify(self, method: str, params: Dict[str, Any]) -> None:
        """Legacy handshake completion. A 202 with no body is the success case."""
        headers = dict(self.headers)
        headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": self.protocol_version,
            "Mcp-Method": method,
        })
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params})
        request = urlrequest.Request(
            self.url, data=body.encode("utf-8"), headers=headers, method="POST"
        )
        try:
            urlrequest.urlopen(request, timeout=DEFAULT_TIMEOUT).read()
        except (urlerror.URLError, OSError):
            pass  # notifications are best-effort


class StdioTransport(Transport):
    """Newline-delimited JSON-RPC over a subprocess's stdin/stdout.

    This spawns the server the same way the user's MCP client already does, on
    their own machine, with a server they already chose to run. The caller prints
    exactly what will be spawned before this is constructed.
    """

    def __init__(self, command: str, args: List[str], env: Optional[Dict[str, str]] = None, cwd: Optional[str] = None):
        self.command = command
        self.args = list(args)
        self.env = {k: expand(v) for k, v in (env or {}).items()}
        self.cwd = cwd
        self._process: Optional[subprocess.Popen] = None
        self._stderr: List[str] = []
        self._id = 0

    @property
    def description(self) -> str:
        return " ".join([self.command] + self.args)

    def _start(self) -> subprocess.Popen:
        if self._process is not None:
            return self._process
        if shutil.which(self.command) is None and not os.path.exists(self.command):
            raise TransportError("unreachable", "command not found: {}".format(self.command))
        environ = dict(os.environ)
        environ.update(self.env)
        try:
            process = subprocess.Popen(
                [self.command] + self.args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environ,
                cwd=self.cwd,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            raise TransportError("unreachable", str(exc))

        # Drain stderr on a thread. Servers log freely there and a full pipe
        # buffer would deadlock the process we are trying to talk to.
        def drain() -> None:
            assert process.stderr is not None
            for line in process.stderr:
                self._stderr.append(line.rstrip("\n"))

        thread = threading.Thread(target=drain, daemon=True)
        thread.start()
        self._process = process
        return process

    def request(self, method: str, params: Dict[str, Any], timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
        process = self._start()
        self._id += 1
        request_id = self._id
        line = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        assert process.stdin is not None and process.stdout is not None
        try:
            process.stdin.write(line + "\n")
            process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise TransportError("error", "server closed stdin: {}".format(exc))

        result: Dict[str, Any] = {}
        error: List[str] = []

        def read() -> None:
            try:
                for raw in process.stdout:  # type: ignore[union-attr]
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        message = json.loads(raw)
                    except ValueError:
                        # Servers sometimes emit non-MCP noise on stdout despite
                        # the spec forbidding it. Skip rather than fail.
                        continue
                    if isinstance(message, dict) and message.get("id") == request_id:
                        result.update(message)
                        return
            except (OSError, ValueError) as exc:
                error.append(str(exc))

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        reader.join(timeout)
        if reader.is_alive():
            raise TransportError("unreachable", "timed out after {:g}s".format(timeout))
        if error:
            raise TransportError("error", error[0])
        if not result:
            detail = self._stderr[-1] if self._stderr else "server exited without responding"
            raise TransportError("error", detail[:200])
        return result

    def close(self) -> None:
        """Shutdown per the stdio transport spec: close stdin, wait, then escalate."""
        process = self._process
        if process is None:
            return
        try:
            if process.stdin:
                process.stdin.close()
        except OSError:
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        self._process = None

    def notify(self, method: str, params: Dict[str, Any]) -> None:
        """Fire-and-forget notification, used only by the legacy initialize path."""
        process = self._start()
        assert process.stdin is not None
        try:
            process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": params}) + "\n")
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass


def _first_message(payload: str, content_type: str) -> Optional[Dict[str, Any]]:
    """Extract a JSON-RPC response from either a JSON body or an SSE stream."""
    payload = payload.strip()
    if not payload:
        return None
    if "text/event-stream" in content_type or payload.startswith(("event:", "data:", ":")):
        for block in re.split(r"\n\s*\n", payload):
            data = "".join(
                line[5:].lstrip() for line in block.splitlines() if line.startswith("data:")
            )
            if not data:
                continue
            try:
                message = json.loads(data)
            except ValueError:
                continue
            if isinstance(message, dict) and ("result" in message or "error" in message):
                return message
        return None
    try:
        message = json.loads(payload)
    except ValueError:
        return None
    return message if isinstance(message, dict) else None

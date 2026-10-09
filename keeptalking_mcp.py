"""Minimal MCP client for companion plugins — stdio transport only.

A plugin that wraps an existing MCP server (DESIGN_PLUGIN_ACTIONS.md §7.4)
needs four operations: spawn, ``initialize``, ``tools/list``, ``tools/call``.
That is newline-delimited JSON-RPC 2.0 over a child's stdio, so this module
implements exactly that instead of pulling in the official SDK and its
dependency tree. Requests are multiplexed by id, so concurrent calls share one
server process; a cancelled call tells the server via
``notifications/cancelled``.

Stdlib only: the companion imports plugin modules on its own (possibly old)
interpreter to read their declarations, so keep this file 3.9-compatible.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "2025-06-18"
# Tool results carry base64 screenshots; asyncio's 64 KiB default line limit
# would split them mid-frame.
LINE_LIMIT = 64 * 1024 * 1024


class McpError(RuntimeError):
    """A JSON-RPC error from the server, a timeout, or a dead server."""

    def __init__(self, message: str, code: int | None = None, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data


class McpStdioClient:
    """One MCP server child process and the session spoken over its stdio."""

    def __init__(
        self,
        argv: list[str],
        *,
        env: dict[str, str] | None = None,
        stderr_path: Path | None = None,
        client_name: str = "keeptalking-companion",
        client_version: str = "1",
    ):
        self.argv = list(argv)
        self.env = env
        self.stderr_path = stderr_path
        self.client_info = {"name": client_name, "version": client_version}
        self.server_info: dict = {}
        self.server_capabilities: dict = {}
        # Server notifications (e.g. "notifications/resources/list_changed"),
        # as (method, params). Called on the read loop: keep it quick.
        self.on_notification: Any = None
        self._process: asyncio.subprocess.Process | None = None
        self._reader_task: asyncio.Task | None = None
        self._pending: dict[int, asyncio.Future] = {}
        self._next_id = 0
        self._closed = False

    @property
    def running(self) -> bool:
        return (
            not self._closed
            and self._process is not None
            and self._process.returncode is None
        )

    async def start(self, timeout: float = 20.0) -> dict:
        """Spawns the server and completes the initialize handshake. Returns
        the server's ``initialize`` result."""
        stderr: Any = asyncio.subprocess.DEVNULL
        if self.stderr_path is not None:
            stderr = open(self.stderr_path, "ab")
        try:
            self._process = await asyncio.create_subprocess_exec(
                *self.argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=stderr,
                env=self.env if self.env is not None else dict(os.environ),
                limit=LINE_LIMIT,
            )
        finally:
            if self.stderr_path is not None:
                stderr.close()  # the child holds its own descriptor
        self._reader_task = asyncio.get_running_loop().create_task(self._read_loop())
        result = await self._request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": self.client_info,
            },
            timeout,
        )
        self.server_info = result.get("serverInfo") or {}
        self.server_capabilities = result.get("capabilities") or {}
        self._notify("notifications/initialized")
        return result

    async def list_tools(self, timeout: float = 20.0) -> list[dict]:
        tools: list[dict] = []
        cursor = None
        while True:
            params = {"cursor": cursor} if cursor else {}
            page = await self._request("tools/list", params, timeout)
            tools += page.get("tools") or []
            cursor = page.get("nextCursor")
            if not cursor:
                return tools

    @property
    def offers_resources(self) -> bool:
        return "resources" in self.server_capabilities

    async def list_resources(self, timeout: float = 20.0) -> list[dict]:
        """The server's published resources (`uri`, `name`, optional `title`,
        `description`, `mimeType`, `size`); empty when it publishes none."""
        if not self.offers_resources:
            return []
        resources: list[dict] = []
        cursor = None
        while True:
            params = {"cursor": cursor} if cursor else {}
            page = await self._request("resources/list", params, timeout)
            resources += page.get("resources") or []
            cursor = page.get("nextCursor")
            if not cursor:
                return resources

    async def read_resource(self, uri: str, *, timeout: float | None = 60.0) -> list[dict]:
        """`resources/read`: the resource's contents, each `{uri, mimeType?,
        text | blob}` (blob = base64)."""
        result = await self._request("resources/read", {"uri": uri}, timeout)
        return result.get("contents") or []

    async def call_tool(
        self, name: str, arguments: dict, *, timeout: float | None = None
    ) -> dict:
        """The raw ``CallToolResult``: ``content``, ``structuredContent``,
        ``isError``. Tool failures come back as results; protocol failures
        raise :class:`McpError`."""
        return await self._request(
            "tools/call", {"name": name, "arguments": arguments}, timeout)

    async def close(self) -> None:
        self._closed = True
        process = self._process
        if process is not None and process.returncode is None:
            # Closing stdin is the polite stdio shutdown; escalate if ignored.
            try:
                if process.stdin is not None:
                    process.stdin.close()
                await asyncio.wait_for(process.wait(), 3.0)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
        if self._reader_task is not None:
            self._reader_task.cancel()
        self._fail_pending(McpError("MCP client closed"))

    # -- JSON-RPC plumbing --

    def _write(self, message: dict) -> None:
        process = self._process
        if process is None or process.stdin is None or not self.running:
            raise McpError("MCP server is not running")
        process.stdin.write(json.dumps(message).encode("utf-8") + b"\n")

    def _notify(self, method: str, params: dict | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._write(message)

    async def _request(self, method: str, params: dict, timeout: float | None) -> dict:
        self._next_id += 1
        request_id = self._next_id
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        try:
            self._write({
                "jsonrpc": "2.0", "id": request_id, "method": method, "params": params,
            })
            assert self._process is not None and self._process.stdin is not None
            await self._process.stdin.drain()
            return await asyncio.wait_for(asyncio.shield(future), timeout)
        except asyncio.TimeoutError:
            self._cancel_remote(request_id, "timed out")
            raise McpError(f"{method} timed out after {timeout:.0f}s")
        except asyncio.CancelledError:
            self._cancel_remote(request_id, "cancelled by the caller")
            raise
        finally:
            self._pending.pop(request_id, None)

    def _cancel_remote(self, request_id: int, reason: str) -> None:
        try:
            self._notify(
                "notifications/cancelled", {"requestId": request_id, "reason": reason})
        except McpError:
            pass

    async def _read_loop(self) -> None:
        assert self._process is not None and self._process.stdout is not None
        stdout = self._process.stdout
        try:
            while True:
                line = await stdout.readline()
                if not line:
                    break
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    continue  # stray non-protocol output
                if not isinstance(message, dict):
                    continue
                if "method" in message:
                    self._answer_server_request(message)
                    continue
                future = self._pending.get(message.get("id"))
                if future is None or future.done():
                    continue
                if "error" in message:
                    error = message["error"] or {}
                    future.set_exception(McpError(
                        str(error.get("message", "MCP error")),
                        error.get("code"),
                        error.get("data"),
                    ))
                else:
                    future.set_result(message.get("result") or {})
        except (asyncio.CancelledError, ValueError):
            pass
        finally:
            self._fail_pending(McpError("MCP server exited"))

    def _answer_server_request(self, message: dict) -> None:
        """Server→client traffic: notifications go to `on_notification`;
        requests get `ping` answered and everything else (sampling, roots,
        elicitation) declined — a companion plugin offers no client
        capabilities."""
        if "id" not in message:
            if self.on_notification is not None:
                try:
                    self.on_notification(message.get("method"), message.get("params") or {})
                except Exception:
                    pass  # a listener bug must not kill the read loop
            return
        if message.get("method") == "ping":
            reply: dict[str, Any] = {"jsonrpc": "2.0", "id": message["id"], "result": {}}
        else:
            reply = {
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {"code": -32601, "message": "method not supported by this client"},
            }
        try:
            self._write(reply)
        except McpError:
            pass

    def _fail_pending(self, error: McpError) -> None:
        for future in list(self._pending.values()):
            if not future.done():
                future.set_exception(error)


def kt_content(result: dict) -> list[dict]:
    """An MCP tool result's ``content`` reduced to the block shapes the KT host
    decodes (MCP ``Tool.Content``). Server-specific extras (annotations,
    ``_meta``) are dropped so one odd field can't fail the host's decode — a
    failed decode would degrade the whole result to text and lose images."""
    blocks: list[dict] = []
    for item in result.get("content") or []:
        kind = item.get("type")
        if kind == "text":
            blocks.append({"type": "text", "text": str(item.get("text", ""))})
        elif kind in ("image", "audio") and item.get("data"):
            blocks.append({
                "type": kind,
                "data": item["data"],
                "mimeType": item.get("mimeType") or "application/octet-stream",
            })
        elif kind == "resource_link" and item.get("uri"):
            link = {"type": "resource_link", "uri": item["uri"],
                    "name": item.get("name") or item["uri"]}
            for key in ("description", "mimeType"):
                if item.get(key):
                    link[key] = item[key]
            blocks.append(link)
        elif kind == "resource" and isinstance(item.get("resource"), dict):
            blocks.append({"type": "resource", "resource": item["resource"]})
        else:
            blocks.append({"type": "text", "text": json.dumps(item)[:4000]})
    return blocks

#!/usr/bin/env python3
"""The KT Companion broker: owns the one KTPP socket.

Plugins connect to ``keeptalking.plugin.PluginHost`` exactly as before;
KeepTalking apps attach to ``keeptalking.plugin.Companion`` (one ``Attach``
stream carrying everything, so a call's elucidations stay ahead of its result)
and name the node every message speaks for. The broker routes between them by plugin name,
request id and node, and keeps no policy of its own: grants, attestation and
ACT budgets stay with the app that made the call.

Mirrors ``KTPPWireMessages.swift`` / ``KTPPWireService.swift`` in the SDK.
"""

from __future__ import annotations

import argparse
import asyncio
import itertools
import json
import os
import signal
import sys
import time
import uuid
from pathlib import Path

import grpc

sys.path.insert(0, str(Path(__file__).resolve().parent))

from keeptalking_plugin import (  # noqa: E402
    PROTOCOL_VERSION,
    _decode,
    _encode,
    default_socket_path,
)

APP_PROTOCOL_VERSION = 1
PLUGIN_SERVICE = "keeptalking.plugin.PluginHost"
COMPANION_SERVICE = "keeptalking.plugin.Companion"

REVEAL_MARKER = "@kt-companion reveal"
IDENTITIES_MARKER = "@kt-companion identities"
CHOOSE_MARKER = "@kt-companion choose-identity"
CHOICE_CLOSED_MARKER = "@kt-companion choice-closed"

PRESENCE_LAPSE = 15.0
CHOICE_TIMEOUT = 120.0

SERVER_OPTIONS = [
    ("grpc.keepalive_time_ms", 10_000),
    ("grpc.keepalive_timeout_ms", 5_000),
    ("grpc.keepalive_permit_without_calls", 1),
    ("grpc.http2.min_ping_interval_without_data_ms", 5_000),
    ("grpc.http2.max_ping_strikes", 0),
    ("grpc.http2.max_pings_without_data", 0),
    ("grpc.max_send_message_length", 64 * 1024 * 1024),
    ("grpc.max_receive_message_length", 64 * 1024 * 1024),
]

def log(line: str) -> None:
    print(f"[KT Companion] {line}", flush=True)


def marker(name: str, payload: dict) -> None:
    print(f"{name} {json.dumps(payload, separators=(',', ':'), ensure_ascii=False)}", flush=True)


class KTPPAbort(Exception):
    """A refused plugin RPC; the plugin SDK reads ``code`` from the ``ktpp-code`` trailer."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class Connection:
    """One stream peer: its ordered outbox and the requests awaiting its reply."""

    def __init__(self, ids: itertools.count):
        self.outbox: asyncio.Queue = asyncio.Queue()
        self.pending: dict[int, asyncio.Future] = {}
        self.closed = False
        self.error: tuple[grpc.StatusCode, str] | None = None
        self._ids = ids

    def send(self, message: dict) -> None:
        if not self.closed:
            self.outbox.put_nowait(message)

    async def request(self, body_key: str, body: dict, to: str | None = None) -> dict:
        if self.closed:
            raise ConnectionError("connection closed")
        request_id = next(self._ids)
        future = asyncio.get_running_loop().create_future()
        self.pending[request_id] = future
        message: dict = {"id": request_id, body_key: body}
        if to is not None:
            message["to"] = to
        self.send(message)
        try:
            return await future
        finally:
            self.pending.pop(request_id, None)

    def resolve(self, message: dict) -> None:
        future = self.pending.pop(message.get("replyTo"), None)
        if future is not None and not future.done():
            future.set_result(message)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for future in self.pending.values():
            if not future.done():
                future.set_exception(ConnectionError("connection closed"))
        self.pending.clear()
        self.outbox.put_nowait(None)


class PluginState:
    def __init__(self, hello: dict):
        self.name = hello["name"]
        self.vendor = hello.get("vendor", "")
        self.version = hello.get("version", "")
        self.kinds: dict | None = None
        self.connection: Connection | None = None


class Attachment(Connection):
    def __init__(self, ids: itertools.count):
        super().__init__(ids)
        self.instance = "?"
        self.tasks: set[asyncio.Task] = set()

    def spawn(self, coroutine) -> None:
        task = asyncio.ensure_future(coroutine)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    def close(self) -> None:
        super().close()
        for task in list(self.tasks):
            task.cancel()


class Node:
    def __init__(self, attachment: Attachment, label: str | None):
        self.attachment = attachment
        self.label = label
        self.last_seen = time.monotonic()

    @property
    def online(self) -> bool:
        return not self.attachment.closed and time.monotonic() - self.last_seen < PRESENCE_LAPSE


class Broker:
    def __init__(self, has_ui: bool = False):
        self.has_ui = has_ui
        self.instance = uuid.uuid4().hex
        self.plugins: dict[str, PluginState] = {}
        self.attachments: set[Attachment] = set()
        self.nodes: dict[str, Node] = {}
        self.calls: dict[str, tuple[str, Connection]] = {}
        self.choices: dict[str, asyncio.Future] = {}
        self._ids = itertools.count(1)
        self._announced: list[dict] | None = None
        self._server: grpc.aio.Server | None = None
        self._sweeper: asyncio.Task | None = None

    # -- lifecycle --

    async def start(self, socket_path: str) -> None:
        path = Path(socket_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() or path.is_symlink():
            path.unlink()
        server = grpc.aio.server(options=SERVER_OPTIONS)
        server.add_generic_rpc_handlers((self._plugin_handlers(), self._companion_handlers()))
        server.add_insecure_port(f"unix:{socket_path}")
        await server.start()
        os.chmod(socket_path, 0o600)
        self._server = server
        self._sweeper = asyncio.ensure_future(self._sweep())
        log(f"listening on {socket_path}")
        self._announce_presence()

    async def shutdown(self) -> None:
        for peer in [*self.attachments, *(p.connection for p in self.plugins.values() if p.connection)]:
            peer.close()
        if self._sweeper:
            self._sweeper.cancel()
        if self._server:
            await self._server.stop(1.0)

    def _plugin_handlers(self) -> grpc.GenericRpcHandler:
        return grpc.method_handlers_generic_handler(
            PLUGIN_SERVICE,
            {
                "Connect": self._stream(self._plugin_connect),
                "RequestAct": self._unary(self._request_act),
                "ProposeAction": self._unary(self._propose_action),
                "OpenAddAction": self._unary(self._plugin_open_add_action),
            },
        )

    def _companion_handlers(self) -> grpc.GenericRpcHandler:
        return grpc.method_handlers_generic_handler(
            COMPANION_SERVICE,
            {"Attach": self._stream(self._attach)},
        )

    @staticmethod
    def _stream(serve):
        return grpc.stream_stream_rpc_method_handler(
            serve, request_deserializer=_decode, response_serializer=_encode)

    @staticmethod
    def _unary(body):
        async def handler(request, context):
            try:
                return await body(request)
            except KTPPAbort as abort:
                await context.abort(
                    grpc.StatusCode.FAILED_PRECONDITION, abort.message,
                    trailing_metadata=(("ktpp-code", abort.code),))

        return grpc.unary_unary_rpc_method_handler(
            handler, request_deserializer=_decode, response_serializer=_encode)

    async def _drain(self, connection: Connection, reader: asyncio.Task, context):
        try:
            while True:
                message = await connection.outbox.get()
                if message is None:
                    break
                yield message
        finally:
            reader.cancel()
        if connection.error:
            await context.abort(*connection.error)

    # -- plugins --

    async def _plugin_connect(self, requests, context):
        connection = Connection(self._ids)
        state: list[PluginState] = []
        reader = asyncio.ensure_future(self._read_plugin(connection, requests, state))
        try:
            async for message in self._drain(connection, reader, context):
                yield message
        finally:
            connection.close()
            if state and state[0].connection is connection:
                state[0].connection = None
                log(f"plugin {state[0].name} disconnected")
                self._broadcast_catalog()

    async def _read_plugin(self, connection: Connection, requests, state: list[PluginState]) -> None:
        try:
            async for message in requests:
                if not state:
                    hello = message.get("hello")
                    if not hello:
                        connection.error = (grpc.StatusCode.FAILED_PRECONDITION, "hello first")
                        break
                    if hello.get("protocolVersion") != PROTOCOL_VERSION:
                        connection.error = (
                            grpc.StatusCode.FAILED_PRECONDITION,
                            f"protocol {hello.get('protocolVersion')} unsupported (want {PROTOCOL_VERSION})")
                        break
                    state.append(self._attach_plugin(hello, connection))
                    continue
                plugin = state[0]
                if "replyTo" in message:
                    connection.resolve(message)
                elif "kinds" in message:
                    plugin.kinds = message["kinds"]
                    self._broadcast_catalog()
                elif "elucidation" in message:
                    self._route_elucidation(message["elucidation"] or {})
                elif "goodbye" in message:
                    break
                elif message.get("id") is not None:
                    connection.send({
                        "replyTo": message["id"],
                        "failure": {"code": "unsupported", "message": "the companion does not serve that"},
                    })
        except (asyncio.CancelledError, grpc.aio.AioRpcError):
            pass
        finally:
            connection.close()

    def _attach_plugin(self, hello: dict, connection: Connection) -> PluginState:
        name = hello["name"]
        plugin = self.plugins.get(name) or PluginState(hello)
        plugin.vendor, plugin.version = hello.get("vendor", ""), hello.get("version", "")
        self.plugins[name] = plugin
        previous = plugin.connection
        if previous is not None:
            previous.send({"goodbye": {"reason": "superseded", "message": "a newer copy connected"}})
            previous.close()
        plugin.connection = connection
        connection.send({
            "welcome": {"protocolVersion": PROTOCOL_VERSION, "hostNodeID": "", "instance": self.instance}
        })
        log(f"plugin {name} v{plugin.version} connected")
        self._broadcast_catalog()
        return plugin

    def _catalog(self) -> dict:
        plugins = []
        for plugin in sorted(self.plugins.values(), key=lambda p: p.name):
            entry = {
                "name": plugin.name,
                "vendor": plugin.vendor,
                "version": plugin.version,
                "connected": plugin.connection is not None and not plugin.connection.closed,
            }
            if plugin.kinds is not None:
                entry["kinds"] = plugin.kinds
            plugins.append(entry)
        return {"catalog": {"plugins": plugins}}

    def _broadcast_catalog(self) -> None:
        catalog = self._catalog()
        for attachment in self.attachments:
            attachment.send(catalog)

    # -- apps --

    async def _attach(self, requests, context):
        attachment = Attachment(self._ids)
        reader = asyncio.ensure_future(self._read_app(attachment, requests))
        try:
            async for message in self._drain(attachment, reader, context):
                yield message
        finally:
            attachment.close()
            if attachment in self.attachments:
                self.attachments.discard(attachment)
                log(f"app {attachment.instance[:8]} detached")
            for node_id in [n for n, node in self.nodes.items() if node.attachment is attachment]:
                del self.nodes[node_id]
            self._announce_presence()

    async def _read_app(self, attachment: Attachment, requests) -> None:
        welcomed = False
        try:
            async for message in requests:
                if not welcomed:
                    hello = message.get("hello")
                    if not hello or hello.get("protocolVersion") != APP_PROTOCOL_VERSION:
                        attachment.error = (
                            grpc.StatusCode.FAILED_PRECONDITION,
                            f"hello with protocol {APP_PROTOCOL_VERSION} first")
                        break
                    welcomed = True
                    attachment.instance = str(hello.get("instance", "?"))
                    self.attachments.add(attachment)
                    attachment.send({
                        "welcome": {"protocolVersion": APP_PROTOCOL_VERSION, "instance": self.instance}
                    })
                    attachment.send(self._catalog())
                    log(f"app {hello.get('app', '?')} {hello.get('version', '')} attached "
                        f"({attachment.instance[:8]})")
                    continue
                node_id = message.get("from")
                if "replyTo" in message:
                    attachment.resolve(message)
                elif "keepalive" in message and node_id:
                    self._keepalive(attachment, node_id, (message["keepalive"] or {}).get("label"))
                elif "leave" in message and node_id:
                    node = self.nodes.get(node_id)
                    if node is not None and node.attachment is attachment:
                        del self.nodes[node_id]
                        self._announce_presence()
                elif "cancel" in message:
                    call = self.calls.get((message["cancel"] or {}).get("requestID", ""))
                    if call is not None:
                        call[1].send({"cancel": message["cancel"]})
                elif message.get("id") is not None:
                    attachment.spawn(self._answer_app(attachment, message))
        except (asyncio.CancelledError, grpc.aio.AioRpcError):
            pass
        finally:
            attachment.close()

    def _keepalive(self, attachment: Attachment, node_id: str, label: str | None) -> None:
        node = self.nodes.get(node_id)
        if node is not None and node.attachment is attachment:
            node.last_seen = time.monotonic()
            node.label = label
        else:
            self.nodes[node_id] = Node(attachment, label)
        self._announce_presence()

    def _online(self) -> list[tuple[str, Node]]:
        return sorted(
            ((node_id, node) for node_id, node in self.nodes.items() if node.online),
            key=lambda item: ((item[1].label or "").lower(), item[0]),
        )

    def _identities(self, online: list[tuple[str, Node]]) -> list[dict]:
        return [{"id": node_id, "label": node.label or node_id[:8]} for node_id, node in online]

    def _announce_presence(self) -> None:
        identities = self._identities(self._online())
        if identities != self._announced:
            self._announced = identities
            marker(IDENTITIES_MARKER, {"identities": identities})

    async def _sweep(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            self._announce_presence()

    def _attachment(self, node_id: str) -> Attachment | None:
        node = self.nodes.get(node_id)
        if node is None or node.attachment.closed:
            return None
        return node.attachment

    # -- app → plugin --

    async def _answer_app(self, attachment: Attachment, message: dict) -> None:
        request_id, node_id = message["id"], message.get("from")
        reply: dict = {"replyTo": request_id}
        if node_id:
            reply["to"] = node_id
        if "call" in message:
            reply.update(await self._relay(message["call"] or {}, "call", "callResult", node_id))
        elif "scopeOptions" in message:
            reply.update(await self._relay(message["scopeOptions"] or {}, "scopeOptions", "scopeOptions", node_id))
        elif "resourceRead" in message:
            reply.update(await self._relay(message["resourceRead"] or {}, "resourceRead", "resourceRead", node_id))
        elif "reveal" in message:
            print(REVEAL_MARKER, flush=True)
            reply["reveal"] = {"revealed": self.has_ui}
        else:
            reply["failure"] = {"code": "unsupported", "message": "the companion does not serve that"}
        attachment.send(reply)

    async def _relay(self, body: dict, request_key: str, reply_key: str, node_id: str | None) -> dict:
        name = body.get("plugin", "")
        plugin = self.plugins.get(name)
        connection = plugin.connection if plugin else None
        if connection is None or connection.closed:
            return {"failure": {"code": "not_connected", "message": f"{name} is not connected"}}
        request = body.get("request") or {}
        call_id = request.get("requestID") if request_key == "call" else None
        if call_id:
            self.calls[call_id] = (node_id or "", connection)
        try:
            reply = await connection.request(request_key, request)
        except asyncio.CancelledError:
            if call_id:
                connection.send({"cancel": {"requestID": call_id}})
            raise
        except ConnectionError:
            return {"failure": {"code": "not_connected", "message": f"{name} disconnected"}}
        finally:
            if call_id:
                self.calls.pop(call_id, None)
        if reply_key in reply:
            return {reply_key: reply[reply_key]}
        failure = dict(reply.get("failure") or {"code": "internal", "message": f"{name} sent no {reply_key}"})
        return {"failure": failure}

    # -- plugin → app --

    def _route_elucidation(self, elucidation: dict) -> None:
        call = self.calls.get(elucidation.get("requestID", ""))
        node_id = call[0] if call else None
        attachment = self._attachment(node_id) if node_id else None
        if attachment is not None:
            attachment.send({"to": node_id, "elucidation": elucidation})

    async def _request_act(self, body: dict) -> dict:
        request_id = body.get("requestID", "")
        call = self.calls.get(request_id)
        node_id = call[0] if call else None
        if node_id is None:
            raise KTPPAbort("act_unbound", f"no in-flight call {request_id}")
        attachment = self._attachment(node_id)
        if attachment is None:
            raise KTPPAbort("act_unavailable", "the calling app is gone")
        try:
            reply = await attachment.request("act", body, to=node_id)
        except ConnectionError:
            raise KTPPAbort("act_unavailable", "the calling app is gone")
        if "act" in reply:
            return reply["act"]
        failure = reply.get("failure") or {}
        raise KTPPAbort(failure.get("code", "act_failed"), failure.get("message", "ACT failed"))

    async def _target(
        self, plugin: str | None, kind: str | None, reason: str | None
    ) -> tuple[str, Attachment] | None:
        online = self._online()
        if len(online) > 1:
            token = uuid.uuid4().hex
            future = asyncio.get_running_loop().create_future()
            self.choices[token] = future
            marker(CHOOSE_MARKER, {
                "token": token, "plugin": plugin, "kind": kind, "reason": reason,
                "identities": self._identities(online),
            })
            try:
                node_id = await asyncio.wait_for(future, CHOICE_TIMEOUT)
            except asyncio.TimeoutError:
                node_id = None
            finally:
                self.choices.pop(token, None)
                marker(CHOICE_CLOSED_MARKER, {"token": token})
        else:
            node_id = online[0][0] if online else None
        attachment = self._attachment(node_id) if node_id else None
        return (node_id, attachment) if attachment else None

    def choose(self, token: str, node_id: str | None) -> None:
        future = self.choices.get(token)
        if future is not None and not future.done():
            future.set_result(node_id)

    async def _forward(self, key: str, body: dict, node_id: str | None = None) -> dict:
        target = (node_id, self._attachment(node_id)) if node_id else await self._target(
            body.get("pluginName"), body.get("kindName"), body.get("reason"))
        if not target or not target[1]:
            return {"failure": {"code": "not_connected", "message": "no KeepTalking identity to ask"}}
        try:
            return await target[1].request(key, body, to=target[0])
        except ConnectionError:
            return {"failure": {"code": "not_connected", "message": "KeepTalking went away"}}

    async def _propose_action(self, body: dict) -> dict:
        reply = await self._forward("actionCreate", body)
        return reply.get("actionCreate") or {
            "status": "unsupported", "message": (reply.get("failure") or {}).get("message", "")}

    async def _plugin_open_add_action(self, body: dict) -> dict:
        reply = await self._forward("addAction", body)
        if "addAction" not in reply:
            raise KTPPAbort("not_connected", (reply.get("failure") or {}).get("message", "no KeepTalking"))
        return {}

    async def open_add_action(self, kind: str | None, plugin: str | None, node_id: str | None) -> bool:
        body = {key: value for key, value in (("kindName", kind), ("pluginName", plugin)) if value}
        reply = await self._forward("addAction", body, node_id)
        if "addAction" not in reply:
            log(f"openAddAction: {(reply.get('failure') or {}).get('message', 'refused')}")
        return "addAction" in reply


async def serve_standalone(socket_path: str) -> None:
    broker = Broker()
    await broker.start(socket_path)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)
    await stop.wait()
    await broker.shutdown()


def main() -> None:
    sys.stdout.reconfigure(line_buffering=True)
    parser = argparse.ArgumentParser(description="KT Companion broker (no plugins)")
    parser.add_argument("--socket", default=None)
    args = parser.parse_args()
    asyncio.run(serve_standalone(args.socket or default_socket_path()))


if __name__ == "__main__":
    main()

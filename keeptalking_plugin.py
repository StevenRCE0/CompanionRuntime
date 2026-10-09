"""KeepTalking plugin SDK.

Speaks the KeepTalking Plugin Protocol to the host over gRPC on its Unix
socket, with JSON messages (no protobuf). There is no pairing and there are no
sessions: whoever reaches the socket is the user's own process, and a plugin is
known by the name it gives in ``hello``. Declare *action kinds* with scope
schemas (the Primitive convention), enforce your instance scope in the handler,
call ``ctx.report_usage``; the SDK does the rest.

Mirrors ``Sources/KeepTalking/Services/PluginHost/Wire/KTPPWireMessages.swift``
(message shapes) and ``KTPPWireService.swift`` (methods, keepalive). ``grpc`` is
imported only when a plugin connects, so reading a plugin's declaration
(``companion.py --describe``) needs nothing beyond the standard library.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Awaitable, Callable, NamedTuple

PROTOCOL_VERSION = 0
COMPANION_ROLE = "companion"

# Every plugin venv needs the SDK's own dependency, since the plugin process
# imports this module with the venv's interpreter.
SDK_REQUIREMENTS = ["grpcio>=1.70"]

SERVICE = "keeptalking.plugin.PluginHost"
CONNECT_METHOD = f"/{SERVICE}/Connect"
REQUEST_ACT_METHOD = f"/{SERVICE}/RequestAct"
PROPOSE_ACTION_METHOD = f"/{SERVICE}/ProposeAction"
OPEN_ADD_ACTION_METHOD = f"/{SERVICE}/OpenAddAction"

# Matches the host's keepalive (`KTPPWire.keepaliveTime`/`Timeout`): an exit
# closes the socket at once, so these pings only catch a frozen host. gRPC
# stops pinging after two pings without data by default, which would silence
# keepalive on a quiet connection — lifted here.
CHANNEL_OPTIONS = [
    ("grpc.keepalive_time_ms", 10_000),
    ("grpc.keepalive_timeout_ms", 5_000),
    ("grpc.keepalive_permit_without_calls", 1),
    ("grpc.http2.max_pings_without_data", 0),
    # Results can carry screenshots and documents.
    ("grpc.max_send_message_length", 64 * 1024 * 1024),
    ("grpc.max_receive_message_length", 64 * 1024 * 1024),
]


# The companion spawns plugin processes while its own channel is open; gRPC's
# fork handlers only log noise for children that exec straight away.
os.environ.setdefault("GRPC_ENABLE_FORK_SUPPORT", "false")
os.environ.setdefault("GRPC_VERBOSITY", "ERROR")


def _encode(message: Any) -> bytes:
    return json.dumps(
        message, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _decode(data: bytes) -> Any:
    return json.loads(data)


def _rpc_failure(error: BaseException, default_code: str = "failed") -> str:
    """``code: message`` for a failed host RPC — KTPP's own code from the
    ``ktpp-code`` trailer when the host set one, else the gRPC status."""
    code, details = default_code, str(error) or type(error).__name__
    try:
        import grpc

        if isinstance(error, grpc.aio.AioRpcError):
            details = error.details() or details
            code = error.code().name.lower()
            for key, value in error.trailing_metadata() or ():
                if key == "ktpp-code":
                    code = value
    except ImportError:
        pass
    return f"{code}: {details}"


# --- canonical JSON -----------------------------------------------------------
#
# Byte-identical to the host's `KeepTalkingCanonicalJSON` — the bytes any
# signing attestor works over — and used here for the manifest and
# requirement-set hashes.


def _forbid_floats(obj: Any) -> None:
    if isinstance(obj, float):
        raise TypeError("KTPP canonical JSON forbids floats; use integer units")
    if isinstance(obj, dict):
        for value in obj.values():
            _forbid_floats(value)
    elif isinstance(obj, list):
        for value in obj:
            _forbid_floats(value)


def canonical(obj: Any) -> bytes:
    _forbid_floats(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(obj: Any) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


# --- verifiable calls ---------------------------------------------------------


class CallAttestor:
    """The plugin's half of the verifiable-call seam (the host's half is
    ``KeepTalkingCallAttestor``). Nothing attests by default; a billing or
    audit scheme subclasses this and passes it as ``Plugin(attestor=…)``.

    ``call`` is the host's call payload; its ``authorization`` is the host
    attestor's evidence for exactly this call, when the host made some."""

    def check_authorization(self, call: dict) -> str | None:
        """None runs the call; a string refuses it with that reason."""
        return None

    def receipt(self, call: dict, result: dict) -> dict | None:
        """Evidence over ``result`` (``content``, ``isError``, ``usage``),
        bound to the call — ``{"scheme": …, "payload": …}`` — or None."""
        return None


# --- state --------------------------------------------------------------------


def _state_dir(name: str) -> Path:
    slug = "".join(c if c.isalnum() or c in "-_" else "-" for c in name.lower())
    path = Path.home() / ".keeptalking-plugin" / slug
    path.mkdir(parents=True, exist_ok=True)
    return path


def _discovery_candidates() -> list[Path]:
    """Places a KeepTalking host may publish `ktpp.json`.

    A sandboxed KeepTalking cannot use plain Application Support — that lives
    inside its container, invisible to plugin processes — so it publishes into
    its **app-group** container instead. Unsandboxed hosts (the CLI lab) still
    use Application Support. Check both, plus the sandbox container directly as
    a last resort for hosts without a group.
    """
    home = Path.home()
    candidates: list[Path] = [
        home / "Library" / "Application Support" / "KeepTalking" / "ktpp.json",
    ]
    candidates += sorted(
        (home / "Library" / "Group Containers").glob(
            "*[Kk]eep[Tt]alking*/ktpp.json"
        )
    )
    candidates += sorted(
        (home / "Library" / "Containers").glob(
            "*[Kk]eep[Tt]alking*/Data/Library/Application Support/KeepTalking/ktpp.json"
        )
    )
    return candidates


def discover_socket_path() -> str:
    override = os.environ.get("KT_PLUGIN_SOCKET")
    if override:
        return override
    # Freshest first: with several hosts published, follow the one that most
    # recently announced itself rather than whichever path sorts first.
    found: list[tuple[float, str]] = []
    for discovery in _discovery_candidates():
        try:
            socket_path = json.loads(discovery.read_text())["socketPath"]
        except (OSError, json.JSONDecodeError, KeyError):
            continue
        if Path(socket_path).exists():
            found.append((discovery.stat().st_mtime, socket_path))
    if found:
        return max(found)[1]
    raise RuntimeError(
        "No KeepTalking plugin socket found — start KeepTalking (it publishes "
        "ktpp.json in its app-group container) or set KT_PLUGIN_SOCKET"
    )


# --- plugin configuration -----------------------------------------------------


@dataclasses.dataclass
class ConfigField:
    """One runtime-configuration field a plugin exposes to the Companion app.

    Distinct from instance *scope* (per-action, granted in the KT host): config
    is plugin-wide runtime state — credentials, model choices, defaults — set
    once in the Companion UI. Resolution order: `config.json` in the state dir
    (written by the Companion) > declared `env` variable > `default`.
    """

    key: str
    label: str
    type: str = "string"  # "string" | "secret" | "bool" | "choice"
    default: Any = None
    env: str | None = None  # environment fallback, e.g. "OPENAI_API_KEY"
    choices: list[str] | None = None
    description: str | None = None

    def describe(self, resolved: Any, from_file_or_env: bool) -> dict:
        entry: dict[str, Any] = {
            "key": self.key,
            "label": self.label,
            "type": self.type,
            "isSet": from_file_or_env,
        }
        if self.default is not None:
            entry["default"] = _stringify(self.default)
        if self.env:
            entry["env"] = self.env
        if self.choices:
            entry["choices"] = self.choices
        if self.description:
            entry["description"] = self.description
        # Secrets never leave the runtime; other fields show their effective value.
        if self.type != "secret" and resolved is not None:
            entry["value"] = _stringify(resolved)
        return entry


def config_field(
    key: str,
    *,
    label: str | None = None,
    type: str = "string",
    default: Any = None,
    env: str | None = None,
    choices: list[str] | None = None,
    description: str | None = None,
) -> ConfigField:
    return ConfigField(
        key=key,
        label=label or key.replace("_", " ").title(),
        type=type,
        default=default,
        env=env,
        choices=choices,
        description=description,
    )


def _stringify(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


# --- resources ----------------------------------------------------------------
#
# The `resources` block on a call carries the run's staged file
# manifest: canonical handles (KT_<KIND>_<HEX>) plus the host-resolved paths.
# THIS SDK IS THE OBSCURING BOUNDARY (DESIGN_PLUGIN_RESOURCES_ACT.md §3.2):
# the path stays in a private field; handler code addresses resources by
# handle/objectName and moves bytes through streams. No file bytes cross the
# socket — reads and writes are direct local IO on the SDK-private path.


class ResourceError(RuntimeError):
    """Handle-addressed resource misuse: unknown handle/slot, direction
    violation, or an invalid child name. Messages name handles, never paths."""


def file_in(name: str, description: str = "") -> dict:
    """Declares a file INPUT object for a kind (staged for the handler)."""
    return {"name": name, "direction": "input", "description": description}


def file_out(name: str, description: str = "") -> dict:
    """Declares a file OUTPUT object — a write slot the host harvests."""
    return {"name": name, "direction": "output", "description": description}


def _validated_child(child: str) -> str:
    """One sane filename component — the same rule the host applies to skill
    output names: no separators, no dot-navigation, no control characters."""
    if (
        not child
        or len(child.encode("utf-8")) > 255
        or "/" in child
        or "\\" in child
        or child.startswith(".")
        or any(ord(c) < 0x20 or ord(c) == 0x7F for c in child)
    ):
        raise ResourceError(f"invalid child name {child!r}")
    return child


class Resource:
    """One provisioned resource of the current call, addressed by handle.

    Reads are always allowed (a handler may re-read its own output slot);
    writes require a `write`-direction slot. Directory resources (collection
    slots, staged dirs) take a `child` filename; file resources forbid one.
    The resolved path is deliberately private — not in ``repr``, not in
    errors, not in any public attribute — so handler code stays structurally
    incapable of depending on (or leaking) host filesystem layout.
    """

    __slots__ = (
        "handle",
        "kind",
        "direction",
        "name",
        "object_name",
        "is_directory",
        "_path",
    )

    def __init__(self, entry: dict):
        self.handle = entry.get("handle", "")
        self.kind = entry.get("kind", "")
        self.direction = entry.get("direction", "read")
        self.name = entry.get("name", "")
        self.object_name = entry.get("objectName")
        self.is_directory = bool(entry.get("isDirectory", False))
        self._path = entry.get("path")

    def __repr__(self) -> str:
        return (
            f"Resource(handle={self.handle}, kind={self.kind}, "
            f"direction={self.direction}, name={self.name!r})"
        )

    def _resolved(self, child: str | None, *, writing: bool) -> Path:
        if writing and self.direction != "write":
            raise ResourceError(f"resource {self.handle} is not a write slot")
        if self._path is None:
            raise ResourceError(
                f"resource {self.handle} is not locally reachable"
            )
        path = Path(self._path)
        if child is not None:
            if not self.is_directory:
                raise ResourceError(
                    f"resource {self.handle} is not a directory"
                )
            path = path / _validated_child(child)
        elif self.is_directory and writing:
            raise ResourceError(
                f"collection slot {self.handle} needs a child filename"
            )
        return path

    def open(self, mode: str = "rb", *, child: str | None = None):
        """A real file stream over the resource — the primary interface;
        stream-consuming libraries plug in with zero copies."""
        writing = any(flag in mode for flag in "wax+")
        path = self._resolved(child, writing=writing)
        if writing:
            path.parent.mkdir(parents=True, exist_ok=True)
        return open(path, mode)

    def read_bytes(self, *, child: str | None = None) -> bytes:
        with self.open("rb", child=child) as stream:
            return stream.read()

    def read_text(
        self, encoding: str = "utf-8", *, child: str | None = None
    ) -> str:
        return self.read_bytes(child=child).decode(encoding)

    def write_bytes(self, data: bytes, *, child: str | None = None) -> None:
        with self.open("wb", child=child) as stream:
            stream.write(data)

    def write_text(
        self, text: str, encoding: str = "utf-8", *, child: str | None = None
    ) -> None:
        self.write_bytes(text.encode(encoding), child=child)

    def list(self) -> list[dict]:
        """Children of a directory resource: [{name, byteCount, isDirectory}]."""
        if not self.is_directory:
            raise ResourceError(f"resource {self.handle} is not a directory")
        root = self._resolved(None, writing=False)
        entries: list[dict] = []
        try:
            children = sorted(root.iterdir(), key=lambda p: p.name)
        except OSError:
            return []
        for item in children:
            if item.name.startswith("."):
                continue
            is_dir = item.is_dir()
            entry: dict[str, Any] = {"name": item.name, "isDirectory": is_dir}
            if not is_dir:
                try:
                    entry["byteCount"] = item.stat().st_size
                except OSError:
                    pass
            entries.append(entry)
        return entries

    @property
    def byte_count(self) -> int | None:
        """Size of a file resource, stat'd on demand; None when unknowable."""
        if self._path is None or self.is_directory:
            return None
        try:
            return Path(self._path).stat().st_size
        except OSError:
            return None


class Resources:
    """The call's resource view: entries plus slot lookups. ``input()`` /
    ``output()`` raise descriptively (listing what IS available) so handler
    code stays assertion-free."""

    def __init__(self, entries: list[dict] | None):
        self.entries = [Resource(entry) for entry in (entries or [])]

    def __iter__(self):
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def inputs(self) -> list[Resource]:
        return [r for r in self.entries if r.direction == "read"]

    def _available(self, direction: str) -> str:
        names = [
            r.object_name or r.handle
            for r in self.entries
            if r.direction == direction
        ]
        return ", ".join(names) if names else "(none)"

    def input(self, name: str | None = None) -> Resource:
        """A read entry by objectName or handle; ``None`` = the sole input.

        A named miss falls back to the sole read entry when there is exactly
        one: callers stage inputs in several ways (kt_send_file OTBs, context
        attachments) and their labels don't always reach the objectName — an
        unambiguous input should never fail a handler over naming."""
        candidates = self.inputs()
        if name is not None:
            for resource in candidates:
                if name in (resource.object_name, resource.handle):
                    return resource
        if len(candidates) == 1:
            return candidates[0]
        if name is None:
            raise ResourceError(
                f"input() without a name needs exactly one input resource; "
                f"this call has: {self._available('read')}"
            )
        raise ResourceError(
            f"no input resource {name!r}; this call has: {self._available('read')}"
        )

    def output(self, name: str | None = None) -> Resource:
        """A write slot by objectName or handle; ``None`` = the sole slot.

        Same fallback as ``input``: a caller may label its requested output
        anything ("catalogue_markdown" for a kind whose declared output is
        "markdown"); with exactly one write slot the intent is unambiguous."""
        slots = [r for r in self.entries if r.direction == "write"]
        if name is not None:
            for resource in slots:
                if name in (resource.object_name, resource.handle):
                    return resource
        if len(slots) == 1:
            return slots[0]
        if name is None:
            raise ResourceError(
                f"output() without a name needs exactly one write slot; "
                f"this call has: {self._available('write')}"
            )
        raise ResourceError(
            f"no output slot {name!r}; this call has: {self._available('write')}"
        )


# --- ACT (host-side AI turns) -------------------------------------------------


class ActResult(NamedTuple):
    """One completed host ACT turn."""

    text: str
    thinking: str | None
    model: str
    usage: dict  # {"inputTokens": …, "outputTokens": …} when the host has them


class ActDenied(RuntimeError):
    """The host declined an ACT turn: consent off, budget exhausted, no AI
    configured, or the call binding was invalid. Handlers should degrade
    gracefully (skip the AI-assisted step) rather than fail the call."""


# --- call context -------------------------------------------------------------


@dataclasses.dataclass
class CallContext:
    """Handed to kind handlers: the user-configured instance scope, the
    plugin's resolved runtime configuration, the call's provisioned
    resources, and the usage reporter."""

    instance_id: str
    scope: dict | None
    config: dict
    _usage: dict
    resources: Resources = dataclasses.field(
        default_factory=lambda: Resources(None)
    )
    # The sub-tool the caller addressed, or None for a kind called as a whole.
    tool: str | None = None
    # Plugin → host plumbing (RequestAct, elucidations): the plugin runtime and
    # the id of the in-flight call this context serves. Internal; set when the
    # call arrives.
    _plugin: Any = None
    _request_id: str = ""

    def report_usage(self, meter: str, units: int) -> None:
        if not isinstance(units, int):
            raise ValueError("usage units must be integers (meter quantum)")
        self._usage[meter] = self._usage.get(meter, 0) + units

    async def act(
        self,
        task: str,
        *,
        system: str | None = None,
        attachments: list[str] | None = None,
        expects: str = "text",
        max_output_tokens: int | None = None,
        timeout: float = 120.0,
    ) -> ActResult:
        """One bounded AI turn on the HOST's ACT connector (`RequestAct`).

        Valid only while this call is in flight; the host enforces the
        catalog's consent toggle and a per-call budget. `attachments` are
        handles from ``ctx.resources`` whose text content the host injects.
        Raises :class:`ActDenied` on any refusal — catch it and degrade.
        """
        plugin = self._plugin
        if plugin is None or not plugin.connected:
            raise ActDenied("not connected to a host")
        payload: dict[str, Any] = {"requestID": self._request_id, "task": task}
        if system:
            payload["system"] = system
        if attachments:
            payload["attachments"] = list(attachments)
        if expects != "text":
            payload["expects"] = expects
        if max_output_tokens is not None:
            payload["maxOutputTokens"] = max_output_tokens

        try:
            body = await plugin._unary(REQUEST_ACT_METHOD, payload, timeout)
        except RuntimeError as error:
            raise ActDenied(str(error))
        except Exception as error:
            raise ActDenied(_rpc_failure(error, default_code="act_failed"))
        return ActResult(
            text=body.get("text", ""),
            thinking=body.get("thinking"),
            model=body.get("model", ""),
            usage=body.get("usage") or {},
        )

    def elucidate(self, message: str, detail: str | None = None) -> None:
        """Fire-and-forget narration: one short note published into the
        caller's trace and backfed to the summarizing agent. Never raises,
        never blocks the handler.

        Queued on the connection synchronously, in program order: a note sent
        before the call's result is recorded before the result closes the
        call."""
        try:
            plugin = self._plugin
            if plugin is None:
                return
            note: dict[str, Any] = {
                "requestID": self._request_id,
                "message": message,
            }
            if detail:
                note["detail"] = detail
            plugin._queue({"elucidation": note})
        except Exception:
            pass


Handler = Callable[[dict, CallContext], Awaitable[Any]]


# --- scope options ------------------------------------------------------------
#
# A scope key can offer the user CHOICES in KeepTalking's instance form
# instead of a free-text field — the apps that are open, the repos you have,
# the calendars on this Mac. The plugin supplies them live, at form time.
# They are display data only: whatever the user picks still lands in the
# scope bag every call carries, and the kind's handler still enforces it.

OPTIONS_KEYWORD = "x-ktpp-options"
MAX_SCOPE_OPTIONS = 500


@dataclasses.dataclass
class ScopeOptionsRequest:
    """What the host asked for: one key of one kind, given the form's current
    scope bag (so a key's choices can depend on another's) and an optional
    search string."""

    kind_name: str
    key: str
    scope: dict
    query: str | None
    config: dict


ScopeOptionsProvider = Callable[[ScopeOptionsRequest], Awaitable[list]]


def scope_option(
    value: Any,
    label: str | None = None,
    *,
    detail: str | None = None,
    group: str | None = None,
    symbol: str | None = None,
    app: str | None = None,
    caution: str | None = None,
) -> dict:
    """One choice for the instance form. `value` (a string, int or bool) is
    what lands in the scope bag; `label` is what the user reads. `group`
    sections the list, `symbol` (an SF Symbol) or `app` (a bundle id whose
    icon the host draws) decorates it, and `caution` warns about it."""
    option: dict[str, Any] = {"value": value, "label": label or str(value)}
    if detail:
        option["detail"] = detail
    if group:
        option["group"] = group
    if symbol or app:
        option["icon"] = {
            k: v for k, v in (("symbol", symbol), ("app", app)) if v
        }
    if caution:
        option["caution"] = caution
    return option


def resource(
    uri: str,
    name: str,
    *,
    title: str | None = None,
    description: str | None = None,
    mime_type: str | None = None,
    size: int | None = None,
) -> dict:
    """One resource a kind declares, in MCP's `resources/list` shape."""
    entry: dict[str, Any] = {"uri": uri, "name": name}
    for key, value in (
        ("title", title),
        ("description", description),
        ("mimeType", mime_type),
        ("size", size),
    ):
        if value is not None:
            entry[key] = value
    return entry


@dataclasses.dataclass
class _Kind:
    name: str
    display_name: str
    description: str
    input_schema: dict | None
    scope_schema: dict | None
    default_scope: dict | None
    handler: Handler
    # Directioned file objects (file_in/file_out dicts). Materialized onto the
    # instance descriptor host-side — what makes calls to this kind stage
    # inputs and mint output slots.
    objects: list[dict] | None = None
    # Capabilities from the host's FIXED vocabulary (currently: "act").
    # The kind-level ceiling; the user narrows per instance via the reserved
    # `capabilities` scope key, and the catalog's allowsACT toggle gates act
    # globally — all three must agree.
    capabilities: list[str] | None = None
    # Shorthand for capabilities=["act"].
    uses_act: bool = False
    # Named sub-tools ({name, description, inputSchema}) the caller addresses
    # through the kind's `tool` argument; grants can narrow to them by name.
    sub_tools: list[dict] | None = None
    # Resources the kind exposes, declared beside its tools (MCP
    # `resources/list` shape, see `resource(...)`).
    resources: list[dict] | None = None

    def effective_capabilities(self) -> list[str]:
        merged = set(self.capabilities or [])
        if self.uses_act:
            merged.add("act")
        return sorted(merged)

    def declaration(self) -> dict:
        decl: dict[str, Any] = {
            "kindName": self.name,
            "displayName": self.display_name,
            "indexDescription": self.description,
        }
        if self.input_schema is not None:
            decl["inputSchema"] = self.input_schema
        if self.scope_schema is not None:
            decl["scopeSchema"] = self.scope_schema
        if self.default_scope is not None:
            decl["defaultScope"] = self.default_scope
        if self.objects:
            decl["objects"] = self.objects
        if self.sub_tools:
            decl["subTools"] = self.sub_tools
        if self.resources:
            decl["resources"] = self.resources
        if capabilities := self.effective_capabilities():
            decl["capabilities"] = capabilities
        return decl


# --- system permissions -------------------------------------------------------
#
# What a plugin needs from the OS (Accessibility, Screen Recording, …) is part
# of its manifest. The vocabulary is fixed and lives in `permissions.json`
# beside this file — the one registry the SDK and the Companion app both read:
# each entry names the permission, says how to check and request it per
# platform, and where its Settings pane is. Plugins declare entries; the
# Companion is the identity that holds the grants (every plugin runs down its
# process chain, so macOS attributes checks and prompts to KT Companion).

PERMISSIONS_FILE = Path(__file__).resolve().parent / "permissions.json"
# Stdout line the Companion app reads as "a plugin asked for a permission";
# the JSON body follows a space. Keep in sync with the Companion's supervisor.
PERMISSION_MARKER = "@kt-companion permission-request"
PERMISSION_REQUEST_INTERVAL = (
    120.0  # seconds between prompts for one permission
)


def _load_permission_registry() -> dict[str, dict]:
    try:
        entries = (
            json.loads(PERMISSIONS_FILE.read_text()).get("permissions") or []
        )
    except (OSError, ValueError):
        return {}
    return {
        entry["id"]: entry
        for entry in entries
        if isinstance(entry, dict) and "id" in entry
    }


SYSTEM_PERMISSIONS = _load_permission_registry()


def permission(
    permission_id: str, reason: str, *, required: bool = True
) -> dict:
    """Declares one system permission for a plugin's manifest. `reason` is
    shown to the user beside the request ("To click and type in the apps you
    allow"); `required=False` marks one only some features need."""
    if permission_id not in SYSTEM_PERMISSIONS:
        raise ValueError(
            f"unknown permission {permission_id!r}; known: "
            f"{', '.join(sorted(SYSTEM_PERMISSIONS)) or '(registry missing)'}"
        )
    return {"id": permission_id, "reason": reason, "required": required}


class _MacPermissionBroker:
    """The registry's macOS `status` / `request` methods, through the system
    frameworks via ctypes (stdlib only). Status is "granted", "missing" or
    "unknown" — the APIs can't tell a refusal from a question never asked."""

    def __init__(self) -> None:
        import ctypes

        self.ctypes = ctypes
        frameworks = "/System/Library/Frameworks/"
        self.cf = ctypes.CDLL(
            frameworks + "CoreFoundation.framework/CoreFoundation"
        )
        self.ax = ctypes.CDLL(
            frameworks + "ApplicationServices.framework/ApplicationServices"
        )
        self.cg = ctypes.CDLL(
            frameworks + "CoreGraphics.framework/CoreGraphics"
        )
        for function in (
            self.ax.AXIsProcessTrusted,
            self.cg.CGPreflightScreenCaptureAccess,
            self.cg.CGRequestScreenCaptureAccess,
        ):
            function.restype = ctypes.c_bool
            function.argtypes = []
        self.ax.AXIsProcessTrustedWithOptions.restype = ctypes.c_bool
        self.ax.AXIsProcessTrustedWithOptions.argtypes = [ctypes.c_void_p]
        self.cf.CFDictionaryCreate.restype = ctypes.c_void_p
        self.cf.CFDictionaryCreate.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_long,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self.cf.CFRelease.argtypes = [ctypes.c_void_p]

    def status(self, method: str) -> str:
        if method == "ax-trusted":
            return "granted" if self.ax.AXIsProcessTrusted() else "missing"
        if method == "screen-capture-preflight":
            return (
                "granted"
                if self.cg.CGPreflightScreenCaptureAccess()
                else "missing"
            )
        return "unknown"

    def request(self, method: str) -> bool:
        """Raises the system prompt; False when the method has none (the
        caller then opens the Settings pane instead)."""
        if method == "ax-prompt":
            ctypes = self.ctypes
            key = ctypes.c_void_p.in_dll(self.ax, "kAXTrustedCheckOptionPrompt")
            true = ctypes.c_void_p.in_dll(self.cf, "kCFBooleanTrue")
            keys = (ctypes.c_void_p * 1)(key.value)
            values = (ctypes.c_void_p * 1)(true.value)
            options = self.cf.CFDictionaryCreate(
                None,
                keys,
                values,
                1,
                ctypes.addressof(
                    ctypes.c_char.in_dll(
                        self.cf, "kCFTypeDictionaryKeyCallBacks"
                    )
                ),
                ctypes.addressof(
                    ctypes.c_char.in_dll(
                        self.cf, "kCFTypeDictionaryValueCallBacks"
                    )
                ),
            )
            try:
                self.ax.AXIsProcessTrustedWithOptions(options)
            finally:
                self.cf.CFRelease(options)
            return True
        if method == "screen-capture-request":
            self.cg.CGRequestScreenCaptureAccess()
            return True
        return False


_mac_broker: _MacPermissionBroker | None = None


def _broker() -> _MacPermissionBroker | None:
    global _mac_broker
    if sys.platform != "darwin":
        return None
    if _mac_broker is None:
        try:
            _mac_broker = _MacPermissionBroker()
        except (OSError, AttributeError):
            return None
    return _mac_broker


def permission_status(permission_id: str) -> str:
    """ "granted" | "missing" | "unknown" for this process's identity — inside
    the Companion's chain, that is KT Companion's grant."""
    spec = (SYSTEM_PERMISSIONS.get(permission_id) or {}).get("macos") or {}
    broker = _broker()
    if broker is None or not spec.get("status"):
        return "unknown"
    try:
        return broker.status(spec["status"])
    except (OSError, AttributeError, ValueError):
        return "unknown"


# --- the plugin runtime -------------------------------------------------------


class Plugin:
    def __init__(
        self,
        name: str,
        vendor: str,
        version: str,
        meters: list[tuple[str, str, str]] | None = None,
        role: str | None = None,
        config: list[ConfigField] | None = None,
        requires: list[str] | None = None,
        post_install: list[list[str]] | None = None,
        summary: str | None = None,
        description: str | None = None,
        symbol: str | None = None,
        tint: str | None = None,
        category: str | None = None,
        homepage: str | None = None,
        permissions: list[dict] | None = None,
        attestor: CallAttestor | None = None,
    ):
        self.info = {"name": name, "vendor": vendor, "version": version}
        # System permissions this plugin needs (`permission(...)` entries from
        # the registry). The manifest is the contract: a plugin may only
        # request what it declared here.
        self.permissions = list(permissions or [])
        self._permission_requested_at: dict[str, float] = {}
        # How the Companion's window presents the plugin: a one-line summary,
        # a longer description, an SF Symbol name, a "#RRGGBB" tint for the
        # icon, a category, and a homepage URL. All optional, display-only.
        self.listing = {
            key: value
            for key, value in {
                "summary": summary,
                "description": description,
                "symbol": symbol,
                "tint": tint,
                "category": category,
                "homepage": homepage,
            }.items()
            if value
        }
        self.role = role
        # Invoked when the host asks to reveal — a UI-bearing runtime (the
        # companion) surfaces its window here. Left unset, the host is told
        # nothing was revealed so it can fall back to launching the app.
        self.on_reveal: Callable[[], Any] | None = None
        self.config_fields = config or []
        # pip requirement specifiers installed into this plugin's own venv,
        # plus argv (passed to the venv python) run afterwards — e.g.
        # ["-m", "playwright", "install", "chromium"].
        self.requires = requires or []
        self.post_install = post_install or []
        # The plugin's half of verifiable calls; attests nothing by default.
        self.attestor = attestor or CallAttestor()
        self.meters = meters or []
        self.kinds: dict[str, _Kind] = {}
        # Reads a declared resource when the host asks; see resource_reader.
        self._resource_reader: Callable[[str], Awaitable[list]] | None = None
        # (kind name, scope key) -> (provider, allows custom values)
        self._scope_options: dict[
            tuple[str, str], tuple[ScopeOptionsProvider, bool]
        ] = {}
        self.state_dir = _state_dir(name)
        # Random per process launch, so the host can tell a restart from a
        # reconnect.
        self.instance = uuid.uuid4().hex
        # True once the host has welcomed this plugin on the current
        # connection; `host` is that welcome (node id, host instance).
        self.connected = False
        self.host: dict | None = None
        # Futures resolved on connect, so supervisors can AWAIT it instead of
        # sleep-polling. A plain future list (not asyncio.Event): loop-agnostic
        # on every interpreter the runtime may land on.
        self._connected_waiters: list[asyncio.Future] = []
        self._active_calls: dict[str, asyncio.Task] = {}
        self._background: set[asyncio.Task] = set()
        # The live connection: the channel the unary calls ride and the queue
        # the `Connect` stream drains, in order.
        self._channel: Any = None
        self._outbox: asyncio.Queue | None = None

    # -- declaration DSL --

    def kind(
        self,
        name: str,
        *,
        description: str,
        display_name: str | None = None,
        input_schema: dict | None = None,
        scope_schema: dict | None = None,
        default_scope: dict | None = None,
        objects: list[dict] | None = None,
        capabilities: list[str] | None = None,
        uses_act: bool = False,
        sub_tools: list[dict] | None = None,
        resources: list[dict] | None = None,
    ):
        def decorate(handler: Handler) -> Handler:
            self.kinds[name] = _Kind(
                name=name,
                display_name=display_name or name.replace("-", " ").title(),
                description=description,
                input_schema=input_schema,
                scope_schema=scope_schema,
                default_scope=default_scope,
                handler=handler,
                objects=objects,
                capabilities=capabilities,
                uses_act=uses_act,
                sub_tools=sub_tools,
                resources=resources,
            )
            return handler

        return decorate

    def scope_options(
        self, kind_name: str, key: str, *, allows_custom: bool = True
    ):
        """Registers the live choices for one scope key of one of this
        plugin's kinds (`plugin.scope.options`); the key's declaration is
        marked `x-ktpp-options` so the host's form asks for them.

            @plugin.scope_options("computer-use", "allowedApps")
            async def open_apps(request: ScopeOptionsRequest) -> list[dict]:
                return [scope_option("com.apple.Safari", "Safari", app="com.apple.Safari")]

        `allows_custom=False` makes the form offer the choices only, with no
        free entry. Keep providers quick — the user is waiting on the form."""

        def decorate(provider: ScopeOptionsProvider) -> ScopeOptionsProvider:
            self._scope_options[(kind_name, key)] = (provider, allows_custom)
            return provider

        return decorate

    def _declaration(self, kind: _Kind) -> dict:
        decl = kind.declaration()
        live = {
            key: allows_custom
            for (kind_name, key), (
                _,
                allows_custom,
            ) in self._scope_options.items()
            if kind_name == kind.name
        }
        schema = decl.get("scopeSchema")
        if live and isinstance(schema, dict):
            schema = {
                k: dict(v) if isinstance(v, dict) else v
                for k, v in schema.items()
            }
            for key, allows_custom in live.items():
                if isinstance(schema.get(key), dict):
                    schema[key][OPTIONS_KEYWORD] = {
                        "live": True,
                        "allowsCustom": allows_custom,
                    }
            decl["scopeSchema"] = schema
        return decl

    def kinds_payload(self) -> dict:
        kinds = [self._declaration(k) for k in self.kinds.values()]
        payload: dict[str, Any] = {
            "manifestVersion": self.info["version"],
            "kinds": kinds,
            "meters": [
                {"name": n, "quantum": q, "description": d}
                for n, q, d in self.meters
            ],
        }
        if self.permissions:
            payload["permissions"] = self.permissions
        payload["manifestHash"] = "sha256:" + sha256_hex(kinds)
        return payload

    # -- declared resources --

    def resource_reader(self, reader: Callable[[str], Awaitable[list]]):
        """Registers how a declared resource is read: `reader(uri)` returns
        MCP `resources/read` contents ([{uri, mimeType?, text | blob}]) —
        for a plugin wrapping an MCP server, its server's own answer. The SDK
        only ever asks for uris a kind declared (`plugin.kind(resources=…)`).

            @plugin.resource_reader
            async def read(uri):
                return await client.read_resource(uri)
        """
        self._resource_reader = reader
        return reader

    # -- system permissions --

    def permission_status(self, permission_id: str) -> str:
        return permission_status(permission_id)

    def request_permission(self, permission_id: str) -> bool:
        """Asks the user for one DECLARED permission: announces it to the
        Companion app (marker line) and raises the system prompt, which macOS
        attributes to KT Companion. Throttled per permission so a retrying
        agent can't stack prompts. Returns whether a request went out now."""
        declared = {entry["id"]: entry for entry in self.permissions}
        if permission_id not in declared:
            raise ValueError(
                f"{self.info['name']} did not declare {permission_id!r}"
            )
        now = time.monotonic()
        last = self._permission_requested_at.get(permission_id)
        if last is not None and now - last < PERMISSION_REQUEST_INTERVAL:
            return False
        self._permission_requested_at[permission_id] = now
        print(
            PERMISSION_MARKER
            + " "
            + json.dumps(
                {
                    "plugin": self.info["name"],
                    "permission": permission_id,
                    "reason": declared[permission_id].get("reason", ""),
                }
            ),
            flush=True,
        )
        spec = (SYSTEM_PERMISSIONS.get(permission_id) or {}).get("macos") or {}
        broker = _broker()
        prompted = False
        if broker is not None and spec.get("request"):
            try:
                prompted = broker.request(spec["request"])
            except (OSError, AttributeError, ValueError):
                prompted = False
        if (
            not prompted
            and spec.get("settingsURL")
            and sys.platform == "darwin"
        ):
            subprocess.run(["/usr/bin/open", spec["settingsURL"]], check=False)
        return True

    # -- dependency provisioning (per-plugin venv) --

    @property
    def venv_dir(self) -> Path:
        return self.state_dir / "venv"

    @property
    def venv_python(self) -> Path:
        return self.venv_dir / "bin" / "python"

    @property
    def requirements(self) -> list[str]:
        """Everything the plugin's own interpreter needs: the SDK's dependency
        plus whatever the plugin declared."""
        return SDK_REQUIREMENTS + list(self.requires)

    @property
    def _provision_marker(self) -> Path:
        return self.venv_dir / ".kt-provisioned"

    @property
    def _requirements_hash(self) -> str:
        payload = {
            "requires": self.requirements,
            "postInstall": self.post_install,
        }
        return hashlib.sha256(canonical(payload)).hexdigest()[:16]

    @property
    def is_provisioned(self) -> bool:
        """True when a venv exists whose recorded requirement set still matches
        the declaration — so bumping `requires` re-provisions automatically."""
        if not self.venv_python.exists():
            return False
        try:
            return (
                self._provision_marker.read_text().strip()
                == self._requirements_hash
            )
        except OSError:
            return False

    @property
    def interpreter(self) -> str:
        """The python that should run this plugin: its venv when provisioned,
        otherwise whatever is running the companion (fine for dependency-free
        plugins)."""
        return str(self.venv_python) if self.is_provisioned else sys.executable

    @staticmethod
    def _venv_base_interpreter() -> str:
        """The python a NEW venv should be built from: the first available
        interpreter of version ≥ 3.10. `sys.executable` alone is wrong here —
        the Companion may itself run under an older embedded python (Xcode
        ships 3.9), and a venv inherits its base's version, silently making
        modern dependencies (markitdown needs ≥ 3.10) uninstallable."""
        import shutil

        candidates = [
            shutil.which("python3"),
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
            "/usr/bin/python3",
            sys.executable,
        ]
        for candidate in candidates:
            if not candidate or not Path(candidate).exists():
                continue
            probe = subprocess.run(
                [
                    candidate,
                    "-c",
                    "import sys; print(sys.version_info >= (3, 10))",
                ],
                capture_output=True,
                text=True,
            )
            if probe.returncode == 0 and probe.stdout.strip() == "True":
                return candidate
        return sys.executable

    def _venv_needs_rebuild(self) -> bool:
        """True when an EXISTING venv was built from a pre-3.10 python while a
        modern base is available. Real failure mode: an early Install click
        under an old embedded interpreter (Xcode ships 3.9) built a 3.9 venv,
        and pip then quietly resolved ancient dependency versions into it —
        `markitdown` "installed" as a years-old release. Rebuilding from the
        modern base is always safe (dependencies are reinstalled)."""
        if not self.venv_python.exists():
            return False
        probe = subprocess.run(
            [
                str(self.venv_python),
                "-c",
                "import sys; print(sys.version_info >= (3, 10))",
            ],
            capture_output=True,
            text=True,
        )
        venv_modern = probe.returncode == 0 and probe.stdout.strip() == "True"
        if venv_modern:
            return False
        base_probe = subprocess.run(
            [
                self._venv_base_interpreter(),
                "-c",
                "import sys; print(sys.version_info >= (3, 10))",
            ],
            capture_output=True,
            text=True,
        )
        return (
            base_probe.returncode == 0 and base_probe.stdout.strip() == "True"
        )

    def provision(self, log: Callable[[str], None] = print) -> bool:
        """Creates the plugin's venv and installs its dependencies. Safe to
        re-run; returns True on success."""
        if not self.requires:
            log(f"[{self.info['name']}] no declared dependencies")
        try:
            if self._venv_needs_rebuild():
                import shutil

                log(
                    f"[{self.info['name']}] rebuilding venv (base python too old)"
                )
                shutil.rmtree(self.venv_dir, ignore_errors=True)
            if not self.venv_python.exists():
                base = self._venv_base_interpreter()
                log(
                    f"[{self.info['name']}] creating venv at {self.venv_dir} (base: {base})"
                )
                subprocess.run(
                    [base, "-m", "venv", str(self.venv_dir)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            steps: list[list[str]] = [
                [
                    str(self.venv_python),
                    "-m",
                    "pip",
                    "install",
                    "--upgrade",
                    "pip",
                ],
                [
                    str(self.venv_python),
                    "-m",
                    "pip",
                    "install",
                    *self.requirements,
                ],
            ]
            steps += [
                [str(self.venv_python), *argv] for argv in self.post_install
            ]
            for argv in steps:
                log(f"[{self.info['name']}] $ {' '.join(argv[1:])}")
                result = subprocess.run(argv, capture_output=True, text=True)
                if result.returncode != 0:
                    tail = (
                        (result.stderr or result.stdout)
                        .strip()
                        .splitlines()[-4:]
                    )
                    log(f"[{self.info['name']}] FAILED: " + " / ".join(tail))
                    return False
            self._provision_marker.write_text(self._requirements_hash)
            log(f"[{self.info['name']}] provisioned")
            return True
        except subprocess.CalledProcessError as error:
            log(
                f"[{self.info['name']}] venv creation failed: {error.stderr or error}"
            )
            return False
        except OSError as error:
            log(f"[{self.info['name']}] provisioning failed: {error}")
            return False

    # -- runtime configuration --

    def _config_file_values(self) -> dict:
        config_file = self.state_dir / "config.json"
        if config_file.exists():
            try:
                loaded = json.loads(config_file.read_text())
                return loaded if isinstance(loaded, dict) else {}
            except json.JSONDecodeError:
                return {}
        return {}

    @property
    def config(self) -> dict:
        """Resolved configuration: config.json (Companion-written) > env > default."""
        file_values = self._config_file_values()
        resolved: dict[str, Any] = {}
        for field in self.config_fields:
            if field.key in file_values and file_values[field.key] not in (
                None,
                "",
            ):
                resolved[field.key] = file_values[field.key]
            elif field.env and os.environ.get(field.env):
                resolved[field.key] = os.environ[field.env]
            else:
                resolved[field.key] = field.default
        return resolved

    def describe(self) -> dict:
        """Machine-readable description for the Companion app (`--describe`)."""
        file_values = self._config_file_values()
        resolved = self.config
        return {
            "name": self.info["name"],
            "vendor": self.info["vendor"],
            "version": self.info["version"],
            **self.listing,
            "role": self.role,
            "stateDir": str(self.state_dir),
            "requires": self.requires,
            "provisioned": self.is_provisioned,
            "venvPath": str(self.venv_dir) if self.requires else None,
            "permissions": self.permissions,
            "kinds": [
                {
                    "kindName": k.name,
                    "displayName": k.display_name,
                    "description": k.description,
                }
                for k in self.kinds.values()
            ],
            "config": [
                field.describe(
                    resolved.get(field.key),
                    from_file_or_env=bool(
                        file_values.get(field.key) not in (None, "")
                        or (field.env and os.environ.get(field.env))
                    ),
                )
                for field in self.config_fields
            ],
        }

    # -- connection state supervisors can AWAIT (no sleep-polling) --

    @staticmethod
    def _notify(waiters: list[asyncio.Future]) -> None:
        for future in waiters:
            if not future.done():
                future.set_result(True)
        waiters.clear()

    async def wait_connected(self, timeout: float | None = None) -> bool:
        """Resolves once the host has welcomed this plugin. True immediately
        when already connected; False on timeout."""
        if self.connected:
            return True
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._connected_waiters.append(future)
        try:
            await asyncio.wait_for(future, timeout)
            return True
        except asyncio.TimeoutError:
            return False

    # -- talking to the host --

    def _queue(self, message: dict) -> None:
        """Queues one message on the connection, in order. Dropped when not
        connected — nobody is left to answer."""
        if self._outbox is not None:
            self._outbox.put_nowait(message)

    def _reply(self, request_id: int | None, body_key: str, body: dict) -> None:
        self._queue({"replyTo": request_id, body_key: body})

    def _fail(self, request_id: int | None, code: str, message: str) -> None:
        self._reply(request_id, "failure", {"code": code, "message": message})

    def _spawn(self, coroutine: Awaitable[Any]) -> asyncio.Task:
        task = asyncio.ensure_future(coroutine)
        self._background.add(task)
        task.add_done_callback(self._background.discard)
        return task

    async def _unary(self, method: str, payload: dict, timeout: float) -> dict:
        """One plugin → host RPC (`RequestAct`, `ProposeAction`,
        `OpenAddAction`). Raises RuntimeError when not connected; gRPC
        failures propagate as ``grpc.aio.AioRpcError``."""
        channel = self._channel
        if channel is None or not self.connected:
            raise RuntimeError("not connected to a host")
        rpc = channel.unary_unary(
            method, request_serializer=_encode, response_deserializer=_decode
        )
        return await rpc(payload, timeout=timeout)

    async def propose_action(
        self,
        kind_name: str,
        *,
        suggested_name: str | None = None,
        reason: str | None = None,
        suggested_scope: dict | None = None,
        timeout: float = 300.0,
    ) -> dict:
        """Asks the HOST to create an action instance of one of this plugin's
        kinds (`ProposeAction`).

        This is a proposal, never a command: the user sees it, edits the scope,
        and confirms. Returns the host's verdict —
        ``{"status": "created"|"declined"|"unsupported", "actionID": …}``.
        A plugin may only propose its own kinds; the host rejects anything else.
        """
        if kind_name not in self.kinds:
            raise ValueError(
                f"{kind_name!r} is not a kind this plugin declares"
            )
        payload: dict[str, Any] = {
            "pluginName": self.info["name"],
            "kindName": kind_name,
        }
        if suggested_name:
            payload["suggestedName"] = suggested_name
        if reason:
            payload["reason"] = reason
        if suggested_scope is not None:
            payload["suggestedScope"] = suggested_scope
        try:
            return await self._unary(PROPOSE_ACTION_METHOD, payload, timeout)
        except Exception as error:
            return {"status": "unsupported", "message": _rpc_failure(error)}

    async def request_open_add_action(
        self,
        kind_name: str | None = None,
        plugin_name: str | None = None,
        timeout: float = 10.0,
    ) -> dict:
        """Asks the HOST to open its Add Action flow (`OpenAddAction`),
        optionally pre-scoped to a kind."""
        payload: dict[str, Any] = {}
        if kind_name:
            payload["kindName"] = kind_name
        if plugin_name:
            payload["pluginName"] = plugin_name
        try:
            await self._unary(OPEN_ADD_ACTION_METHOD, payload, timeout)
            return {"status": "ok"}
        except Exception as error:
            return {"status": "error", "message": _rpc_failure(error)}

    # -- lifecycle --

    def run(self, socket_path: str | None = None) -> None:
        asyncio.run(self.serve_forever(socket_path))

    async def serve_forever(self, socket_path: str | None = None) -> None:
        """Connects to the host and serves it until a newer copy of this
        plugin replaces it: waits while the host is away (the gRPC channel
        reconnects by itself) and reconnects after any drop."""
        import grpc

        tag = self.info["name"]
        while True:
            path = socket_path
            if path is None:
                try:
                    path = discover_socket_path()
                except RuntimeError:
                    await asyncio.sleep(1.0)  # nothing published yet
                    continue
            channel = grpc.aio.insecure_channel(
                f"unix:{path}", options=CHANNEL_OPTIONS
            )
            try:
                try:
                    # Waits while the host is away. Gives up now and then only
                    # to re-read discovery, in case a host appeared elsewhere.
                    await asyncio.wait_for(
                        channel.channel_ready(), timeout=10.0
                    )
                except asyncio.TimeoutError:
                    continue
                if await self._serve_connection(channel, path) == "superseded":
                    print(
                        f"[{tag}] a newer copy of this plugin connected; exiting",
                        flush=True,
                    )
                    return
            except grpc.aio.AioRpcError as error:
                print(
                    f"[{tag}] connection ended ({error.code().name}: {error.details()})",
                    flush=True,
                )
            finally:
                await channel.close()
            await asyncio.sleep(0.5)

    async def _serve_connection(self, channel: Any, path: str) -> str | None:
        """One connection: hello and kinds out, then the host's requests in,
        until either side ends it. Returns the goodbye reason that ended it,
        if the host gave one."""
        outbox: asyncio.Queue = asyncio.Queue()
        outbox.put_nowait(
            {
                "hello": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "name": self.info["name"],
                    "vendor": self.info["vendor"],
                    "version": self.info["version"],
                    "role": self.role or "plugin",
                    "instance": self.instance,
                    "features": [],
                }
            }
        )
        outbox.put_nowait({"kinds": self.kinds_payload()})

        async def outgoing():
            while True:
                message = await outbox.get()
                if message is None:
                    return
                yield message

        connect = channel.stream_stream(
            CONNECT_METHOD,
            request_serializer=_encode,
            response_deserializer=_decode,
        )
        call = connect(outgoing())
        self._channel = channel
        self._outbox = outbox
        try:
            async for message in call:
                verdict = self._receive(message, path)
                if verdict is not None:
                    return verdict
            return None
        finally:
            self.connected = False
            self._outbox = None
            self._channel = None
            outbox.put_nowait(None)
            # The host already failed these calls when the connection went;
            # stop the work nobody is waiting for.
            for task in list(self._active_calls.values()):
                task.cancel()
            call.cancel()

    def _receive(self, message: dict, path: str) -> str | None:
        """Routes one host message. Requests answer on their own tasks so a
        slow handler never stalls the connection; returns a goodbye reason
        when the host is ending it."""
        request_id = message.get("id")
        if "welcome" in message:
            self.host = message["welcome"]
            self.connected = True
            self._notify(self._connected_waiters)
            host_node = str((self.host or {}).get("hostNodeID", ""))
            print(
                f"[{self.info['name']}] connected {path} (host {host_node[:8]})",
                flush=True,
            )
        elif "call" in message:
            call = message["call"] or {}
            call_id = call.get("requestID", "")
            task = self._spawn(self._handle_call(request_id, call))
            self._active_calls[call_id] = task
            task.add_done_callback(
                lambda _: self._active_calls.pop(call_id, None)
            )
        elif "cancel" in message:
            call_id = (message["cancel"] or {}).get("requestID", "")
            if task := self._active_calls.get(call_id):
                task.cancel()
        elif "scopeOptions" in message:
            self._spawn(
                self._answer_scope_options(
                    request_id, message["scopeOptions"] or {}
                )
            )
        elif "resourceRead" in message:
            self._spawn(
                self._answer_resource_read(
                    request_id, message["resourceRead"] or {}
                )
            )
        elif "reveal" in message:
            self._spawn(self._answer_reveal(request_id))
        elif "goodbye" in message:
            reason = (message["goodbye"] or {}).get("reason") or "goodbye"
            print(
                f"[{self.info['name']}] host said goodbye ({reason})",
                flush=True,
            )
            return reason
        elif request_id is not None:
            self._fail(
                request_id,
                "unsupported",
                "this plugin does not handle that request",
            )
        return None

    # -- answering the host --

    async def _answer_reveal(self, request_id: int | None) -> None:
        revealed = False
        if self.on_reveal is not None:
            result = self.on_reveal()
            if asyncio.iscoroutine(result):
                await result
            revealed = True
        self._reply(request_id, "reveal", {"revealed": revealed})

    async def _answer_scope_options(
        self, request_id: int | None, payload: dict
    ) -> None:
        kind_name, key = payload.get("kindName", ""), payload.get("key", "")
        entry = self._scope_options.get((kind_name, key))
        if entry is None:
            self._fail(
                request_id,
                "unsupported",
                f"{kind_name} offers no choices for {key!r}",
            )
            return
        provider, _ = entry
        request = ScopeOptionsRequest(
            kind_name=kind_name,
            key=key,
            scope=payload.get("scope") or {},
            query=payload.get("query") or None,
            config=self.config,
        )
        try:
            options = [
                option
                for option in (await provider(request) or [])
                if isinstance(option, dict)
                and "value" in option
                and option.get("label")
            ][:MAX_SCOPE_OPTIONS]
        except Exception as failure:  # a provider bug is an answer, not a crash
            self._fail(
                request_id, "internal", str(failure) or type(failure).__name__
            )
            return
        self._reply(request_id, "scopeOptions", {"options": options})

    async def _answer_resource_read(
        self, request_id: int | None, payload: dict
    ) -> None:
        kind = self.kinds.get(payload.get("kindName", ""))
        uri = payload.get("uri", "")
        if kind is None or not any(
            r.get("uri") == uri for r in kind.resources or []
        ):
            self._fail(
                request_id,
                "invalidArgument",
                f"{uri!r} is not a declared resource",
            )
            return
        if self._resource_reader is None:
            self._fail(
                request_id, "unsupported", "this plugin has no resource reader"
            )
            return
        try:
            contents = [
                c
                for c in (await self._resource_reader(uri) or [])
                if isinstance(c, dict)
            ]
        except Exception as failure:  # the reader's refusal is an answer
            self._fail(
                request_id, "internal", str(failure) or type(failure).__name__
            )
            return
        self._reply(request_id, "resourceRead", {"contents": contents})

    async def _handle_call(self, request_id: int | None, call: dict) -> None:
        usage: dict[str, int] = {}
        refusal = self.attestor.check_authorization(call)
        if refusal is not None:
            content, is_error = [{"type": "text", "text": refusal}], True
        else:
            try:
                content, is_error = await self._execute_call(call, usage)
            except asyncio.CancelledError:
                content, is_error = (
                    [{"type": "text", "text": "call cancelled"}],
                    True,
                )
            except (
                Exception
            ) as error:  # handler bugs become error results, not crashes
                content, is_error = [{"type": "text", "text": str(error)}], True

        result: dict[str, Any] = {
            "requestID": call.get("requestID", ""),
            "content": content,
            "isError": is_error,
            "usage": [
                {"meter": meter, "units": units}
                for meter, units in sorted(usage.items())
            ],
        }
        receipt = self.attestor.receipt(
            call,
            {"content": content, "isError": is_error, "usage": result["usage"]},
        )
        if receipt is not None:
            result["receipt"] = receipt
        self._reply(request_id, "callResult", result)

    async def _execute_call(
        self, call: dict, usage: dict[str, int]
    ) -> tuple[list[dict], bool]:
        kind_name = call.get("kindName", "")
        kind = self.kinds.get(kind_name)
        if kind is None:
            return [{"type": "text", "text": f"unknown kind {kind_name}"}], True

        instance = call.get("instance") or {}
        resources_block = call.get("resources")
        context = CallContext(
            instance_id=instance.get("id", ""),
            scope=instance.get("scope"),
            config=self.config,
            _usage=usage,
            resources=Resources((resources_block or {}).get("entries")),
            tool=call.get("tool"),
            _plugin=self,
            _request_id=call.get("requestID", ""),
        )
        result = await kind.handler(call.get("arguments") or {}, context)

        if isinstance(result, tuple):
            content, is_error = result
        else:
            content, is_error = result, False
        if isinstance(content, str):
            content = [{"type": "text", "text": content}]
        return content, is_error

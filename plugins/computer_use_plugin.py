"""Computer Use — background control of macOS apps through Cua Driver.

Registers the `computer-use` action kind: a curated, app-scoped slice of
Cua Driver's MCP server (https://github.com/trycua/cua, MIT), the open-source
background computer-use driver. The agent reads a window's accessibility tree
plus screenshot and acts on elements by token — clicks, typing, keys, menus —
posted to the target process, so the user's own cursor and focus stay put.

How it is wired:
  * the driver ships in this plugin's venv as the `cua-driver` wheel (a signed
    binary, no other dependencies);
  * it runs EMBEDDED: a private daemon spawned down the Companion's own process
    chain, so macOS charges Accessibility / Screen Recording to KT Companion —
    one grant, no second app in Privacy & Security, and the driver never
    prompts on its own;
  * this plugin talks MCP to it (`cua-driver mcp --embedded`) and exposes only
    the tools below — never shell, clipboard, browser CDP, recording, process
    killing, config, or self-update.

Enforcement is dual, as for every KTPP kind: the host gates the call against
the caller's grant, and this handler re-checks the instance scope before
anything reaches the driver — the target app (`allowedApps`), whether the
instance may act at all (`control`), and whether it may take the foreground
(`foreground`). Some apps are never reachable (KeepTalking itself, password
managers, Keychain Access) and some only when an instance names them
explicitly (terminals, System Settings, script runners).
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import time
from pathlib import Path

from keeptalking_mcp import McpError, McpStdioClient, kt_content
from keeptalking_plugin import (
    CallContext,
    Plugin,
    ScopeOptionsRequest,
    config_field,
    permission,
    resource,
    scope_option,
)

DRIVER_REQUIREMENT = "cua-driver==0.34.0"
SESSION = "KeepTalking"  # also the badge under the agent cursor
HOST_BUNDLE_ID = "org.rcex.KeepTalkingCompanion"  # advisory label only
CALL_TIMEOUT = 90.0
DEFAULT_MAX_ELEMENTS = 400
APP_CACHE_TTL = 15.0

# Apps no instance may observe or drive. KeepTalking and the Companion would let
# an agent approve its own grants; the rest hold credentials.
BLOCKED_APPS = {
    "org.rcex.keeptalkingapp",
    "org.rcex.keeptalkingcompanion",
    "com.apple.keychainaccess",
    "com.apple.passwords",
    "com.1password.1password",
    "com.agilebits.onepassword7",
    "com.agilebits.onepassword-osx",
    "com.bitwarden.desktop",
    "com.lastpass.lastpass",
    "com.dashlane.dashlanephonefinal",
    "org.keepassxc.keepassxc",
    # System consent and authentication surfaces.
    "com.apple.securityagent",
    "com.apple.localauthentication.uiagent",
    "com.apple.usernotificationcenter",
    "com.apple.coreservices.uiagent",
}
BLOCKED_NAMES = {
    "keeptalking", "kt companion", "keychain access", "passwords", "1password",
    "bitwarden", "lastpass", "dashlane", "keepassxc",
}
# Apps that amount to shell access or system configuration: reachable only
# when an instance's allowedApps names them, never through an empty
# ("any app") allowlist. The value is the caution the scope form shows.
_SHELL = "Can run any command on this Mac"
_SCRIPTS = "Can run scripts and automations"
EXPLICIT_ONLY_APPS = {
    "com.apple.systempreferences": "Can change privacy and security settings",
    "com.apple.terminal": _SHELL,
    "com.googlecode.iterm2": _SHELL,
    "dev.warp.warp-stable": _SHELL,
    "com.mitchellh.ghostty": _SHELL,
    "net.kovidgoyal.kitty": _SHELL,
    "org.alacritty": _SHELL,
    "com.github.wez.wezterm": _SHELL,
    "com.apple.scripteditor2": _SCRIPTS,
    "com.apple.automator": _SCRIPTS,
    "com.apple.shortcuts": _SCRIPTS,
    "com.anthropic.claudefordesktop": "Another AI agent with its own permissions",
}

# --- the curated tool surface -------------------------------------------------

_DELIVERY = {
    "type": "string",
    "enum": ["background", "foreground"],
    "description": "background (default) never fronts the app; foreground briefly "
    "fronts the window, acts, then restores the user's app — needs window_id and "
    "an instance that allows foreground",
}
PROPERTIES: dict[str, dict] = {
    "pid": {"type": "integer", "description": "Target app's process ID (from list_apps or launch_app)"},
    "window_id": {"type": "integer", "description": "Window ID from list_windows / launch_app"},
    "element_token": {
        "type": "string",
        "description": "Element handle from the latest get_window_state of that window "
        "(e.g. s1a2b3c4d:12). Preferred over x,y; stale after the next snapshot",
    },
    "x": {"type": "number", "description": "X in the window screenshot's pixels (top-left origin)"},
    "y": {"type": "number", "description": "Y in the window screenshot's pixels"},
    "from_zoom": {"type": "boolean", "description": "x,y are in the last zoom image, not the full window"},
    "capture_id": {"type": "string", "description": "Bind x,y to this exact capture from get_window_state"},
    "button": {"type": "string", "enum": ["left", "right", "middle"], "description": "Mouse button (default left)"},
    "count": {"type": "integer", "description": "Click count for pixel clicks (2 = double-click)"},
    "action": {
        "type": "string",
        "description": "AX action for element clicks: press (default), show_menu, pick, confirm, cancel, open",
    },
    "modifiers": {
        "type": "array", "items": {"type": "string"},
        "description": "Held modifiers: cmd, shift, option, ctrl, fn",
    },
    "delivery_mode": _DELIVERY,
    "text": {"type": "string", "description": "Text to insert at the target's cursor"},
    "key": {
        "type": "string",
        "description": "Key name: return, tab, escape, space, delete, up/down/left/right, "
        "home, end, pageup, pagedown, f1-f12, or a letter/digit",
    },
    "keys": {
        "type": "array", "items": {"type": "string"},
        "description": "Modifier(s) plus one key, e.g. [\"cmd\", \"s\"]",
    },
    "value": {
        "type": "string",
        "description": "New value: a popup/select option's title, or an AXValue for sliders, "
        "steppers, date pickers and plain text fields",
    },
    "direction": {"type": "string", "enum": ["up", "down", "left", "right"], "description": "Scroll direction"},
    "amount": {"type": "integer", "description": "Wheel notches or key repeats (default 3, max 50)"},
    "by": {"type": "string", "enum": ["line", "page"], "description": "Scroll granularity (default line)"},
    "path": {
        "type": "array", "items": {"type": "string"},
        "description": "Menu labels from the menu bar down, e.g. [\"File\", \"Export as PDF…\"]",
    },
    "from_x": {"type": "number", "description": "Drag start X (window screenshot pixels)"},
    "from_y": {"type": "number", "description": "Drag start Y"},
    "to_x": {"type": "number", "description": "Drag end X"},
    "to_y": {"type": "number", "description": "Drag end Y"},
    "duration_ms": {"type": "integer", "description": "Drag duration (default 500)"},
    "x1": {"type": "number", "description": "Zoom region left (window screenshot pixels)"},
    "y1": {"type": "number", "description": "Zoom region top"},
    "x2": {"type": "number", "description": "Zoom region right"},
    "y2": {"type": "number", "description": "Zoom region bottom"},
    "bundle_id": {"type": "string", "description": "App bundle ID, e.g. com.apple.TextEdit (preferred over name)"},
    "name": {"type": "string", "description": "App display name, used when bundle_id is absent"},
    "urls": {
        "type": "array", "items": {"type": "string"},
        "description": "Files or URLs the launched app should open",
    },
    "query": {"type": "string", "description": "Only return tree rows matching this text (plus their ancestors)"},
    "include_screenshot": {
        "type": "boolean",
        "description": "Attach the window screenshot (default true; false is cheaper when only re-indexing)",
    },
    "max_elements": {"type": "integer", "description": f"Cap on tree rows (default {DEFAULT_MAX_ELEMENTS})"},
    "on_screen_only": {"type": "boolean", "description": "Only windows on the current Space"},
}


class _Tool:
    def __init__(
        self,
        summary: str,
        params: list[str],
        required: list[str] | None = None,
        *,
        acts: bool = False,
        foreground: bool = False,
        renames: dict[str, str] | None = None,
        verb: str = "",
    ):
        self.summary = summary
        self.params = params
        self.required = list(required or [])
        self.acts = acts            # needs scope.control
        self.foreground = foreground  # always takes the foreground
        self.renames = renames or {}  # KT argument name -> driver argument name
        self.verb = verb


TOOLS: dict[str, _Tool] = {
    "list_apps": _Tool(
        "Running and installed apps this instance may use, with pids and windows", []),
    "list_windows": _Tool(
        "Windows (id, title, on-screen / other Space) of one app or all permitted apps",
        ["pid", "on_screen_only"]),
    "get_window_state": _Tool(
        "A window's accessibility tree (rows with element_token) plus a screenshot",
        ["pid", "window_id", "query", "include_screenshot", "max_elements"],
        ["pid", "window_id"], verb="Reading"),
    "zoom": _Tool(
        "A close-up JPEG of a window region; follow with from_zoom=true on click",
        ["pid", "window_id", "x1", "y1", "x2", "y2"],
        ["pid", "window_id", "x1", "y1", "x2", "y2"], verb="Zooming into"),
    "launch_app": _Tool(
        "Launch (or find) an app in the background and return its pid and windows",
        ["bundle_id", "name", "urls"], acts=True, verb="Launching"),
    "click": _Tool(
        "Click an element (element_token) or window pixels (x,y)",
        ["pid", "window_id", "element_token", "x", "y", "from_zoom", "capture_id",
         "button", "count", "action", "modifiers", "delivery_mode"],
        ["pid"], acts=True, renames={"modifiers": "modifier"}, verb="Clicking in"),
    "type_text": _Tool(
        "Insert text into the focused field, or the field at element_token / x,y",
        ["pid", "text", "window_id", "element_token", "x", "y", "delivery_mode"],
        ["pid", "text"], acts=True, verb="Typing into"),
    "press_key": _Tool(
        "Press one key, optionally with modifiers",
        ["pid", "key", "modifiers", "window_id", "element_token", "delivery_mode"],
        ["pid", "key"], acts=True, verb="Pressing a key in"),
    "hotkey": _Tool(
        "Press a key combination such as cmd+s",
        ["pid", "keys", "window_id", "element_token", "delivery_mode"],
        ["pid", "keys"], acts=True, verb="Pressing a shortcut in"),
    "set_value": _Tool(
        "Choose a popup/select option or set a control's value directly",
        ["pid", "value", "element_token", "window_id"],
        ["pid", "value"], acts=True, verb="Setting a value in"),
    "scroll": _Tool(
        "Scroll at an element or point, or the focused region",
        ["pid", "direction", "amount", "by", "window_id", "element_token", "x", "y",
         "delivery_mode"],
        ["pid", "direction"], acts=True, verb="Scrolling in"),
    "invoke_menu": _Tool(
        "Invoke an app menu item by its label path",
        ["pid", "window_id", "path"], ["pid", "window_id", "path"],
        acts=True, verb="Using the menu of"),
    "drag": _Tool(
        "Drag between two window points (always briefly takes the foreground)",
        ["pid", "window_id", "from_x", "from_y", "to_x", "to_y", "button", "modifiers",
         "duration_ms", "from_zoom"],
        ["pid", "window_id", "from_x", "from_y", "to_x", "to_y"],
        acts=True, foreground=True, renames={"modifiers": "modifier"}, verb="Dragging in"),
    "bring_to_front": _Tool(
        "Activate an app and leave it frontmost (steals focus; rarely needed)",
        ["pid", "window_id"], ["pid"], acts=True, foreground=True,
        verb="Bringing to front:"),
}
OBSERVATION_TOOLS = {name for name, spec in TOOLS.items() if not spec.acts}

# The driver's resources this kind exposes — its own operating guide and the
# notes that apply to the tools above (browser, Linux, recording and embedding
# docs cover surfaces this plugin doesn't offer).
CUA_RESOURCES = [
    resource(
        "skill://cua-driver/SKILL.md", "SKILL.md", title="Cua Driver guide",
        description="How to drive a GUI app: snapshot the window, act through element "
        "tokens, menu paths or pixels, and verify from fresh state",
        mime_type="text/markdown"),
    resource(
        "skill://cua-driver/MACOS.md", "MACOS.md", title="macOS notes",
        description="macOS specifics: background delivery, Spaces, focus, permissions",
        mime_type="text/markdown"),
    resource(
        "skill://cua-driver/WORKFLOW.md", "WORKFLOW.md", title="Workflow patterns",
        description="Multi-step task patterns and recovery when an action doesn't land",
        mime_type="text/markdown"),
    resource(
        "skill://cua-driver/VISUAL.md", "VISUAL.md", title="Visual grounding",
        description="Working from screenshots and zoom when the accessibility tree is thin",
        mime_type="text/markdown"),
]
INTEGER_PARAMS = {"pid", "window_id", "count", "amount", "duration_ms", "max_elements"}


def _input_schema() -> dict:
    used = sorted({p for spec in TOOLS.values() for p in spec.params})
    properties: dict[str, dict] = {
        "tool": {
            "type": "string",
            "enum": list(TOOLS),
            "description": "Which operation: "
            + "; ".join(f"{name} — {spec.summary}" for name, spec in TOOLS.items()),
        }
    }
    properties.update({p: PROPERTIES[p] for p in used})
    return {
        "type": "object",
        "title": "computer-use",
        "properties": properties,
        "required": ["tool"],
        "additionalProperties": False,
    }


def _sub_tools() -> list[dict]:
    return [
        {
            "name": name,
            "description": spec.summary,
            "inputSchema": {
                "type": "object",
                "properties": {p: PROPERTIES[p] for p in spec.params},
                "required": spec.required,
                "additionalProperties": False,
            },
        }
        for name, spec in TOOLS.items()
    ]


# --- scope ----------------------------------------------------------------------

def _app_refusal(bundle_id: str | None, name: str | None, allowed: list[str]) -> str | None:
    """Why this instance may not touch the app, or None when it may."""
    bundle = (bundle_id or "").lower()
    title = (name or "").lower()
    label = name or bundle_id or "this app"
    if bundle in BLOCKED_APPS or title in BLOCKED_NAMES:
        return f"{label} is never available to computer use"
    named = {entry.strip().lower() for entry in allowed if entry.strip()}
    explicit = bool(named & {bundle, title} - {""})
    if bundle in EXPLICIT_ONLY_APPS and not explicit:
        return (f"{label} is only reachable when this instance's allowedApps "
                f"names it explicitly")
    if named and not explicit:
        return f"{label} is outside this instance's allowedApps ({', '.join(allowed)})"
    return None


def _scope(ctx: CallContext) -> tuple[list[str], bool, bool]:
    scope = ctx.scope or {}
    allowed = [str(a) for a in scope.get("allowedApps") or [] if str(a).strip()]
    return allowed, bool(scope.get("control", True)), bool(scope.get("foreground", False))


# --- the embedded driver ----------------------------------------------------------

class DriverUnavailable(RuntimeError):
    pass


def _driver_binary() -> Path:
    # find_spec locates the package without importing it (its __init__ loads
    # a 55 MB native SDK this plugin never uses).
    spec = importlib.util.find_spec("cua_driver")
    locations = list(spec.submodule_search_locations or []) if spec else []
    for location in locations:
        binary = Path(location) / "bin" / "cua-driver"
        if binary.exists():
            if not os.access(binary, os.X_OK):
                binary.chmod(0o755)
            return binary
    raise DriverUnavailable(
        "Cua Driver is not installed — use Install for Computer Use in the KT "
        "Companion (or: companion.py --provision ComputerUse)")


class Driver:
    """A private `cua-driver serve --embedded` daemon plus the MCP proxy this
    plugin speaks to. Started on first use; restarted when either dies. Both
    children exit with this process: the daemon watches its stdin pipe
    (CUA_DRIVER_PARENT_LIVENESS_STDIN) and the proxy exits on stdin EOF."""

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.socket = state_dir / "driver.sock"
        self.log = state_dir / "driver.log"
        self.client: McpStdioClient | None = None
        self.daemon: asyncio.subprocess.Process | None = None
        self.permissions: dict = {}
        self.started_at = 0.0
        self._lock = asyncio.Lock()
        self._apps: list[dict] = []
        self._apps_at = 0.0

    def _env(self, config: dict) -> dict[str, str]:
        # Inherited CUA_* settings (an unrestricted permission mode, a stray
        # socket) never reach the embedded driver; this plugin sets its own.
        env = {k: v for k, v in os.environ.items() if not k.startswith("CUA_")}
        env.update({
            "CUA_DRIVER_EMBEDDED": "1",
            "CUA_DRIVER_HOST_BUNDLE_ID": HOST_BUNDLE_ID,
            "CUA_DRIVER_PARENT_LIVENESS_STDIN": "1",
            "CUA_DRIVER_RS_HOME": str(self.state_dir / "driver-home"),
            "CUA_DRIVER_INSTALL_CHANNEL": "python_package",
            "CUA_DRIVER_RS_UPDATE_CHECK": "0",
            "CUA_DRIVER_RS_TELEMETRY_ENABLED": "0",
            "CUA_TELEMETRY_ENABLED": "false",
            "DO_NOT_TRACK": "1",
        })
        if config.get("fast_actions"):
            env["CUA_DRIVER_WINDOW_CHANGE_TIMEOUT_MS"] = "200"
        return env

    @property
    def running(self) -> bool:
        return (
            self.client is not None and self.client.running
            and self.daemon is not None and self.daemon.returncode is None
        )

    async def ensure(self, config: dict) -> McpStdioClient:
        async with self._lock:
            if self.running:
                assert self.client is not None
                return self.client
            await self._stop_locked()
            await self._start_locked(config)
            assert self.client is not None
            return self.client

    async def restart(self, config: dict) -> None:
        async with self._lock:
            await self._stop_locked()
            await self._start_locked(config)

    async def _start_locked(self, config: dict) -> None:
        binary = _driver_binary()
        env = self._env(config)
        if self.socket.exists():
            self.socket.unlink()
        (self.state_dir / "driver-home").mkdir(exist_ok=True)
        with open(self.log, "wb") as log:  # one run per log
            self.daemon = await asyncio.create_subprocess_exec(
                str(binary), "serve", "--embedded", "--permission-mode", "standard",
                "--socket", str(self.socket),
                stdin=asyncio.subprocess.PIPE,  # never written: the liveness pipe
                stdout=log, stderr=log, env=env,
            )
        deadline = time.monotonic() + 15.0
        while not self.socket.exists():
            if self.daemon.returncode is not None or time.monotonic() > deadline:
                tail = self.log.read_text(errors="replace")[-600:].strip()
                await self._stop_locked()
                raise DriverUnavailable(f"Cua Driver daemon did not start: {tail or 'no output'}")
            await asyncio.sleep(0.05)

        client = McpStdioClient(
            [str(binary), "mcp", "--embedded", "--socket", str(self.socket)],
            env=env, stderr_path=self.log, client_name="keeptalking-computer-use",
        )
        self.client = client
        try:
            await client.start()
            await client.call_tool("start_session", {"session": SESSION}, timeout=20)
            if not config.get("show_agent_cursor", True):
                await client.call_tool(
                    "set_agent_cursor_enabled",
                    {"session": SESSION, "enabled": False}, timeout=20)
            permissions = await client.call_tool("check_permissions", {}, timeout=20)
            self.permissions = permissions.get("structuredContent") or {}
        except McpError as error:
            await self._stop_locked()
            raise DriverUnavailable(f"Cua Driver did not come up: {error}")
        self.started_at = time.monotonic()
        self._apps_at = 0.0

    async def _stop_locked(self) -> None:
        if self.client is not None:
            await self.client.close()
            self.client = None
        if self.daemon is not None and self.daemon.returncode is None:
            try:
                if self.daemon.stdin is not None:
                    self.daemon.stdin.close()  # liveness pipe: orderly shutdown
                await asyncio.wait_for(self.daemon.wait(), 5.0)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    self.daemon.kill()
                except ProcessLookupError:
                    pass
        self.daemon = None

    async def call(self, config: dict, tool: str, arguments: dict) -> dict:
        client = await self.ensure(config)
        return await client.call_tool(
            tool, {**arguments, "session": SESSION}, timeout=CALL_TIMEOUT)

    async def apps(self, config: dict, *, fresh: bool = False) -> list[dict]:
        """`list_apps` records (running and installed), cached briefly so scope
        checks don't cost a round-trip per action."""
        if fresh or time.monotonic() - self._apps_at > APP_CACHE_TTL:
            result = await self.call(config, "list_apps", {})
            self._apps = (result.get("structuredContent") or {}).get("apps") or []
            self._apps_at = time.monotonic()
        return self._apps

    async def app_for_pid(self, config: dict, pid: int) -> dict | None:
        for fresh in (False, True):
            for app in await self.apps(config, fresh=fresh):
                if app.get("running") and app.get("pid") == pid:
                    return app
        return None

    def invalidate_apps(self) -> None:
        self._apps_at = 0.0



# --- rendering ------------------------------------------------------------------

def _action_note(structured: dict) -> str | None:
    """One line from the driver's ActionResult: whether the effect was seen
    and how the input travelled — the agent's cue to verify or escalate."""
    if not structured.get("effect"):
        return None
    parts = [f"effect={structured['effect']}"]
    if structured.get("route"):
        parts.append(f"route={structured['route']}")
    delivery = structured.get("delivery") or {}
    if delivery.get("mode"):
        parts.append(f"delivery={delivery['mode']}")
    escalation = structured.get("escalation") or {}
    if escalation:
        parts.append(
            f"escalation: {escalation.get('reason', '?')} → {escalation.get('target', '?')}")
    return "Action result: " + ", ".join(parts)


def _render_window_state(structured: dict) -> str:
    elements = structured.get("elements") or []
    head = (
        f"{structured.get('app_name') or 'App'} — window {structured.get('window_id')} "
        f"(pid {structured.get('pid')}): {structured.get('returned_element_count', len(elements))}"
        f" of {structured.get('total_element_count', len(elements))} elements"
    )
    if structured.get("truncated"):
        head += " (truncated — narrow with query or raise max_elements)"
    lines = [head]
    if structured.get("degraded"):
        lines.append(f"Degraded: {structured.get('degraded_reason')}")

    # Tokens are "<snapshot>:<element_index>"; when they all share one
    # snapshot, say so once instead of repeating it on every row.
    prefixes = set()
    for element in elements:
        token = str(element.get("element_token") or "")
        prefix, _, index = token.rpartition(":")
        if not prefix or index != str(element.get("element_index")):
            prefixes = set()
            break
        prefixes.add(prefix)
    shared = next(iter(prefixes)) if len(prefixes) == 1 else None
    if shared:
        lines.append(f"element_token = \"{shared}:<index>\" for every [index] below")

    for element in elements:
        depth = min(int(element.get("depth") or 0), 12)
        row = [f"{'  ' * depth}[{element.get('element_index')}] {element.get('role') or '?'}"]
        label = element.get("label")
        value = element.get("value")
        if label:
            row.append(json.dumps(str(label)[:100], ensure_ascii=False))
        if value not in (None, "") and value != label:
            row.append("= " + json.dumps(str(value)[:160], ensure_ascii=False))
        if element.get("actions"):
            row.append("{" + ",".join(element["actions"]) + "}")
        if not shared and element.get("element_token"):
            row.append(f"token={element['element_token']}")
        lines.append(" ".join(row))
    return "\n".join(lines)


def _render_apps(apps: list[dict]) -> str:
    running = [a for a in apps if a.get("running")]
    installed = [a for a in apps if not a.get("running")]
    lines = [f"{len(running)} running app(s) available to this instance:"]
    for app in running:
        windows = app.get("windows") or []
        shown = ", ".join(
            f"{w.get('window_id')} {json.dumps(w.get('title') or '', ensure_ascii=False)}"
            for w in windows[:6]
        )
        lines.append(
            f"- {app.get('name')} (pid {app.get('pid')}) [{app.get('bundle_id')}]"
            + (f" windows: {shown}" if shown else ""))
    if installed:
        lines.append(f"Installed, not running ({len(installed)}; start with launch_app): "
                     + ", ".join(f"{a.get('name')} [{a.get('bundle_id')}]" for a in installed))
    return "\n".join(lines)


def _render_windows(windows: list[dict]) -> str:
    if not windows:
        return "No windows."
    lines = [f"{len(windows)} window(s):"]
    for w in windows:
        where = "on screen" if w.get("is_on_screen") else (
            "current Space, hidden or minimized" if w.get("on_current_space")
            else "on another Space — its tree is unreachable until it is on the current Space")
        lines.append(
            f"- window_id {w.get('window_id')} · {w.get('app_name')} (pid {w.get('pid')}) · "
            f"{json.dumps(w.get('title') or '', ensure_ascii=False)} · {where}")
    return "\n".join(lines)


def _images(result: dict) -> list[dict]:
    return [block for block in kt_content(result) if block["type"] == "image"]


# --- the plugin -------------------------------------------------------------------

def make_plugin() -> Plugin:
    plugin = Plugin(
        name="ComputerUse",
        vendor="keeptalking",
        version="0.1.0",
        summary="Operate Mac apps in the background",
        description="Lets KeepTalking read and operate the apps on this Mac through "
        "their accessibility tree and window screenshots, powered by Cua Driver "
        "(open source, MIT). Clicks and typing go straight to the target app, so "
        "your own cursor and focus stay where they are; a separate agent cursor "
        "shows what it is doing.\n\nEach action instance names the apps it may "
        "use and whether it may act or only look. KeepTalking itself, password "
        "managers and Keychain Access are never reachable; terminals and System "
        "Settings only when an instance lists them.\n\nNeeds Accessibility and "
        "Screen Recording for KT Companion.",
        symbol="cursorarrow.motionlines",
        tint="#3B82F6",
        category="Automation",
        homepage="https://github.com/trycua/cua",
        meters=[
            ("computer.observations", "call", "App lists, window trees and screenshots read"),
            ("computer.actions", "call", "Inputs delivered to apps"),
        ],
        requires=[DRIVER_REQUIREMENT],
        permissions=[
            permission(
                "system.accessibility",
                "To read the windows of the apps you allow, and click and type in them",
            ),
            permission(
                "system.screen-recording",
                "To see screenshots of those windows",
                required=False,
            ),
        ],
        config=[
            config_field(
                "show_agent_cursor", label="Show agent cursor", type="bool", default=True,
                description="Draw Cua's agent cursor while it acts (your own pointer never moves)",
            ),
            config_field(
                "screenshot_max_dimension", label="Screenshot size", type="choice",
                choices=["1024", "1280", "1568"], default="1280",
                description="Long edge of window screenshots sent to the model, in pixels",
            ),
            config_field(
                "fast_actions", label="Faster actions", type="bool", default=False,
                description="Watch for new windows 200 ms after each action instead of "
                "1 s: quicker, but a stolen focus is reverted for less time",
            ),
        ],
    )
    driver = Driver(plugin.state_dir)

    @plugin.kind(
        "computer-use",
        display_name="Computer Use",
        description="Operate macOS apps in the background through Cua Driver — the user "
        "keeps their own cursor and focus. Workflow: list_apps (or launch_app) → "
        "list_windows → get_window_state(pid, window_id) returns tree rows with "
        "element tokens plus a screenshot → act by element_token (click, type_text, "
        "set_value, press_key, hotkey, scroll, invoke_menu) → get_window_state again to "
        "check the result; tokens go stale after each snapshot. Use x,y (window "
        "screenshot pixels) only for surfaces missing from the tree. Windows on another "
        "Space can't be read. Apps outside this instance's scope are refused.",
        input_schema=_input_schema(),
        scope_schema={
            "allowedApps": {
                "title": "Apps",
                "type": "array",
                "items": {"type": "string"},
                "description": "Bundle IDs or app names this instance may use; empty "
                "allows any app except protected ones",
            },
            "control": {
                "title": "Allow control",
                "type": "boolean",
                "description": "Allow clicking, typing and launching; off = look only",
            },
            "foreground": {
                "title": "Allow foreground",
                "type": "boolean",
                "description": "Allow briefly taking the foreground (drags, menu "
                "shortcuts that ignore background input)",
            },
        },
        default_scope={"allowedApps": [], "control": True, "foreground": False},
        sub_tools=_sub_tools(),
        resources=CUA_RESOURCES,
    )
    async def computer_use(args: dict, ctx: CallContext):
        arguments = dict(args)
        tool = ctx.tool or arguments.pop("tool", None)
        arguments.pop("tool", None)
        spec = TOOLS.get(tool or "")
        if spec is None:
            return (f"unknown tool {tool!r}; choose one of: {', '.join(TOOLS)}", True)

        allowed, control, foreground = _scope(ctx)
        if spec.acts and not control:
            return (f"Denied by instance scope: this instance may only look "
                    f"({', '.join(sorted(OBSERVATION_TOOLS))}).", True)
        wants_foreground = spec.foreground or arguments.get("delivery_mode") == "foreground"
        if wants_foreground and not foreground:
            return ("Denied by instance scope: this instance may not take the "
                    "foreground. Use background delivery, or ask the user to allow "
                    "foreground on this instance.", True)

        missing = [p for p in spec.required if arguments.get(p) in (None, "", [])]
        if missing:
            return f"{tool} needs: {', '.join(missing)}", True
        # Forward only the curated parameters: no session/scope/target
        # overrides, no file-writing paths, no launch arguments.
        forwarded = {
            spec.renames.get(key, key): value
            for key, value in arguments.items()
            if key in spec.params and value is not None
        }
        for key in INTEGER_PARAMS & set(forwarded):
            try:
                forwarded[key] = int(forwarded[key])
            except (TypeError, ValueError):
                return f"{key} must be an integer", True
        if tool == "drag":
            forwarded["delivery_mode"] = "foreground"  # macOS has no background drag
        config = ctx.config
        try:
            await driver.ensure(config)
            permissions = driver.permissions
            # TCC answers are cached per process: when this process already
            # sees a grant the driver doesn't (or a while has passed), the
            # driver's answer is stale and a fresh one re-asks.
            stale = [
                key for key, permission_id in (
                    ("accessibility", "system.accessibility"),
                    ("screen_recording", "system.screen-recording"),
                )
                if not permissions.get(key)
                and plugin.permission_status(permission_id) == "granted"
            ]
            if stale or (not permissions.get("accessibility")
                         and time.monotonic() - driver.started_at > 10):
                await driver.restart(config)
                permissions = driver.permissions
            if not permissions.get("accessibility") and tool != "list_apps":
                asked = plugin.request_permission("system.accessibility")
                return ((
                    "KT Companion needs Accessibility to use apps. macOS is now asking "
                    "the user to allow it"
                    if asked else
                    "KT Companion still doesn't have Accessibility; the user was asked "
                    "moments ago"
                ) + " (System Settings → Privacy & Security → Accessibility). Try again "
                    "once they have.", True)

            # -- app scope --
            target_app = None
            if tool == "launch_app":
                bundle_id, name = forwarded.get("bundle_id"), forwarded.get("name")
                if not bundle_id and not name:
                    return "launch_app needs bundle_id or name", True
                for app in await driver.apps(config):
                    if (bundle_id and str(app.get("bundle_id", "")).lower() == str(bundle_id).lower()) or (
                            not bundle_id and name and str(app.get("name", "")).lower() == str(name).lower()):
                        target_app = app
                        break
                refusal = _app_refusal(
                    (target_app or {}).get("bundle_id") or bundle_id,
                    (target_app or {}).get("name") or name, allowed)
                if refusal:
                    return f"Denied by instance scope: {refusal}.", True
            elif "pid" in forwarded:
                target_app = await driver.app_for_pid(config, forwarded["pid"])
                if target_app is None:
                    return (f"pid {forwarded['pid']} is not a running app — call "
                            "list_apps for current pids.", True)
                refusal = _app_refusal(target_app.get("bundle_id"), target_app.get("name"), allowed)
                if refusal:
                    return f"Denied by instance scope: {refusal}.", True

            # -- per-tool shaping --
            screen_ok = bool(permissions.get("screen_recording"))
            notes: list[str] = []
            if tool == "get_window_state":
                forwarded.setdefault("max_elements", DEFAULT_MAX_ELEMENTS)
                forwarded["max_image_dimension"] = int(config.get("screenshot_max_dimension") or 1280)
                if not screen_ok and forwarded.get("include_screenshot", True):
                    forwarded["include_screenshot"] = False
                    plugin.request_permission("system.screen-recording")
                    notes.append("No screenshot: KT Companion doesn't have Screen Recording "
                                 "yet; macOS asks the user, and screenshots start once "
                                 "they allow it.")
            elif tool == "zoom" and not screen_ok:
                plugin.request_permission("system.screen-recording")
                return ("zoom needs Screen Recording for KT Companion; macOS is asking the "
                        "user to allow it (System Settings → Privacy & Security → Screen "
                        "Recording). Try again once they have.", True)

            if spec.verb and target_app:
                ctx.elucidate(f"{spec.verb} {target_app.get('name')}")
            elif tool == "launch_app":
                ctx.elucidate(f"Launching {forwarded.get('bundle_id') or forwarded.get('name')}")

            result = await driver.call(config, tool, forwarded)
        except DriverUnavailable as error:
            return str(error), True
        except McpError as error:
            # Never replay an input whose completion is unknown; the next call
            # restarts the driver if it died.
            return f"Cua Driver error during {tool}: {error}", True

        ctx.report_usage("computer.actions" if spec.acts else "computer.observations", 1)
        if tool == "launch_app":
            driver.invalidate_apps()

        structured = result.get("structuredContent") or {}
        is_error = bool(result.get("isError"))
        if is_error:
            return kt_content(result) or [{"type": "text", "text": f"{tool} failed"}], True

        if tool == "list_apps":
            permitted = [a for a in structured.get("apps") or []
                         if _app_refusal(a.get("bundle_id"), a.get("name"), allowed) is None]
            content = [{"type": "text", "text": _render_apps(permitted)}]
        elif tool == "list_windows":
            windows = structured.get("windows") or []
            if "pid" not in forwarded:
                permitted_pids = {
                    a.get("pid") for a in await driver.apps(config)
                    if a.get("running")
                    and _app_refusal(a.get("bundle_id"), a.get("name"), allowed) is None
                }
                windows = [w for w in windows if w.get("pid") in permitted_pids]
            content = [{"type": "text", "text": _render_windows(windows)}]
        elif tool == "get_window_state":
            content = [{"type": "text", "text": _render_window_state(structured)}]
            content += _images(result)
        else:
            content = kt_content(result)
            note = _action_note(structured)
            if note:
                content.append({"type": "text", "text": note})
        for note in notes:
            content.append({"type": "text", "text": note})
        return content

    # Declared resources are read through KeepTalking's plugin-resources meta
    # tool; the SDK only asks for uris the kind declares (CUA_RESOURCES).
    @plugin.resource_reader
    async def read_resource(uri: str) -> list[dict]:
        return await (await driver.ensure(plugin.config)).read_resource(uri)

    @plugin.scope_options("computer-use", "allowedApps")
    async def app_choices(request: ScopeOptionsRequest) -> list[dict]:
        """Open apps first, then installed ones; protected apps are never
        offered, and shell-like ones carry their caution."""
        try:
            apps = await driver.apps(request.config, fresh=True)
        except DriverUnavailable as error:
            raise RuntimeError(str(error))
        query = (request.query or "").lower()
        chosen: dict[str, dict] = {}
        for app in apps:
            bundle, name = app.get("bundle_id"), app.get("name")
            if not bundle or not name:
                continue
            # Named explicitly, only the never-reachable apps still refuse.
            if _app_refusal(bundle, name, [bundle]) is not None:
                continue
            if query and query not in name.lower() and query not in bundle.lower():
                continue
            key = bundle.lower()
            if key not in chosen or app.get("running"):
                chosen[key] = app
        ordered = sorted(
            chosen.values(),
            key=lambda a: (not a.get("running"), str(a.get("name")).lower()))
        return [
            scope_option(
                app["bundle_id"], app["name"],
                detail=app["bundle_id"],
                group="Open now" if app.get("running") else "Installed",
                app=app["bundle_id"],
                caution=EXPLICIT_ONLY_APPS.get(app["bundle_id"].lower()),
            )
            for app in ordered
        ]

    return plugin


if __name__ == "__main__":
    make_plugin().run()

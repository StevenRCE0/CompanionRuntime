# KT Companion — unified plugin runtime

The **companion runtime** for KeepTalking's plugin action catalogs (see
[`DESIGN_PLUGIN_ACTIONS.md`](../../../DESIGN_PLUGIN_ACTIONS.md)): one app the user
installs, hosting N plugins. Heavy dependencies (browsers, ML runtimes) live
here, never in the KTSDK; the socket is the boundary.

KTPP is gRPC over KeepTalking's Unix socket, with JSON messages (no
protobuf). There is **no pairing and there are no sessions**: the socket is
reachable by this user alone, so whoever connects is trusted, and a plugin is
known by the name it gives in `hello`. Each plugin connects on its own, as its
own catalog; the companion connects too (as `role: companion`, so KeepTalking
can ask it to show its window) and supervises the plugins' processes. It never
proxies their messages.

Files:

- `companion.py` — the runtime shell: plugin discovery, venv provisioning,
  supervision, and the runtime's own interpreter (`--runtime-python`).
- `plugin_host.py` — runs one plugin in its own interpreter (the child process
  the companion supervises).
- `keeptalking_plugin.py` — the plugin SDK: the kind DSL, resources, scope
  options, `ctx.act` / `ctx.elucidate`, and the KTPP client. Its one
  dependency is `grpcio`, imported only when a plugin connects — reading a
  plugin's declaration needs the standard library alone.
- `keeptalking_mcp.py` — a stdlib MCP stdio client for plugins that wrap an
  MCP server.
- `permissions.json` — the system-permission registry plugins declare from.

Plugins ship in `plugins/` (MarkItDown, BrowserUse, ComputerUse); the user's own
go in `~/Library/Application Support/KeepTalkingCompanion/Plugins`
(`KT_COMPANION_PLUGINS` to override, `companion.py --install <path>` to copy one
in).

## The protocol, briefly

Service `keeptalking.plugin.PluginHost` (mirrors
`KeepTalking/Sources/KeepTalking/Services/PluginHost/Wire/`):

- `Connect` (bidirectional stream) — the plugin's connection. The plugin sends
  `hello` (name, role, version, a per-launch `instance`) and its `kinds`;
  KeepTalking answers `welcome` and sends its calls, scope-option and
  resource-read requests, and reveal requests down the same stream. Messages
  are flat JSON objects with one body key: `{"id": 3, "call": {…}}`,
  `{"replyTo": 3, "callResult": {…}}`. A newer connection with the same plugin
  name replaces an older one (`goodbye: superseded`), and the stream ending
  means the plugin is gone.
- `RequestAct` — one AI turn for an in-flight call (bound by its `requestID`).
- `ProposeAction` — ask the user to create an instance of one of the plugin's
  own kinds.
- `OpenAddAction` — open KeepTalking's Add Action flow.

Calls can be made verifiable without a protocol change: the host's
`KeepTalkingCallAttestor` may attach `authorization` evidence to a call, and a
plugin's `CallAttestor` (`Plugin(attestor=…)`) may check it and return a
`receipt`. Neither attests anything by default.

## The runtime's interpreter

The runtime needs Python ≥ 3.10 with grpcio. `companion.py --runtime-python`
builds a venv for it from the first modern interpreter it finds
(`~/.keeptalking-plugin/kt-companion/venv`), installs grpcio, and prints that
interpreter. Any `python3` can run the setup — the Companion app runs it with
the system one, then launches `companion.py` on the interpreter it printed.
Plugins with dependencies get their own venvs (`--provision`), each with grpcio
as well; a venv whose requirement set changed updates itself on the next start.

## Run it against the lab host

Terminal 1 — the lab host (the SDK's `KeepTalkingPluginHost`):

```bash
swift run --package-path ../../../KeepTalking KeepTalking pluginlab --socket /tmp/ktpp-demo.sock --stay
```

Terminal 2 — the companion:

```bash
PY=$(python3 companion.py --runtime-python)
KT_PLUGIN_SOCKET=/tmp/ktpp-demo.sock "$PY" companion.py
```

The companion and each plugin connect and are welcomed; the lab prints the
kinds each one pushes. Add `--call <kind> --args '<json>' --scope '<json>'` to
the lab to drive one call end to end.

## State

`~/.keeptalking-plugin/<name>/` per plugin (and the companion): its venv,
`config.json` (written by the Companion app), and any files the plugin keeps.

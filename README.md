# KT Companion — unified plugin runtime

The **companion runtime** for KeepTalking's plugin action catalogs (see
[`DESIGN_PLUGIN_ACTIONS.md`](../../../DESIGN_PLUGIN_ACTIONS.md)): one app the user
installs, hosting N plugins. Heavy dependencies (browsers, ML runtimes) live
here, never in the KTSDK; the socket is the boundary.

KTPP is gRPC over one Unix socket, with JSON messages (no protobuf). **The
companion owns the socket**: plugins connect to it, KeepTalking apps attach to
it, and the companion relays between them. The socket is reachable by this user
alone, so whoever connects is trusted. A plugin is known by the name it gives in
`hello`; an app names the node (identity) every message speaks for, so one app
can carry several identities and several apps can attach at once.

The socket is `~/Library/Group Containers/group.org.rcex.KeepTalkingApp/ktpp.sock`
(`/tmp/ktpp-<uid>.sock` when that path would pass 100 bytes; `KT_PLUGIN_SOCKET`
or `--socket` to override). There is no discovery file.

Files:

- `companion.py` — the runtime shell: plugin discovery, venv provisioning,
  supervision, the broker, and the runtime's own interpreter
  (`--runtime-python`).
- `companion_server.py` — the broker: serves both services on the socket and
  routes between plugins and apps (also runs alone: `--socket <path>`).
- `plugin_host.py` — runs one plugin in its own interpreter (the child process
  the companion supervises).
- `keeptalking_plugin.py` — the plugin SDK: the kind DSL, resources, scope
  options, `ctx.act` / `ctx.elucidate`, and the plugin's KTPP client. Its one
  dependency is `grpcio`, imported only when a plugin connects — reading a
  plugin's declaration needs the standard library alone.
- `keeptalking_mcp.py` — a stdlib MCP stdio client for plugins that wrap an
  MCP server.
- `permissions.json` — the system-permission registry plugins declare from.

The runtime ships no plugins. They live in
`~/Library/Application Support/KeepTalkingCompanion/Plugins`
(`KT_COMPANION_PLUGINS` to override, `companion.py --install <path>` to copy one
in), where the Companion app installs them from ports repositories
([CompanionPorts](https://github.com/StevenRCE0/CompanionPorts); MarkItDown,
BrowserUse and ComputerUse are on its `builtin` branch). A plugin is a folder
with `manifest.json` and an entry module that declares itself with
`Plugin.from_manifest(__file__)`; a single module exposing `make_plugin()`
still loads too.

## The protocol, briefly

Both services mirror `KeepTalking/Sources/KeepTalking/Services/PluginHost/Wire/`.
Messages are flat JSON objects with one body key: `{"id": 3, "call": {…}}`,
`{"replyTo": 3, "callResult": {…}}`.

Service `keeptalking.plugin.PluginHost` — what plugins speak:

- `Connect` (bidirectional stream) — the plugin's connection. The plugin sends
  `hello` (name, version, a per-launch `instance`) and its `kinds`; the
  companion answers `welcome` and relays calls, scope-option and resource-read
  requests down the same stream. A newer connection with the same plugin name
  replaces an older one (`goodbye: superseded`); the stream ending means the
  plugin is gone.
- `RequestAct` — one AI turn for an in-flight call, routed by its `requestID`
  to the app that made the call.
- `ProposeAction` — ask the user to create an instance of one of the plugin's
  own kinds.
- `OpenAddAction` — open KeepTalking's Add Action flow.

Service `keeptalking.plugin.Companion` — what KeepTalking apps speak. One
`Attach` stream carries everything, so a call's elucidations stay ahead of its
result. App messages carry `from` (the node); companion messages carry `to`.

- The app sends `hello`, then `keepalive` every 5 s per identity. An identity
  is online until 15 s after its last keepalive; `leave` takes it offline at
  once, and so does the attachment ending.
- The companion answers `welcome`, then a `catalog` of every plugin (name,
  version, `connected`, kinds), and again on every change.
- App requests: `call`, `scopeOptions`, `resourceRead` (each
  `{plugin, request}`), `cancel`, `reveal`.
- Companion requests to an identity: `act`, `actionCreate`, `addAction`.
- Failures are `{code, message, ktppCode}` (`ktppCode: not_connected` when the
  plugin is away).

When a plugin's `ProposeAction` / `OpenAddAction` has more than one identity
it could go to, the companion asks the user (see the markers below).

## Talking to the Companion app

The Swift app reads marked stdout lines and writes NDJSON to stdin:

- `@kt-companion reveal` — show the window.
- `@kt-companion identities {"identities": [{"id", "label"}]}` — the online
  identities, on start and on every change.
- `@kt-companion choose-identity {"token", "plugin", "kind", "reason",
  "identities"}` — pick one; answer with
  `{"cmd": "chooseIdentity", "token": …, "nodeID": … | null}` (null declines;
  unanswered after 120 s declines). `@kt-companion choice-closed {"token"}`
  follows either way.
- `{"cmd": "openAddAction", "kindName", "pluginName", "nodeID"}` — open Add
  Action in that identity (without `nodeID`: the only one online, else ask).

Calls can be made verifiable without a protocol change: KeepTalking's
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

## Run it by hand

```bash
PY=$(python3 companion.py --runtime-python)
"$PY" companion.py --socket /tmp/ktpp-demo.sock
```

Then attach KeepTalking or the SDK's lab
(`swift run --package-path ../../../KeepTalking KeepTalking pluginlab --socket /tmp/ktpp-demo.sock`)
to the same socket.

## State

`~/.keeptalking-plugin/<name>/` per plugin (and the companion): its venv,
`config.json` (written by the Companion app), and any files the plugin keeps.

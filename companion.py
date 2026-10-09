#!/usr/bin/env python3
"""KT Companion — the unified plugin runtime app.

One app the user installs; plugins are installed BY THE USER into a user-owned
directory and supervised here. The companion is deliberately a thin shell —
"easy to access, cleanly separated from the KTSDK": heavy dependencies
(browsers, ML runtimes, …) stay here, and the SDK only ever sees KTPP over its
socket.

Trust model: there is none to set up. The KeepTalking socket is reachable by
this user alone, so whoever connects is trusted; a plugin is known by its name.
The companion connects as role="companion" (so KeepTalking can ask it to show
its window), and each plugin connects on its own, as its own catalog.

Process model: every plugin runs as a CHILD PROCESS on its own interpreter,
using its own venv when it declares dependencies (`requires=[…]`). The
companion provisions those venvs and spawns and restarts the children — it
never proxies their messages.

The runtime itself needs Python ≥ 3.10 with grpcio (the SDK's one dependency).
`--runtime-python` sets that up — a venv for the companion, built from the
first modern interpreter found — and prints its interpreter, which the
Companion app then runs this file with. Everything else here (--list,
--describe, --provision) runs on any Python 3.9+, standard library only.

Usage:
    python3 companion.py [--socket <path>]
        [--list|--describe|--provision [name]|--runtime-python]

Plugins are python modules exposing `make_plugin() -> Plugin`, loaded from two
places: the ones shipped alongside this runtime in `./plugins/`, and any the
user installed into `~/Library/Application Support/KeepTalkingCompanion/Plugins`
(`KT_COMPANION_PLUGINS` to override; `--install <path>` copies one in). Their
top-level imports must be dependency-free (see plugin_host.py).
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import os
import stat
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from keeptalking_plugin import (  # noqa: E402
    COMPANION_ROLE,
    Plugin,
    discover_socket_path,
)

COMPANION_VERSION = "0.1.0"
# Stdout line the Swift supervisor treats as "surface the panel" — parsed out
# of the runtime's output rather than logged. Keep in sync with
# `CompanionSupervisor.revealMarker`.
REVEAL_MARKER = "@kt-companion reveal"
PLUGIN_HOST = HERE / "plugin_host.py"


def user_plugins_dir() -> Path:
    """Where user-installed plugins live, alongside the ones the Companion
    ships. Separate directory so an app update never clobbers them."""
    override = os.environ.get("KT_COMPANION_PLUGINS")
    path = Path(override) if override else (
        Path.home() / "Library" / "Application Support"
        / "KeepTalkingCompanion" / "Plugins"
    )
    path.mkdir(parents=True, exist_ok=True)
    return path


def plugin_search_paths() -> list[Path]:
    """Bundled plugins first, then user-installed ones."""
    return [HERE / "plugins", user_plugins_dir()]


def discover_plugins(directories: list[Path]) -> list[tuple[Plugin, Path]]:
    """Imports each plugin module *in the companion's interpreter* purely to
    read its declaration — handlers only ever run in the child process."""
    found: list[tuple[Plugin, Path]] = []
    seen: set[str] = set()
    modules = [
        path
        for directory in directories if directory.exists()
        for path in sorted(directory.glob("*.py"))
    ]
    for path in modules:
        if path.name.startswith("_") or path.name in seen:
            continue
        seen.add(path.name)
        spec = importlib.util.spec_from_file_location(f"kt_plugins.{path.stem}", path)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
            found.append((module.make_plugin(), path))
        except Exception as error:
            print(f"[KT Companion] failed to load plugin {path.name}: {error}")
    return found


async def supervise_plugin(
    plugin: Plugin, module_path: Path, socket_path: str
) -> None:
    """Runs one plugin child process forever, restarting with backoff."""
    name = plugin.info["name"]
    backoff = 1.0
    while True:
        argv = [
            plugin.interpreter,
            str(PLUGIN_HOST),
            "--module", str(module_path),
            "--socket", socket_path,
        ]
        process = await asyncio.create_subprocess_exec(
            *argv,
            # Never written: held open so the child sees EOF when we die.
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        print(f"[KT Companion] {name} started (pid {process.pid}, {plugin.interpreter})")

        async def pump() -> None:
            assert process.stdout
            async for line in process.stdout:
                print(line.decode(errors="replace").rstrip())

        started = asyncio.get_running_loop().time()
        await pump()
        code = await process.wait()
        # A child that ran healthily resets the ladder: escalated backoff is
        # for crash LOOPS, not for a restart after hours of uptime.
        if asyncio.get_running_loop().time() - started > 10.0:
            backoff = 1.0
        print(f"[KT Companion] {name} exited ({code}); restarting in {backoff:.0f}s")
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 30.0)


async def stdin_commands(companion: Plugin) -> None:
    """Reads NDJSON commands from stdin (sent by the Companion macOS app)."""
    mode = os.fstat(0).st_mode
    if not (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)):
        # A terminal or /dev/null (manual runs): no app is sending commands.
        return
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    try:
        await loop.connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(reader), sys.stdin
        )
    except OSError as error:
        # stdin isn't a pipe (manual/terminal runs). A raise here would take
        # the WHOLE runtime down through asyncio.gather — commands are an
        # optional channel, never load-bearing.
        print(f"[KT Companion] stdin commands unavailable ({error}); skipping")
        return
    while True:
        line = await reader.readline()
        if not line:
            # EOF on the app's pipe means the app is gone (quit, crash, or
            # Xcode's SIGKILL). Exiting closes each child's stdin pipe in turn,
            # so the whole tree follows instead of staying attached to the host.
            if stat.S_ISFIFO(os.fstat(0).st_mode):
                os._exit(0)
            break
        try:
            cmd = json.loads(line)
        except json.JSONDecodeError:
            continue
        if cmd.get("cmd") == "openAddAction":
            try:
                result = await companion.request_open_add_action(
                    kind_name=cmd.get("kindName"),
                    plugin_name=cmd.get("pluginName"))
                print(f"[KT Companion] openAddAction: {result}")
            except Exception as e:
                print(f"[KT Companion] openAddAction failed: {e}")


def companion_plugin() -> Plugin:
    """The companion's own catalog. It registers no kinds — it supervises
    plugins; it is not a capability provider — and its venv is the runtime's
    (see `--runtime-python`)."""
    return Plugin(
        name="KT Companion",
        vendor="keeptalking.dev",
        version=COMPANION_VERSION,
        role=COMPANION_ROLE,
    )


async def run(socket_path: str, plugins: list[tuple[Plugin, Path]]) -> None:
    companion = companion_plugin()
    # The host's reveal request reaches the Swift menu-bar app through a
    # marked stdout line — the supervisor parses `REVEAL_MARKER` out of the log.
    companion.on_reveal = lambda: print(REVEAL_MARKER, flush=True)

    tasks = [
        asyncio.create_task(companion.serve_forever(socket_path)),
        asyncio.create_task(stdin_commands(companion)),
    ]

    for plugin, module_path in plugins:
        # A venv whose requirement set changed (an SDK or plugin update)
        # re-provisions on its own: the user installed this plugin already,
        # and running it on the wrong interpreter would only fail later.
        if plugin.requires and plugin.venv_python.exists() and not plugin.is_provisioned:
            print(f"[KT Companion] {plugin.info['name']}: requirements changed; updating its venv")
            await asyncio.to_thread(plugin.provision)
        if plugin.requires and not plugin.is_provisioned:
            print(
                f"[KT Companion] {plugin.info['name']}: dependencies not installed "
                f"— run `companion.py --provision {plugin.info['name']}` "
                f"(falling back to the runtime interpreter)"
            )
        tasks.append(asyncio.create_task(supervise_plugin(plugin, module_path, socket_path)))

    await asyncio.gather(*tasks)


def main() -> None:
    # Supervisor output is a live log for the Companion app's panel; without
    # line buffering it would sit in a pipe buffer until exit.
    sys.stdout.reconfigure(line_buffering=True)

    parser = argparse.ArgumentParser(description="KT Companion plugin runtime")
    parser.add_argument("--socket", default=os.environ.get("KT_PLUGIN_SOCKET"))
    parser.add_argument("--list", action="store_true", help="list plugins and exit")
    parser.add_argument(
        "--describe", action="store_true",
        help="print plugins + config schemas as JSON and exit (Companion app contract)",
    )
    parser.add_argument(
        "--install", metavar="PATH",
        help="copy a plugin module into the user plugins directory",
    )
    parser.add_argument(
        "--provision", nargs="?", const="*", metavar="NAME",
        help="create venvs and install dependencies (all plugins, or one by name)",
    )
    parser.add_argument(
        "--runtime-python", action="store_true",
        help="set up the runtime's own venv (Python >= 3.10 + grpcio) and print its interpreter",
    )
    args = parser.parse_args()

    if args.runtime_python:
        # Progress goes to stderr; stdout carries only the interpreter path.
        companion = companion_plugin()
        if not companion.is_provisioned and not companion.provision(
            log=lambda line: print(line, file=sys.stderr, flush=True)
        ):
            raise SystemExit(1)
        print(companion.interpreter)
        return

    if args.install:
        import shutil

        source = Path(args.install).expanduser().resolve()
        if not source.is_file():
            print(f"[KT Companion] no such plugin module: {source}")
            raise SystemExit(1)
        destination = user_plugins_dir() / source.name
        shutil.copy2(source, destination)
        print(f"[KT Companion] installed {source.name} → {destination}")
        return

    plugins = discover_plugins(plugin_search_paths())

    if args.describe:
        print(json.dumps(
            {
                "companionVersion": COMPANION_VERSION,
                "plugins": [
                    {
                        **plugin.describe(),
                        "source": "bundled" if path.parent == HERE / "plugins" else "user",
                        "modulePath": str(path),
                    }
                    for plugin, path in plugins
                ],
            },
            indent=2,
        ))
        return

    if args.provision:
        targets = [
            plugin for plugin, _ in plugins
            if args.provision == "*" or plugin.info["name"] == args.provision
        ]
        if not targets:
            print(f"[KT Companion] no plugin named {args.provision!r}")
            raise SystemExit(1)
        ok = all(plugin.provision() for plugin in targets)
        raise SystemExit(0 if ok else 1)

    print(f"[KT Companion] v{COMPANION_VERSION} — {len(plugins)} plugin(s)")
    for plugin, _ in plugins:
        kinds = ", ".join(plugin.kinds) or "no kinds"
        deps = ""
        if plugin.requires:
            deps = " [deps: {}]".format(
                "ready" if plugin.is_provisioned else "not installed")
        print(f"  - {plugin.info['name']} v{plugin.info['version']}: {kinds}{deps}")
    if args.list:
        return

    socket_path = args.socket
    if not socket_path:
        for attempt in range(120):
            try:
                socket_path = discover_socket_path()
                break
            except RuntimeError:
                if attempt == 0:
                    print("[KT Companion] waiting for KeepTalking to publish a socket…")
                time.sleep(1.0)
        else:
            print("[KT Companion] timed out waiting for socket after 2 minutes")
            raise SystemExit(1)
    try:
        asyncio.run(run(socket_path, plugins))
    except KeyboardInterrupt:
        print("\n[KT Companion] shutting down")


if __name__ == "__main__":
    main()

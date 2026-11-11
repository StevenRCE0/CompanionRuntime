#!/usr/bin/env python3
"""Runs ONE plugin in its own interpreter — the child process the KT Companion
supervises.

Each plugin gets its own venv (so a plugin's dependencies can never break a
sibling's), which means it also needs its own process: this is that process.
The companion spawns `<plugin-venv>/bin/python plugin_host.py --module …`,
and from here on the plugin connects back to the companion's socket.

Convention this relies on: **a plugin module's top-level imports must be
dependency-free** (declare kinds and config there; import heavy libraries
inside handlers). The companion imports the module with its own interpreter to
read the declaration; only this process — running the venv interpreter — ever
executes handlers.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from companion import load_plugin  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="KT plugin host (one plugin)")
    parser.add_argument("--module", required=True, help="path to the plugin module")
    parser.add_argument("--socket", help="the companion's socket (default: KT_PLUGIN_SOCKET, else the app group)")
    args = parser.parse_args()

    plugin = load_plugin(Path(args.module).resolve())

    # The companion holds our stdin pipe open and never writes to it; EOF
    # means it died, however it died. Exit with it rather than linger as an
    # orphan still connected to the socket. A thread, so a stalled event loop
    # can't delay it. Terminal/dev runs (no pipe) are unaffected. asyncio
    # before 3.12 hands the child a socketpair rather than a pipe.
    mode = os.fstat(0).st_mode
    if stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):
        threading.Thread(
            target=lambda: (sys.stdin.buffer.read(), os._exit(0)), daemon=True
        ).start()

    print(f"[{plugin.info['name']}] host starting ({sys.executable})", flush=True)
    plugin.run(args.socket)


if __name__ == "__main__":
    main()

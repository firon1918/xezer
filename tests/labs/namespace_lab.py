#!/usr/bin/env python3
"""Cgroup-independent Juice Shop fallback with private network + Unix ingress.

Run with an extracted, digest-pinned image rootfs. No public listening socket or
host network is available inside the lab. Docker Compose remains the default.
"""

import argparse
import asyncio
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import fcntl
import sys


async def pump(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


async def child(root):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        fcntl.ioctl(sock, 0x8914, struct.pack("16sh", b"lo", 0x49))
    # Empty network namespace has no interface or route to outside targets.
    proc = await asyncio.create_subprocess_exec(
        "/nodejs/bin/node", "/juice-shop/build/app.js", cwd="/juice-shop"
    )

    async def accept(reader, writer):
        try:
            upstream, output = await asyncio.open_connection("127.0.0.1", 3000)
            await asyncio.gather(pump(reader, output), pump(upstream, writer))
        except OSError:
            writer.close()

    server = await asyncio.start_unix_server(accept, "/ingress/juice.sock")
    async with server:
        await proc.wait()


async def host(args):
    root = Path(args.rootfs).resolve()
    if not (root / "nodejs/bin/node").is_file():
        raise SystemExit(
            "Extract the pinned Juice Shop image before starting this fallback."
        )
    state = Path(args.state).resolve()
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Disposable writable application state; never modify the extracted baseline.
    app = state / "app"
    if not app.exists():
        shutil.copytree(root / "juice-shop", app)
    sock = state / "juice.sock"
    sock.unlink(missing_ok=True)
    # System Python is the trusted forwarding helper; the image Node/libs retain
    # their original paths. Host /proc, home, network and Docker socket are absent.
    cmd = [
        "bwrap",
        "--unshare-all",
        "--uid",
        "0",
        "--gid",
        "0",
        "--cap-add",
        "CAP_NET_ADMIN",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--ro-bind",
        str(root / "nodejs"),
        "/nodejs",
        "--bind",
        str(app),
        "/juice-shop",
        "--bind",
        str(state),
        "/ingress",
        "--ro-bind",
        str(Path(__file__).resolve()),
        "/lab.py",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/etc",
        "--setenv",
        "NODE_ENV",
        "production",
        "--setenv",
        "HOME",
        "/tmp",
        "--chdir",
        "/juice-shop",
        "/usr/bin/python3",
        "/lab.py",
        "--child",
    ]
    process = await asyncio.create_subprocess_exec(*cmd, start_new_session=True)

    async def ingress(reader, writer):
        try:
            upstream, output = await asyncio.open_unix_connection(sock)
            await asyncio.gather(pump(reader, output), pump(upstream, writer))
        except OSError:
            writer.close()

    server = None
    try:
        for _ in range(120):
            if process.returncode is not None:
                raise RuntimeError("isolated Juice Shop process exited")
            if sock.exists():
                break
            await asyncio.sleep(0.25)
        server = await asyncio.start_server(ingress, "127.0.0.1", args.port)
        await process.wait()
    finally:
        if server:
            server.close()
            await server.wait_closed()
        if process.returncode is None:
            os.killpg(process.pid, signal.SIGKILL)
            await process.wait()
        sock.unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rootfs")
    parser.add_argument("--state")
    parser.add_argument("--port", type=int, default=3000)
    parser.add_argument("--child", action="store_true")
    options = parser.parse_args()
    if not options.child and (not options.rootfs or not options.state):
        parser.error("--rootfs and --state are required")
    try:
        asyncio.run(child(None) if options.child else host(options))
    except KeyboardInterrupt:
        sys.exit(0)

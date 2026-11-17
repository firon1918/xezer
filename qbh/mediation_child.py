"""Trusted namespace entry point (stdlib only); mounted read-only by broker."""

import asyncio
import ctypes
import fcntl
import os
import socket
import struct
import sys


async def pump(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


async def main():
    # Only the private loopback exists in this network namespace.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        flags = fcntl.ioctl(sock, 0x8913, struct.pack("16sh", b"lo", 0))
        value = struct.unpack("16sh", flags[:18])[1] | 1
        fcntl.ioctl(sock, 0x8914, struct.pack("16sh", b"lo", value))
    libc = ctypes.CDLL(None, use_errno=True)
    for cap in range(41):
        libc.prctl(24, cap, 0, 0, 0)  # PR_CAPBSET_DROP
    libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS

    async def connect(reader, writer):
        upstream, output = await asyncio.open_unix_connection("/broker/socket")
        await asyncio.gather(pump(reader, output), pump(upstream, writer))

    server = await asyncio.start_server(connect, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    proxy = f"http://127.0.0.1:{port}"
    env = dict(
        os.environ,
        http_proxy=proxy,
        https_proxy=proxy,
        HTTP_PROXY=proxy,
        HTTPS_PROXY=proxy,
        ALL_PROXY=proxy,
        NO_PROXY="",
        no_proxy="",
        SSL_CERT_FILE="/broker/ca.pem",
        REQUESTS_CA_BUNDLE="/broker/ca.pem",
        CURL_CA_BUNDLE="/broker/ca.pem",
    )
    command = [arg.replace("{XEzer_PROXY}", proxy) for arg in sys.argv[1:]]
    child = await asyncio.create_subprocess_exec(*command, env=env)
    code = await child.wait()
    server.close()
    await server.wait_closed()
    return code


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

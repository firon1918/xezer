"""Trusted stdlib-only private UDP/TCP DNS to Unix broker bridge."""
import asyncio
import ctypes
import fcntl
import socket
import struct
import sys


async def exchange(data):
    async with asyncio.timeout(12):
        reader, writer = await asyncio.open_unix_connection('/broker/socket')
        try:
            writer.write(len(data).to_bytes(2, 'big') + data)
            await writer.drain()
            size = int.from_bytes(await reader.readexactly(2), 'big')
            return await reader.readexactly(size)
        finally:
            writer.close()
            await writer.wait_closed()


class UDP(asyncio.DatagramProtocol):
    def __init__(self):
        self.tasks = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        if len(data) <= 4096 and len(self.tasks) < 16:
            task = asyncio.create_task(self.reply(data, address))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)

    async def reply(self, data, address):
        try:
            self.transport.sendto(await exchange(data), address)
        except (OSError, TimeoutError, asyncio.IncompleteReadError):
            pass


async def tcp(reader, writer):
    try:
        async with asyncio.timeout(12):
            size = int.from_bytes(await reader.readexactly(2), 'big')
            if not 12 <= size <= 4096:
                return
            response = await exchange(await reader.readexactly(size))
            writer.write(len(response).to_bytes(2, 'big') + response)
            await writer.drain()
    except (OSError, TimeoutError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


async def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        flags = fcntl.ioctl(sock, 0x8913, struct.pack('16sh', b'lo', 0))
        fcntl.ioctl(sock, 0x8914, struct.pack('16sh', b'lo', struct.unpack('16sh', flags[:18])[1] | 1))
    libc = ctypes.CDLL(None)
    for cap in range(41):
        libc.prctl(24, cap, 0, 0, 0)
    libc.prctl(38, 1, 0, 0, 0)
    transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(UDP, local_addr=('127.0.0.1', 0))
    port = transport.get_extra_info('sockname')[1]
    server = await asyncio.start_server(tcp, '127.0.0.1', port)
    try:
        command = [arg.replace('{XEzer_DNS}', f'127.0.0.1:{port}') for arg in sys.argv[1:]]
        child = await asyncio.create_subprocess_exec(*command)
        return await child.wait()
    finally:
        transport.close()
        server.close()
        await server.wait_closed()


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))

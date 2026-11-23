"""Trusted namespace entry point (stdlib only); mounted read-only by broker.

Modes:
  http      — loopback HTTP(S) relay to the request broker; ALL scanner TCP
              egress is redirected into it, so proxy-unaware clients are
              mediated too. Origin-form requests are rewritten to proxy form;
              TLS is forwarded as a synthesized CONNECT keyed by SNI/original
              destination, keeping broker-side TLS termination and policy.
  dns       — private UDP/TCP DNS bridge to the scoped DNS broker; ALL port-53
              egress is redirected into it regardless of the resolver a tool
              hardcodes.
  dns+http  — both bridges for mixed-protocol scanners.

Setup failure exits 125 WITHOUT launching the scanner: mandatory enforcement
is never silently skipped.
"""

import asyncio
import ctypes
import fcntl
import os
import socket
import struct
import subprocess
import sys

FAILURE_CODE = 125
FAILURE_MARKER = b"xezer-isolation:"


def fail(reason):
    sys.stderr.buffer.write(FAILURE_MARKER + reason.encode() + b"\n")
    sys.stderr.flush()
    sys.exit(FAILURE_CODE)


def bring_up_loopback():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        flags = fcntl.ioctl(sock, 0x8913, struct.pack("16sh", b"lo", 0))
        value = struct.unpack("16sh", flags[:18])[1] | 1
        fcntl.ioctl(sock, 0x8914, struct.pack("16sh", b"lo", value))


def drop_capabilities():
    libc = ctypes.CDLL(None, use_errno=True)
    for cap in range(41):
        libc.prctl(24, cap, 0, 0, 0)  # PR_CAPBSET_DROP
    libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS


def run_iptables(binary, args):
    try:
        proc = subprocess.run([binary, *args], capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail(f"{binary} unavailable: {type(exc).__name__}")
    if proc.returncode != 0:
        fail(f"{binary} rule rejected: {proc.stderr.decode(errors='replace')[:200]}")


def add_default_route():
    """Route ALL egress (incl. external) into the namespace so nat OUTPUT can
    redirect it to the bridges. Without this, proxy-unaware clients could only
    reach loopback; external destinations would be unrouted rather than mediated.
    """
    ip = next((p for p in ("/usr/sbin/ip", "/usr/bin/ip", "/bin/ip")
               if os.path.exists(p)), None)
    if ip is None:
        fail("iproute2 unavailable")
    for args in (["link", "add", "dummy0", "type", "dummy"],
                 ["addr", "add", "10.255.255.1/32", "dev", "dummy0"],
                 ["link", "set", "dummy0", "up"],
                 ["route", "add", "default", "dev", "dummy0"]):
        try:
            proc = subprocess.run([ip, *args], capture_output=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            fail(f"ip unavailable: {type(exc).__name__}")
        if proc.returncode != 0:
            fail(f"ip route setup rejected: {proc.stderr.decode(errors='replace')[:200]}")


def install_redirects(relay_port, dns_port):
    """Redirect scanner egress to the local bridges; bridge ports stay direct."""
    v4, v6 = "/usr/sbin/iptables", "/usr/sbin/ip6tables"
    for binary in (v4, v6):
        if relay_port is not None:
            run_iptables(binary, ["-t", "nat", "-A", "OUTPUT", "-p", "tcp",
                                  "--dport", str(relay_port), "-j", "RETURN"])
        if dns_port is not None:
            run_iptables(binary, ["-t", "nat", "-A", "OUTPUT", "-p", "tcp",
                                  "--dport", str(dns_port), "-j", "RETURN"])
            run_iptables(binary, ["-t", "nat", "-A", "OUTPUT", "-p", "udp",
                                  "--dport", "53", "-j", "REDIRECT",
                                  "--to-ports", str(dns_port)])
            run_iptables(binary, ["-t", "nat", "-A", "OUTPUT", "-p", "tcp",
                                  "--dport", "53", "-j", "REDIRECT",
                                  "--to-ports", str(dns_port)])
        if relay_port is not None:
            run_iptables(binary, ["-t", "nat", "-A", "OUTPUT", "-p", "tcp",
                                  "-j", "REDIRECT", "--to-ports", str(relay_port)])


def original_destination(sock):
    """Pre-NAT destination of a REDIRECTed connection (IPv4 and IPv6)."""
    try:
        if sock.family == socket.AF_INET6:
            data = sock.getsockopt(41, 80, 128)  # IP6T_SO_ORIGINAL_DST
            port = struct.unpack("!H", data[2:4])[0]
            addr = socket.inet_ntop(socket.AF_INET6, data[8:24])
        else:
            data = sock.getsockopt(0, 80, 16)  # SO_ORIGINAL_DST
            port = struct.unpack("!H", data[2:4])[0]
            addr = socket.inet_ntoa(data[4:8])
        return addr, port
    except (OSError, struct.error):
        return None


def parse_sni(record):
    """Extract the server_name from a TLS ClientHello record, or None."""
    if len(record) < 6 or record[0] != 22:
        return None
    handshake = record[5:]
    if len(handshake) < 4 or handshake[0] != 1:
        return None
    body = handshake[4:]
    pos = 2 + 32  # client_version + random
    if len(body) < pos + 1:
        return None
    pos += 1 + body[pos]  # session_id
    if len(body) < pos + 2:
        return None
    pos += 2 + int.from_bytes(body[pos:pos + 2], "big")  # cipher_suites
    if len(body) < pos + 1:
        return None
    pos += 1 + body[pos]  # compression_methods
    if len(body) < pos + 2:
        return None
    end = pos + 2 + int.from_bytes(body[pos:pos + 2], "big")
    pos += 2
    while pos + 4 <= min(end, len(body)):
        ext_type = int.from_bytes(body[pos:pos + 2], "big")
        ext_len = int.from_bytes(body[pos + 2:pos + 4], "big")
        pos += 4
        data = body[pos:pos + ext_len]
        pos += ext_len
        if ext_type != 0 or len(data) < 5:
            continue
        cursor = 2
        while cursor + 3 <= len(data):
            name_type = data[cursor]
            name_len = int.from_bytes(data[cursor + 1:cursor + 3], "big")
            name = data[cursor + 3:cursor + 3 + name_len]
            cursor += 3 + name_len
            if name_type == 0:
                try:
                    return name.decode("ascii").rstrip(".")
                except UnicodeDecodeError:
                    return None
    return None


async def pump(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


async def broker_connect():
    return await asyncio.open_unix_connection("/broker/socket")


async def relay_tls(reader, writer, head):
    """Forward intercepted TLS as a CONNECT keyed by SNI / original destination."""
    sock = writer.get_extra_info("socket")
    origin = original_destination(sock) if sock is not None else None
    record = head
    if len(record) >= 5:
        length = int.from_bytes(record[3:5], "big")
        if length > 18432:
            writer.close()
            return
        try:
            record += await asyncio.wait_for(reader.readexactly(length - (len(record) - 5)), 10)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            writer.close()
            return
    host = parse_sni(record)
    if host:
        port = origin[1] if origin else 443
    elif origin:
        host, port = origin
    else:
        writer.close()
        return
    authority = f"{host}:{port}"
    try:
        upstream, output = await broker_connect()
    except OSError:
        writer.close()
        return
    try:
        output.write(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        await output.drain()
        try:
            status = await asyncio.wait_for(upstream.readuntil(b"\r\n\r\n"), 15)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, asyncio.LimitOverrunError):
            return
        if not status.startswith(b"HTTP/1.1 200") and not status.startswith(b"HTTP/1.0 200"):
            return  # Broker denial: no synthetic response reaches the scanner.
        output.write(record)
        await output.drain()
        await asyncio.gather(pump(reader, output), pump(upstream, writer))
    finally:
        output.close()
        writer.close()


async def relay_http(reader, writer, head):
    """Proxy-form traffic passes through; origin-form is rewritten via Host."""
    try:
        line, _, rest = head.partition(b"\r\n")
        parts = line.decode("latin1").split(" ")
        if len(parts) < 3:
            writer.close()
            return
        method, target = parts[0], parts[1]
        if method == "CONNECT" or target.startswith(("http://", "https://")):
            upstream, output = await broker_connect()
            output.write(head)
            await output.drain()
            await asyncio.gather(pump(reader, output), pump(upstream, writer))
            return
        if not target.startswith("/"):
            writer.close()  # Non-HTTP protocol: fail closed, never tunneled.
            return
        host = None
        for header in rest.split(b"\r\n"):
            name, sep, value = header.partition(b":")
            if sep and name.strip().lower() == b"host":
                host = value.strip().decode("latin1")
                break
        if not host:
            sock = writer.get_extra_info("socket")
            origin = original_destination(sock) if sock is not None else None
            if origin is None:
                writer.close()
                return
            host = f"{origin[0]}:{origin[1]}"
        absolute = f"http://{host}{target}"
        upstream, output = await broker_connect()
        # rest already ends with the header terminator read by readuntil; adding
        # another would prepend garbage to a framed request body.
        output.write(f"{method} {absolute} {parts[2]}\r\n".encode("latin1") + rest)
        await output.drain()
        await asyncio.gather(pump(reader, output), pump(upstream, writer))
    except (OSError, UnicodeError):
        writer.close()


async def relay_accept(reader, writer):
    try:
        first = await asyncio.wait_for(reader.readexactly(1), 10)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
        writer.close()
        return
    if first == b"\x16":
        try:
            header = await asyncio.wait_for(reader.readexactly(4), 10)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            writer.close()
            return
        await relay_tls(reader, writer, first + header)
        return
    try:
        head = first + await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, asyncio.LimitOverrunError):
        writer.close()
        return
    await relay_http(reader, writer, head)


async def dns_exchange(data):
    async with asyncio.timeout(12):
        reader, writer = await asyncio.open_unix_connection("/broker/dns")
        try:
            writer.write(len(data).to_bytes(2, "big") + data)
            await writer.drain()
            size = int.from_bytes(await reader.readexactly(2), "big")
            return await reader.readexactly(size)
        finally:
            writer.close()
            await writer.wait_closed()


class DNSUDP(asyncio.DatagramProtocol):
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
            self.transport.sendto(await dns_exchange(data), address)
        except (OSError, TimeoutError, asyncio.IncompleteReadError):
            pass


async def dns_tcp(reader, writer):
    try:
        async with asyncio.timeout(12):
            size = int.from_bytes(await reader.readexactly(2), "big")
            if not 12 <= size <= 4096:
                return
            response = await dns_exchange(await reader.readexactly(size))
            writer.write(len(response).to_bytes(2, "big") + response)
            await writer.drain()
    except (OSError, TimeoutError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


async def main():
    mode = sys.argv[1]
    command = sys.argv[2:]
    if mode not in {"http", "dns", "dns+http"} or not command:
        fail("invalid runner mode")
    stage = "setup"
    try:
        stage = "loopback"
        bring_up_loopback()
        stage = "drop_capabilities"
        drop_capabilities()
        relay_port = dns_port = None
        server = dns_server = dns_transport = None
        if mode in {"http", "dns+http"}:
            stage = "default_route"
            add_default_route()
            stage = "relay_listen"
            server = await asyncio.start_server(relay_accept, "0.0.0.0", 0)
            relay_port = server.sockets[0].getsockname()[1]
        if mode in {"dns", "dns+http"}:
            stage = "dns_listen"
            loop = asyncio.get_running_loop()
            dns_transport, _ = await loop.create_datagram_endpoint(
                DNSUDP, local_addr=("0.0.0.0", 0))
            dns_port = dns_transport.get_extra_info("sockname")[1]
            dns_server = await asyncio.start_server(dns_tcp, "0.0.0.0", dns_port)
        stage = "redirects"
        install_redirects(relay_port, dns_port)
        stage = "child_env"
        env = dict(os.environ)
        if relay_port is not None:
            proxy = f"http://127.0.0.1:{relay_port}"
            env.update(http_proxy=proxy, https_proxy=proxy, HTTP_PROXY=proxy,
                       HTTPS_PROXY=proxy, ALL_PROXY=proxy, NO_PROXY="", no_proxy="",
                       SSL_CERT_FILE="/broker/ca.pem", REQUESTS_CA_BUNDLE="/broker/ca.pem",
                       CURL_CA_BUNDLE="/broker/ca.pem")
        replacements = {"{XEzer_PROXY}": f"http://127.0.0.1:{relay_port}" if relay_port else "",
                        "{XEzer_DNS}": f"127.0.0.1:{dns_port}" if dns_port else ""}
        command = [arg.replace("{XEzer_PROXY}", replacements["{XEzer_PROXY}"])
                       .replace("{XEzer_DNS}", replacements["{XEzer_DNS}"])
                   for arg in command]
        stage = "child_launch"
        child = await asyncio.create_subprocess_exec(*command, env=env)
        stage = "child_wait"
        code = await child.wait()
        if server is not None:
            server.close()
            await server.wait_closed()
        if dns_server is not None:
            dns_server.close()
            await dns_server.wait_closed()
        if dns_transport is not None:
            dns_transport.close()
        return code
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - fail closed with a bounded reason
        # Stage + type + errno only: never exception text (may carry paths/args).
        errno = getattr(exc, "errno", None)
        suffix = f":errno{errno}" if errno is not None else ""
        fail(f"{stage}:{type(exc).__name__}{suffix}")


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

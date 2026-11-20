import asyncio
import ipaddress

import aiohttp
from aiohttp import web
import pytest

from qbh.authorization import Authorization, RuleForbidden
from qbh.http_policy import HttpPolicy
from qbh.scope import ScopeEnforcer


def policy(*targets):
    scope = ScopeEnforcer.from_entries([{"in_scope": list(targets)}])
    p = HttpPolicy(scope, rate=10000, max_retries=0)
    p.authorization = Authorization(scope=scope)
    return p


async def relay(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


@pytest.mark.parametrize("kind", ["http", "socks5"])
async def test_proxy_numeric_target_body_cookie_and_pool(kind):
    hits, tunnels = [], []

    async def target(request):
        hits.append(
            (
                request.method,
                await request.text(),
                request.headers.get("X-Test"),
                request.headers.get("Cookie"),
                id(request.transport),
            )
        )
        return web.Response(text="verified")

    app = web.Application()
    app.router.add_route("*", "/ok", target)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    async def proxy(reader, writer):
        if kind == "http":
            data = await reader.readuntil(b"\r\n\r\n")
            authority = data.split()[1].decode()
            host, target_port = authority.rsplit(":", 1)
            host = host.strip("[]")
        else:
            assert await reader.readexactly(3) == b"\x05\x01\x00"
            writer.write(b"\x05\x00")
            await writer.drain()
            header = await reader.readexactly(4)
            assert header == b"\x05\x01\x00\x01"
            host = str(ipaddress.ip_address(await reader.readexactly(4)))
            target_port = int.from_bytes(await reader.readexactly(2), "big")
        tunnels.append((host, int(target_port)))
        upstream, upstream_writer = await asyncio.open_connection(
            host, int(target_port)
        )
        writer.write(
            b"HTTP/1.1 200 Connection established\r\n\r\n"
            if kind == "http"
            else b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        )
        await writer.drain()
        await asyncio.gather(relay(reader, upstream_writer), relay(upstream, writer))

    server = await asyncio.start_server(proxy, "127.0.0.1", 0)
    proxy_url = f"{kind}://127.0.0.1:{server.sockets[0].getsockname()[1]}"
    p = policy("127.0.0.1")
    url = f"http://127.0.0.1:{port}/ok"
    try:
        async with aiohttp.ClientSession() as session:
            for _ in range(2):
                response = await p.request(
                    session,
                    "POST",
                    url,
                    headers={"X-Test": "kept", "Cookie": "session=one"},
                    data="body",
                    proxy=proxy_url,
                )
                assert response.status == 200
            p.authorization.request_restrictions = [
                {
                    "hosts": ["*"],
                    "paths": ["/ok"],
                    "methods": ["POST"],
                    "forbidden": ["*"],
                }
            ]
            with pytest.raises(RuleForbidden):
                await p.request(session, "POST", url, proxy=proxy_url)
        assert len(tunnels) == 1
        assert hits[0][:4] == ("POST", "body", "kept", "session=one")
        assert len(hits) == 2 and hits[0][4] == hits[1][4]
    finally:
        server.close()
        await server.wait_closed()
        await runner.cleanup()


async def test_real_cli_mandatory_mediation_and_direct_escape():
    from qbh.egress import EgressController
    from qbh.adapters.base import run_process

    hits = []

    async def handler(request):
        hits.append((request.path, await request.read()))
        return web.Response(body=b"allowed\x00\xff")

    app = web.Application()
    app.router.add_route("*", "/{path:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    p = policy("127.0.0.1")
    p.authorization.request_restrictions = [
        {"hosts": ["*"], "paths": ["/restricted"], "methods": ["*"], "forbidden": ["*"]}
    ]
    egress = EgressController(p.authorization)
    try:
        with egress.activate():
            result = await run_process(
                ["curl", "-sS", "--max-time", "5", f"http://127.0.0.1:{port}/ok"]
            )
            assert result.ok, result
            assert result.stdout == b"allowed\x00\xff", result
            result = await run_process(
                [
                    "curl",
                    "-sS",
                    "-f",
                    "--max-time",
                    "5",
                    f"http://127.0.0.1:{port}/restricted",
                ]
            )
            assert not result.ok
        assert hits == [("/ok", b"")]
        assert any(e.get("event") == "mediation_blocked" for e in egress.audit)
    finally:
        await runner.cleanup()


async def test_namespace_cannot_bypass_broker(tmp_path):
    from qbh.mediation import RequestBroker, sandbox_command
    from qbh.adapters.base import run_process

    p = policy("127.0.0.1")
    sentinel_hits = []

    async def sentinel(reader, writer):
        sentinel_hits.append(1)
        writer.close()

    server = await asyncio.start_server(sentinel, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    # Transparent interception redirects ALL child TCP egress into the broker
    # relay, so a connect() to an unauthorized service is accepted by the relay
    # (not refused) but the service itself is never reached directly, and any
    # out-of-scope HTTP request is denied with no response. Both are asserted.
    code = f"""import os,socket
assert not os.path.exists('/run/docker.sock')
# Private procfs: PID 1 is the sandbox runner, so /proc/1/root exists but must
# resolve to the sandbox root itself — never the host filesystem.
root = os.path.realpath('/proc/1/root')
assert os.path.exists(root + '/runner.py'), root
assert not os.path.exists(root + '/home/firon'), root
assert not os.path.exists(root + '/mnt/c'), root
assert not os.path.exists('/home/vercel-sandbox')
s=socket.socket();s.settimeout(2)
s.connect_ex(('127.0.0.1',{port}))
s.close()
s=socket.socket();s.settimeout(3)
data=b''
try:
    s.connect(('192.0.2.1',80))
    s.sendall(b'GET / HTTP/1.1\\r\\nHost: 192.0.2.1\\r\\nConnection: close\\r\\n\\r\\n')
    while True:
        chunk=s.recv(65536)
        if not chunk: break
        data+=chunk
except OSError:
    pass
s.close()
print('isolated' if not data else 'BYPASS:'+repr(data))"""
    try:
        async with RequestBroker(p.authorization, tmp_path, []):
            result = await run_process(
                sandbox_command(["/usr/bin/python3", "-c", code], tmp_path), timeout=15
            )
            assert result.ok, result.stderr.decode()
            assert result.stdout.strip() == b"isolated"
        # The unauthorized loopback service received no direct connection: the
        # child's traffic was intercepted by the relay, never bypassing it.
        assert sentinel_hits == []
    finally:
        server.close()
        await server.wait_closed()


async def test_origin_form_post_body_is_preserved_through_relay(tmp_path):
    """Proxy-unaware clients send origin-form requests; the relay rewrite must
    not alter the framed body (no extra header terminator before the body)."""
    from qbh.mediation import RequestBroker, sandbox_command
    from qbh.adapters.base import run_process

    received = []

    async def target(request):
        received.append((request.path, await request.read()))
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_post("/{path:.*}", target)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    p = policy("127.0.0.1")
    code = f"""import socket
body=b'username=alice&password=synthetic-secret'
s=socket.create_connection(('127.0.0.1',{port}),timeout=5)
s.sendall(b'POST /login HTTP/1.1\\r\\nHost: 127.0.0.1:{port}\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\nContent-Length: '+str(len(body)).encode()+b'\\r\\n\\r\\n'+body)
data=b''
while True:
    chunk=s.recv(65536)
    if not chunk: break
    data+=chunk
assert b'200' in data.split(b'\\r\\n')[0], data
print('done')"""
    try:
        async with RequestBroker(p.authorization, tmp_path, []):
            result = await run_process(
                sandbox_command(["/usr/bin/python3", "-c", code], tmp_path), timeout=15
            )
            assert result.ok, result.stderr.decode()
        assert received == [("/login", b"username=alice&password=synthetic-secret")]
    finally:
        await runner.cleanup()


async def test_proxy_unaware_child_path_and_method_restrictions(tmp_path):
    """Raw-socket children ignore proxy env; transparent interception must still
    enforce configured path and method restrictions at the broker."""
    from qbh.mediation import RequestBroker, sandbox_command
    from qbh.adapters.base import run_process

    hits = []

    async def target(request):
        hits.append((request.method, request.path))
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_route("*", "/{path:.*}", target)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    p = policy("127.0.0.1")
    p.authorization.request_restrictions = [
        {"hosts": ["*"], "paths": ["/restricted"], "methods": ["*"], "forbidden": ["*"]},
        {"hosts": ["*"], "paths": ["/ok"], "methods": ["DELETE"], "forbidden": ["*"]},
    ]
    code = f"""import socket

def raw(method, path):
    s = socket.create_connection(('127.0.0.1', {port}), timeout=5)
    s.sendall((method + ' ' + path + ' HTTP/1.1\\r\\nHost: 127.0.0.1:{port}\\r\\nConnection: close\\r\\n\\r\\n').encode())
    data = b''
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    return data

assert b'200' in raw('GET', '/ok').split(b'\\r\\n')[0]
# Denial is a closed exchange, never a synthetic HTTP response from the target.
assert raw('GET', '/restricted') == b''
assert raw('DELETE', '/ok') == b''
print('enforced')"""
    try:
        async with RequestBroker(p.authorization, tmp_path, []) as broker:
            result = await run_process(
                sandbox_command(["/usr/bin/python3", "-c", code], tmp_path), timeout=15
            )
            assert result.ok, result.stderr.decode()
            assert result.stdout.strip() == b"enforced"
        assert hits == [("GET", "/ok")]
        assert sum(e.get("event") == "mediation_blocked" for e in broker.audit) >= 2
    finally:
        await runner.cleanup()


async def test_https_cli_is_decrypted_and_reauthorized(tmp_path, monkeypatch):
    import ssl
    from qbh.mediation import RequestBroker
    from qbh.egress import EgressController

    p = policy("127.0.0.1")
    ca = RequestBroker(p.authorization, tmp_path, [])
    tls = ca.tls_context("127.0.0.1")
    trust = ssl.create_default_context(cafile=str(tmp_path / "ca.pem"))
    monkeypatch.setattr(aiohttp.connector, "_SSL_CONTEXT_VERIFIED", trust)
    hits = []

    async def handle(request):
        hits.append(request.path)
        return web.Response(text="TLS verified")

    app = web.Application()
    app.router.add_get("/{path:.*}", handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=tls)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    p.authorization.request_restrictions = [
        {"hosts": ["*"], "paths": ["/restricted"], "methods": ["*"], "forbidden": ["*"]}
    ]
    controller = EgressController(p.authorization)
    try:
        for path in ("ok", "restricted"):
            result = await controller.run(
                [
                    "curl",
                    "-sS",
                    "-f",
                    "--max-time",
                    "10",
                    f"https://127.0.0.1:{port}/{path}",
                ]
            )
            assert result.ok == (path == "ok"), result.stderr.decode()
            if path == "ok":
                assert result.stdout == b"TLS verified"
        assert hits == ["/ok"]
    finally:
        await runner.cleanup()


async def test_ffuf_input_and_output_are_preserved(tmp_path):
    import json
    from qbh.egress import EgressController

    hits = []

    async def target(request):
        hits.append(request.path)
        return web.Response(text="found")

    app = web.Application()
    app.router.add_get("/{path:.*}", target)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    words, output = tmp_path / "words", tmp_path / "result.json"
    words.write_text("ok\nrestricted\n")
    output.touch()
    p = policy("127.0.0.1")
    p.authorization.request_restrictions = [
        {"hosts": ["*"], "paths": ["/restricted"], "methods": ["*"], "forbidden": ["*"]}
    ]
    try:
        result = await EgressController(p.authorization).run(
            [
                "ffuf",
                "-w",
                str(words),
                "-u",
                f"http://127.0.0.1:{port}/FUZZ",
                "-mc",
                "200",
                "-of",
                "json",
                "-o",
                str(output),
                "-noninteractive",
                "-s",
                "-t",
                "1",
            ]
        )
        assert result.ok, result.stderr.decode()
        report = json.loads(output.read_text())
        assert [r["url"] for r in report["results"]] == [f"http://127.0.0.1:{port}/ok"]
        assert hits == ["/ok"]
    finally:
        await runner.cleanup()


@pytest.mark.parametrize("secure_proxy", [False, True])
async def test_proxy_tls_numeric_connect_sni_and_credentials(
    tmp_path, monkeypatch, secure_proxy
):
    import ssl
    from qbh.mediation import RequestBroker
    import socket

    original_resolve = socket.getaddrinfo
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, *a, **kw: original_resolve(
            "127.0.0.1" if host == "app.example.test" else host, *a, **kw
        ),
    )
    p = policy("app.example.test", "127.0.0.1")
    certs = RequestBroker(p.authorization, tmp_path, [])
    target_tls = certs.tls_context("app.example.test")
    proxy_tls = certs.tls_context("127.0.0.1") if secure_proxy else None
    trust = ssl.create_default_context(cafile=str(tmp_path / "ca.pem"))
    monkeypatch.setattr(aiohttp.connector, "_SSL_CONTEXT_VERIFIED", trust)
    monkeypatch.setattr("qbh.proxy_transport.ssl.create_default_context", lambda: trust)
    names, connects = [], []
    target_tls.set_servername_callback(lambda sock, name, ctx: names.append(name))

    async def target(request):
        assert request.host.startswith("app.example.test:")
        assert "Proxy-Authorization" not in request.headers
        return web.Response(text="TLS via proxy")

    app = web.Application()
    app.router.add_get("/", target)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=target_tls)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    p.authorization.allowed_ports = (port,)

    async def proxy(reader, writer):
        data = await reader.readuntil(b"\r\n\r\n")
        connects.append(data)
        assert data.startswith(f"CONNECT 127.0.0.1:{port} HTTP/1.1".encode())
        upstream, output = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"HTTP/1.1 200 OK\r\n\r\n")
        await writer.drain()
        await asyncio.gather(relay(reader, output), relay(upstream, writer))

    server = await asyncio.start_server(proxy, "127.0.0.1", 0, ssl=proxy_tls)
    px = f"{'https' if secure_proxy else 'http'}://user:synthetic@127.0.0.1:{server.sockets[0].getsockname()[1]}"
    try:
        async with aiohttp.ClientSession() as session:
            response = await p.request(
                session, "GET", f"https://app.example.test:{port}/", proxy=px
            )
            assert response.status == 200 and response.text == "TLS via proxy"
        assert names == ["app.example.test"]
        assert b"Proxy-Authorization: Basic " in connects[0]
    finally:
        server.close()
        await server.wait_closed()
        await runner.cleanup()


async def test_dry_run_no_broker_or_child(monkeypatch):
    from qbh.egress import EgressController

    p = policy("127.0.0.1")
    p.authorization.dry_run = True

    async def forbidden(*args, **kwargs):
        pytest.fail("dry run attempted IO")

    monkeypatch.setattr(asyncio, "start_unix_server", forbidden)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden)
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", forbidden)
    result = await EgressController(p.authorization).run(["curl", "http://127.0.0.1/"])
    assert result.blocked


async def test_cli_redirect_and_multiple_cookies(tmp_path):
    from qbh.egress import EgressController

    calls = []

    async def handle(request):
        calls.append(request.path)
        if request.path == "/start":
            response = web.Response(status=302, headers={"Location": "/finish"})
            response.set_cookie("one", "first")
            response.set_cookie("two", "second")
            return response
        assert request.cookies == {"one": "first", "two": "second"}
        return web.Response(text="session preserved")

    app = web.Application()
    app.router.add_get("/{path:.*}", handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    p = policy("127.0.0.1")
    try:
        result = await EgressController(p.authorization).run(
            [
                "curl",
                "-fsS",
                "-L",
                "-b",
                "",
                "--max-time",
                "10",
                f"http://127.0.0.1:{port}/start",
            ]
        )
        assert result.ok and result.stdout == b"session preserved", result
        assert calls == ["/start", "/finish"]
    finally:
        await runner.cleanup()

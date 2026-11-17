"""Real optional binaries: no subprocess mocks; select with XEZER_CLI_TESTS=1."""

import os
from pathlib import Path
import json

from aiohttp import web
import pytest

from qbh.authorization import Authorization
from qbh.scope import ScopeEnforcer
from qbh.egress import EgressController
from qbh.installer import validate_pd_httpx

pytestmark = pytest.mark.skipif(
    not os.environ.get("XEZER_CLI_TESTS"),
    reason="explicit additional CLI integration gate",
)


def binary(name):
    return str(Path(os.environ["XEZER_TOOL_BIN"]) / name)


def controller():
    auth = Authorization(
        scope=ScopeEnforcer.from_entries([{"in_scope": ["127.0.0.1", "example.test"]}])
    )
    auth.request_restrictions = [
        {"hosts": ["*"], "paths": ["/restricted"], "methods": ["*"], "forbidden": ["*"]}
    ]
    return EgressController(auth)


async def test_alterx_generates_real_permutations_offline():
    egress = controller()
    result = await egress.run(
        [
            binary("alterx"),
            "-l",
            "api.example.test",
            "-p",
            "{{sub}}-dev.{{suffix}}",
            "-silent",
            "-duc",
        ]
    )
    assert result.ok, result.stderr.decode()
    assert b"api-dev.example.test" in result.stdout
    assert egress.audit[-1]["event"] == "offline_process"


async def test_jsluice_parses_local_javascript_without_network(tmp_path):
    source = tmp_path / "app.js"
    source.write_text("fetch('/api/users');")
    egress = controller()
    result = await egress.run([binary("jsluice"), "urls", str(source)])
    assert result.ok, result.stderr.decode()
    records = [json.loads(line) for line in result.stdout.splitlines()]
    assert any(record["url"] == "/api/users" for record in records)
    assert egress.audit[-1]["event"] == "offline_process"


@pytest.mark.parametrize("scanner", ["httpx", "jsluice"])
async def test_real_http_scanners_permitted_and_denied(scanner):
    hits = []

    async def handler(request):
        hits.append(request.path)
        return web.Response(
            text="fetch('/api/users');"
            if scanner == "jsluice"
            else "<html><title>XEzer fixture</title></html>",
            content_type="application/javascript"
            if scanner == "jsluice"
            else "text/html",
        )

    app = web.Application()
    app.router.add_get("/{path:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    egress = controller()
    try:
        if scanner == "httpx":
            with egress.activate():
                assert await validate_pd_httpx(binary("httpx"))
        for path in ("ok", "restricted"):
            url = f"http://127.0.0.1:{port}/{path}"
            args = (
                [binary(scanner), "urls", url]
                if scanner == "jsluice"
                else [
                    binary(scanner),
                    "-u",
                    url,
                    "-json",
                    "-silent",
                    "-status-code",
                    "-title",
                    "-nfs",
                    "-timeout",
                    "5",
                ]
            )
            result = await egress.run(args, timeout=30)
            if path == "ok":
                assert result.ok, result.stderr.decode()
                records = [
                    json.loads(line)
                    for line in result.stdout.splitlines()
                    if line.startswith(b"{")
                ]
                assert records, (result.stdout, result.stderr)
                if scanner == "httpx":
                    assert (
                        records[0]["status_code"] == 200
                        and records[0]["title"] == "XEzer fixture"
                    )
                else:
                    assert records[0]["url"] == "/api/users"
                    assert records[0]["filename"] == url
        assert hits and set(hits) == {"/ok"}
        assert any(e["event"] == "mediation_blocked" for e in egress.audit)
    finally:
        await runner.cleanup()


async def test_actual_recon_httpx_to_database(make_ctx, tmp_db, monkeypatch):
    from qbh.engines.recon import ReconEngine
    from qbh.results import EngineResult

    hits = []

    async def page(request):
        hits.append(request.path)
        return web.Response(
            text="<html><title>Recon integration</title></html>",
            content_type="text/html",
        )

    app = web.Application()
    app.router.add_get("/{path:.*}", page)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    monkeypatch.setenv("QBH_HTTPX_BIN", binary("httpx"))
    ctx = make_ctx()
    result = EngineResult(stage="recon")
    try:
        with ctx.egress.activate():
            hosts = await ReconEngine(ctx)._httpx([f"http://127.0.0.1:{port}"], result)
        assert result.ok and hosts and hits, (result, hosts)
        assert hosts[0]["status"] == 200
        row = (
            tmp_db.get_db()
            .execute("SELECT subdomain, title FROM hosts WHERE id=?", (hosts[0]["id"],))
            .fetchone()
        )
        assert row[0] == "127.0.0.1" and row[1] == "Recon integration"
        assert any(e["event"] == "offline_process" for e in ctx.egress_audit)
        assert any(e["event"] == "mediated_process" for e in ctx.egress_audit)
    finally:
        await runner.cleanup()


async def test_remote_jsluice_failure_is_not_empty_success():
    async def disconnect(request):
        request.transport.close()
        return web.Response()

    app = web.Application()
    app.router.add_get("/", disconnect)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    egress = controller()
    try:
        url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/"
        result = await egress.run([binary("jsluice"), "urls", url])
        assert not result.ok and b"transport failed" in result.stderr
        assert not any(e["event"] == "offline_process" for e in egress.audit)
    finally:
        await runner.cleanup()


async def test_version_probes_do_not_bypass_dry_run(monkeypatch):
    import asyncio

    async def forbidden(*args, **kwargs):
        pytest.fail("dry-run started a process")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden)
    egress = controller()
    egress.auth.dry_run = True
    result = await egress.run([binary("httpx"), "-version"])
    assert result.blocked


async def test_katana_crawls_real_graph_under_policy(monkeypatch, make_ctx, tmp_db):
    from qbh.engines.recon import ReconEngine
    from qbh.results import EngineResult
    hits = []

    async def page(request):
        hits.append(request.path)
        if request.path == '/':
            return web.Response(text='<a href="/allowed">yes</a><a href="/restricted">no</a>'
                                     '<a href="/jump">redirect</a>', content_type='text/html')
        if request.path == '/jump':
            raise web.HTTPFound(f'http://localhost:{request.url.port}/escape')
        return web.Response(text='<html>discovered</html>', content_type='text/html')

    app = web.Application()
    app.router.add_get('/{path:.*}', page)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    ctx = make_ctx()
    ctx._auth().request_restrictions = controller().auth.request_restrictions
    monkeypatch.setenv('PATH', os.environ['XEZER_TOOL_BIN'] + os.pathsep + os.environ['PATH'])
    host_id = tmp_db.upsert_host('127.0.0.1', ctx.scan_id)
    result = EngineResult(stage='recon')
    try:
        with ctx.egress.activate():
            await ReconEngine(ctx)._crawl([dict(host='127.0.0.1', id=host_id,
                                               url=f'http://127.0.0.1:{port}/')], result)
        assert '/' in hits and '/allowed' in hits, (hits, ctx.egress_audit, result)
        assert '/restricted' not in hits and '/escape' not in hits
        rows = tmp_db.get_db().execute('SELECT url, source FROM urls').fetchall()
        assert any(row[0].endswith('/allowed') and row[1] == 'katana' for row in rows)
        assert not any('localhost' in row[0] for row in rows)
        assert any(e['event'] == 'mediated_process' for e in ctx.egress_audit)
    finally:
        await runner.cleanup()


@pytest.mark.parametrize('escaped', [False, True])
async def test_real_dalfox_positive_and_negative_evidence(escaped, tmp_path, tmp_db, make_ctx):
    import html
    from qbh.engines.xss import XSSEngine
    from qbh.results import EngineResult
    hits = []
    async def reflect(request):
        value = request.query.get('q', '')
        hits.append(value)
        return web.Response(text='<html><body>' + (html.escape(value) if escaped else value)
                            + '</body></html>', content_type='text/html')
    app = web.Application()
    app.router.add_get('/reflect', reflect)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    payload = tmp_path / 'payload.txt'
    payload.write_text('<svg id=dalfox onload=alert(1)>\n')
    ctx = make_ctx()
    url = f'http://127.0.0.1:{port}/reflect?q=baseline'
    host_id = tmp_db.upsert_host('127.0.0.1', ctx.scan_id)
    try:
        proc = await ctx.egress.run([binary('dalfox'), 'url', url, '--no-spinner', '--silence',
            '--format', 'jsonl', '--only-poc', 'r,v', '--skip-mining-all', '--skip-bav',
            '--skip-headless', '--skip-grepping', '--only-custom-payload', '--custom-payload', str(payload),
            '-p', 'q', '--worker', '2', '--timeout', '3', '--output-response'], timeout=60)
        assert proc.ok, (proc.stderr.decode(), proc.stdout.decode())
        assert any('dalfox' in value for value in hits), (hits, proc.stderr.decode())
        res = EngineResult(stage='xss')
        XSSEngine(ctx)._ingest_dalfox(proc.stdout, dict(host_id=host_id, url=url), res)
        if escaped:
            assert res.findings == 0, proc.stdout.decode()
        else:
            assert res.findings > 0, (proc.stdout.decode(), proc.stderr.decode())
            rows = tmp_db.get_db().execute('SELECT status, source, evidence FROM findings').fetchall()
            assert all(row['status'] == 'candidate' and row['source'] == 'dalfox' for row in rows)
            assert any('dalfox' in row['evidence'] for row in rows)
    finally:
        await runner.cleanup()


async def test_real_dalfox_denial_and_cli_failure():
    hits = []
    async def page(request):
        hits.append(request.path)
        return web.Response(text='unexpected')
    app = web.Application()
    app.router.add_get('/{path:.*}', page)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    egress = controller()
    try:
        denied = await egress.run([binary('dalfox'), 'url', f'http://127.0.0.1:{port}/restricted?q=x',
                                   '--silence', '--format', 'jsonl', '--skip-headless',
                                   '--skip-mining-all', '--timeout', '1'], timeout=20)
        assert not denied.timed_out
        assert not hits
        assert any(e['event'] == 'mediation_blocked' for e in egress.audit)
        failed = await egress.run([binary('dalfox'), 'url', f'http://127.0.0.1:{port}/ok?q=x',
                                   '--xezer-invalid-option'], timeout=20)
        assert not failed.ok and failed.returncode != 0
        assert b'unknown flag' in failed.stderr
        assert not hits
    finally:
        await runner.cleanup()

"""Control-plane sources must obey the same transport/lifecycle boundary."""
from types import SimpleNamespace

import aiohttp
import pytest

from qbh.authorization import Authorization, RuleForbidden
from qbh.engines.deep_enum import DeepEnumEngine
from qbh.scope import ScopeEnforcer


def context(*, dry_run=False):
    auth = Authorization(scope=ScopeEnforcer.from_entries([
        {'in_scope': ['example.test', '*.example.test']}]), dry_run=dry_run)
    return SimpleNamespace(cfg=None, guardian=None, authorization=auth,
                           _auth=lambda: auth, egress_audit=[],
                           limits=SimpleNamespace(max_subdomains_per_target=100))


@pytest.mark.asyncio
async def test_crtsh_dry_run_never_constructs_network_session(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('dry-run constructed an outbound session')
    monkeypatch.setattr(aiohttp, 'ClientSession', forbidden)
    with pytest.raises(RuleForbidden, match='dry_run'):
        await DeepEnumEngine(context(dry_run=True))._crtsh('example.test')


@pytest.fixture
async def provider_server():
    from aiohttp import web
    seen = []
    app = web.Application()

    async def handle(request):
        seen.append((request.method, request.path, dict(request.headers), await request.text()))
        if request.path == '/redirect':
            raise web.HTTPFound('/forbidden')
        if request.path == '/crt':
            return web.json_response([{'name_value': '*.api.example.test\nexample.test'}])
        if request.path == '/osv':
            return web.json_response({'vulns': [{'id': 'TEST-1'}]})
        if request.path == '/large':
            return web.Response(text='["' + 'x' * 100 + '"]')
        return web.json_response({'ok': True})

    app.router.add_route('*', '/{path:.*}', handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        yield f'http://127.0.0.1:{port}', seen
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_real_queries_and_crtsh_parser(provider_server, monkeypatch):
    from qbh.provider_policy import PROVIDERS, ProviderSession
    from qbh.engines import cve_intel, library_cve
    base, seen = provider_server
    monkeypatch.setitem(PROVIDERS, 'crtsh', ('GET', base + '/crt'))
    monkeypatch.setitem(PROVIDERS, 'osv', ('POST', base + '/osv'))
    monkeypatch.setattr(cve_intel, 'OSV_URL', base + '/osv')
    monkeypatch.setattr(library_cve, 'OSV_URL', base + '/osv')
    ctx = context()
    assert await DeepEnumEngine(ctx)._crtsh('example.test') == {'api.example.test', 'example.test'}
    async with ProviderSession(ctx, ('osv',)) as session:
        assert await cve_intel.search_osv(session, 'example', '1.0') == ['TEST-1']
        assert await library_cve.osv_npm(session, 'example', '1.0') == [{'id': 'TEST-1'}]
    assert [method for method, *_ in seen] == ['GET', 'POST', 'POST']
    assert all('Cookie' not in headers and 'Authorization' not in headers for _, _, headers, _ in seen)
    assert not ctx.authorization.is_authorized('127.0.0.1')
    assert all(event['event'] == 'provider_authorized' for event in ctx.egress_audit)
    assert 'example.test' not in str(ctx.egress_audit)  # query contents not logged


@pytest.mark.asyncio
async def test_real_redirect_endpoint_and_method_denial(provider_server, monkeypatch):
    from qbh.provider_policy import PROVIDERS, ProviderSession
    base, seen = provider_server
    monkeypatch.setitem(PROVIDERS, 'crtsh', ('GET', base + '/redirect'))
    async with ProviderSession(context(), ('crtsh',)) as session:
        with pytest.raises(RuleForbidden, match='provider_endpoint'):
            async with session.get(base + '/redirect'):
                pass
        with pytest.raises(RuleForbidden, match='provider_endpoint'):
            async with session.post(base + '/redirect', json={'ignored': True}):
                pass
    assert [entry[1] for entry in seen] == ['/redirect']


@pytest.mark.asyncio
async def test_provider_private_dns_cannot_inherit_enterprise_grant(provider_server, monkeypatch):
    import socket
    from qbh.provider_policy import PROVIDERS, ProviderSession
    from qbh.scope import ScopeEnforcer
    base, seen = provider_server
    port = int(base.rsplit(':', 1)[1])
    monkeypatch.setitem(PROVIDERS, 'crtsh', ('GET', f'http://source.example:{port}/'))
    resolved = []

    async def resolve(self, host, port, family=socket.AF_INET):
        resolved.append(host)
        return [dict(hostname=host, host='127.0.0.1', port=port,
                     family=socket.AF_INET, proto=0, flags=0)]

    monkeypatch.setattr(aiohttp.resolver.ThreadedResolver, 'resolve', resolve)
    ctx = context()
    ctx.authorization.scope = ScopeEnforcer.from_entries([{'in_scope': ['example.test', '127.0.0.1']}])
    async with ProviderSession(ctx, ('crtsh',)) as session:
        with pytest.raises(RuleForbidden, match='no_authorized_dns'):
            async with session.get(f'http://source.example:{port}/'):
                pass
    assert resolved == ['source.example']
    assert seen == []


@pytest.mark.asyncio
async def test_provider_lifecycle_rules_and_limits(provider_server, monkeypatch):
    from qbh.provider_policy import PROVIDERS, ProviderSession
    from qbh.authorization import ScanExpired
    from qbh.http_policy import HttpPolicy
    base, seen = provider_server
    monkeypatch.setitem(PROVIDERS, 'crtsh', ('GET', base + '/large'))
    ctx = context()
    shared = HttpPolicy(ctx.authorization.scope, max_body=20)
    ctx.guardian = SimpleNamespace(policy=shared)
    async with ProviderSession(ctx, ('crtsh',)) as session:
        assert session.policy._sem is shared._sem
        assert session.policy._state is shared._state
        async with session.get(base + '/large') as response:
            with pytest.raises(ValueError, match='truncated'):
                await response.json()
        ctx.authorization.dry_run = True
        with pytest.raises(RuleForbidden, match='dry_run'):
            async with session.get(base + '/large'):
                pass
        ctx.authorization.dry_run = False
        ctx.authorization.cancel()
        with pytest.raises(ScanExpired):
            async with session.get(base + '/large'):
                pass
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_provider_engine_operation_denial_before_dns(monkeypatch):
    from qbh.provider_policy import ProviderSession
    ctx = context()
    ctx.authorization.rules.forbidden.add('cve_intel')
    with ctx.authorization.operation('cve_intel'), pytest.raises(RuleForbidden):
        async with ProviderSession(ctx, ('osv',)):
            pytest.fail('forbidden operation opened a session')


@pytest.mark.asyncio
async def test_provider_request_restriction_keeps_parent_action(provider_server, monkeypatch):
    from qbh.provider_policy import PROVIDERS, ProviderSession
    base, seen = provider_server
    monkeypatch.setitem(PROVIDERS, 'crtsh', ('GET', base + '/crt'))
    ctx = context()
    ctx.authorization.request_restrictions = [dict(hosts=['127.0.0.1'], paths=['/crt'],
                                                 methods=['GET'], forbidden=['deep_enum'])]
    with ctx.authorization.operation('deep_enum'):
        async with ProviderSession(ctx, ('crtsh',)) as session:
            with pytest.raises(RuleForbidden, match='explicit_request_restriction'):
                async with session.get(base + '/crt'):
                    pass
    assert seen == []


@pytest.mark.asyncio
async def test_native_fallbacks_and_race_use_policy(make_ctx, provider_server, tmp_db):
    from qbh.engines.fingerprint import FingerprintEngine
    from qbh.engines.api_fuzz import APIFuzzEngine
    from qbh.engines.race import RaceEngine
    base, seen = provider_server
    ctx = make_ctx(race_fixture=base + '/race', race_count=2)
    ctx.guardian = None
    async with aiohttp.ClientSession() as session:
        code, _, text = await FingerprintEngine(ctx)._fetch(session, base + '/ok')
        assert code == 200 and 'true' in text
        assert await APIFuzzEngine(ctx)._fetch_document(session, base + '/api') == {'ok': True}
    result = await RaceEngine(ctx).run()
    assert result.data['http_200'] == 2
    assert len(seen) == 4
    ctx._auth().request_restrictions = [dict(hosts=['127.0.0.1'], paths=['*'],
                                            methods=['GET'], forbidden=['*'])]
    async with aiohttp.ClientSession() as session:
        assert (await FingerprintEngine(ctx)._fetch(session, base + '/ok'))[0] is None
        assert await APIFuzzEngine(ctx)._fetch_document(session, base + '/api') is None
    with pytest.raises(RuleForbidden):
        await RaceEngine(ctx).run()
    ctx.args.dry_run = True
    with pytest.raises(RuleForbidden, match='dry_run'):
        await RaceEngine(ctx).run()
    assert len(seen) == 4


@pytest.mark.asyncio
async def test_provider_deep_json_is_classified_as_invalid_data():
    from qbh.provider_policy import _Response
    response = _Response(SimpleNamespace(status=200, truncated=False,
                                         text='[' * 2000 + '0' + ']' * 2000))
    with pytest.raises(ValueError, match='nesting_exceeded'):
        await response.json()


@pytest.mark.asyncio
async def test_provider_json_string_braces_do_not_consume_depth():
    import json
    from qbh.provider_policy import _Response
    payload = {'text': '\\"' + '[' * 100}
    response = _Response(SimpleNamespace(status=200, truncated=False, text=json.dumps(payload)))
    assert await response.json() == payload

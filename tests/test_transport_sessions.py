"""Real alternate-transport regression: bodies, duplicate cookies and isolation."""
import aiohttp
from aiohttp import web
import pytest
from qbh.http_policy import HttpPolicy
from qbh.scope import ScopeEnforcer
from qbh.stealth.impersonate import ImpersonatingTransport


async def test_curl_login_body_cookies_and_isolation():
    pytest.importorskip('curl_cffi')
    async def login(request):
        data = await request.json()
        response = web.json_response({'name': data['name']})
        response.set_cookie('session', data['name'])
        response.set_cookie('csrf', 'synthetic')
        return response
    async def identity(request):
        return web.json_response(dict(request.cookies))
    app = web.Application()
    app.router.add_post('/login', login)
    app.router.add_get('/identity', identity)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    base = 'http://127.0.0.1:' + str(site._server.sockets[0].getsockname()[1])
    transport = ImpersonatingTransport('chrome')
    policy = HttpPolicy(ScopeEnforcer.from_entries([{'in_scope':['127.0.0.1']}]))
    policy.transport = transport
    try:
        async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as alice, aiohttp.ClientSession() as anonymous:
            result = await policy.post(alice, base+'/login', json={'name':'alice'}, retries=0)
            assert result.status == 200
            assert {k:v.value for k,v in alice.cookie_jar.filter_cookies(__import__('yarl').URL(base)).items()} == {'session':'alice','csrf':'synthetic'}
            assert 'alice' in (await policy.get(alice, base+'/identity')).text
            assert (await policy.get(anonymous, base+'/identity')).text == '{}'
    finally:
        await transport.close()
        await runner.cleanup()


async def test_state_changing_request_is_not_retried(monkeypatch):
    import asyncio
    policy = HttpPolicy(ScopeEnforcer.from_entries([{'in_scope':['127.0.0.1']}]))
    attempts = []
    async def fail(*args):
        attempts.append(args)
        raise asyncio.TimeoutError()
    monkeypatch.setattr(policy, '_fetch_once', fail)
    with pytest.raises(asyncio.TimeoutError):
        await policy.post(None, 'http://127.0.0.1/action', retries=2)
    assert len(attempts) == 1

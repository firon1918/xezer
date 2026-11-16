"""Network policy regressions; exclusively synthetic DNS and loopback fixtures."""
import socket
import pytest
from qbh.authorization import Authorization, RuleForbidden
from qbh.scope import ScopeEnforcer
from qbh.egress import EgressController


def auth(*hosts):
    return Authorization(scope=ScopeEnforcer.from_entries([{'in_scope':list(hosts)}]))


async def test_child_without_visible_target_cannot_escape():
    ctl = EgressController(auth('127.0.0.1'))
    blocked, _ = await ctl.prepare_process(['python', '-c', 'import socket'], [])
    assert blocked is not None and blocked.blocked


async def test_dns_private_requires_explicit_ip_scope():
    from qbh.network_policy import PolicyResolver
    class DNS:
        async def resolve(self, host, port, family):
            return [{'hostname':host,'host':'127.0.0.1','port':port,'family':socket.AF_INET,'proto':0,'flags':0}]
    resolver = PolicyResolver(auth('example.test'), DNS())
    with pytest.raises(RuleForbidden):
        await resolver.resolve('example.test', 443)


async def test_dns_rebinding_is_checked_each_resolution():
    from qbh.network_policy import PolicyResolver
    class DNS:
        def __init__(self): self.calls = 0
        async def resolve(self, host, port, family):
            self.calls += 1
            return [{'hostname':host,'host':'8.8.8.8' if self.calls == 1 else '127.0.0.1','port':port,'family':socket.AF_INET,'proto':0,'flags':0}]
    resolver = PolicyResolver(auth('example.test'), DNS())
    await resolver.resolve('example.test', 443)
    with pytest.raises(RuleForbidden):
        await resolver.resolve('example.test', 443)


@pytest.mark.parametrize('ip',['::1','::ffff:127.0.0.1','169.254.169.254','10.1.1.1','0.0.0.0'])
def test_special_ips_denied_unless_explicit(ip):
    from qbh.network_policy import validate_ip
    with pytest.raises(RuleForbidden):
        validate_ip(auth('example.test'), ip)


def test_port_and_header_overrides():
    from qbh.network_policy import validate_options
    with pytest.raises(RuleForbidden):
        validate_options(auth('example.test'), 'https://example.test:8443/', {}, {})
    with pytest.raises(RuleForbidden):
        validate_options(auth('example.test'), 'https://example.test/', {'X-HTTP-Method-Override':'DELETE'}, {})
    with pytest.raises(RuleForbidden):
        validate_options(auth('example.test'), 'https://example.test/', {}, {'proxy':'http://127.0.0.1'})


async def test_cli_dry_run_never_starts_network_or_process(tmp_path, monkeypatch):
    import asyncio
    import aiohttp
    from main import run, build_parser
    def forbidden(*a, **kw):
        raise AssertionError('dry-run performed I/O')
    monkeypatch.setattr(aiohttp.ClientSession, '_request', forbidden)
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    cfg = tmp_path / 'cfg.yaml'
    cfg.write_text('scope:\n  - in_scope: [127.0.0.1]\n    domain: 127.0.0.1\n')
    for mode in ['full','recon','vuln','hunt','install']:
        assert await run(build_parser().parse_args(['--config',str(cfg),'--mode',mode,'--dry-run'])) == 0


@pytest.mark.parametrize('ports',[[],[True],[0],[65536],['443']])
def test_invalid_port_configuration(load_config, ports):
    from qbh.config import ConfigError
    with pytest.raises(ConfigError):
        load_config([{'domain':'example.test','in_scope':['example.test']}],extra={'network_allowed_ports':ports})


def test_explicit_additional_port(load_config):
    from qbh.authorization import from_config
    from qbh.network_policy import validate_options
    cfg = load_config([{'domain':'example.test','in_scope':['example.test']}],extra={'network_allowed_ports':[8443]})
    validate_options(from_config(cfg), 'https://example.test:8443/', {}, {})


async def test_actual_child_never_runs_even_with_hidden_target(tmp_path):
    import sys
    from qbh.adapters.base import run_process
    marker = tmp_path/'launched'
    controller = EgressController(auth('127.0.0.1'))
    with controller.activate():
        result = await run_process([sys.executable,'-c',f'open({str(marker)!r},"w").close()'])
    assert result.blocked and not marker.exists()


async def test_redirect_credentials_cannot_cross_origin():
    from aiohttp import web, ClientSession
    from qbh.http_policy import HttpPolicy
    hits = []
    async def redirect(request):
        hits.append('original')
        return web.Response(status=307, headers={'Location':'http://127.0.0.1:1/restricted'})
    app = web.Application()
    app.router.add_get('/', redirect)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner,'127.0.0.1',0)
    await site.start()
    policy = HttpPolicy(auth('127.0.0.1').scope)
    policy.authorization = auth('127.0.0.1')
    try:
        async with ClientSession() as session:
            with pytest.raises(RuleForbidden, match='cross_origin'):
                await policy.get(session, f'http://127.0.0.1:{runner.addresses[0][1]}/',
                                 headers={'Authorization':'Bearer synthetic'}, allow_redirects=True)
        assert hits == ['original']
    finally:
        await runner.cleanup()

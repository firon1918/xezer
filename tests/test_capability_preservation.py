import socket
import pytest
from qbh.authorization import Authorization, RuleForbidden
from qbh.scope import ScopeEnforcer
from qbh.network_policy import PolicyResolver, validate_options, validate_ip


def auth(*targets):
    return Authorization(
        scope=ScopeEnforcer.from_entries([{"in_scope": list(targets)}])
    )


async def test_mixed_dns_retains_authorized_candidates():
    class DNS:
        async def resolve(self, host, port, family):
            return [
                dict(
                    hostname=host,
                    host=ip,
                    port=port,
                    family=socket.AF_INET,
                    proto=0,
                    flags=0,
                )
                for ip in ["127.0.0.1", "8.8.8.8"]
            ]

    result = await PolicyResolver(auth("app.example"), DNS()).resolve(
        "app.example", 443
    )
    assert [r["host"] for r in result] == ["8.8.8.8"]


@pytest.mark.parametrize(
    "ip,cidr",
    [
        ("10.1.2.3", "10.1.0.0/16"),
        ("fd00::5", "fd00::/64"),
        ("::ffff:10.1.2.3", "10.1.0.0/16"),
    ],
)
def test_enterprise_explicit_network(ip, cidr):
    validate_ip(auth(cidr), ip)
    assert not auth(cidr).is_authorized("unrelated.example")
    with pytest.raises(RuleForbidden):
        validate_ip(auth("public.example"), ip)


@pytest.mark.parametrize(
    "operation",
    [
        "dos",
        "ddos",
        "resource_exhaustion",
        "brute_force_attacks",
        "persistence",
        "destructive_operations",
        "unauthorized_exfiltration",
    ],
)
def test_immutable_prohibited_categories(operation):
    assert not auth("example.test").allows(operation)


def test_method_override_uses_effective_authorization():
    policy = auth("example.test")
    validate_options(
        policy, "https://example.test/", {"X-HTTP-Method-Override": "PATCH"}, {}
    )
    policy.rules.forbidden.add("state_changing")
    with pytest.raises(RuleForbidden):
        validate_options(
            policy, "https://example.test/", {"X-HTTP-Method-Override": "PATCH"}, {}
        )


async def test_hostname_pool_reuse_and_authorized_redirect(monkeypatch):
    import aiohttp
    from aiohttp import web
    from qbh.http_policy import HttpPolicy

    transports = []
    observed = []

    async def handler(request):
        transports.append(request.transport)
        observed.append(dict(request.headers))
        if request.path == "/redirect":
            return web.Response(
                status=302,
                headers={"Location": f"http://other.example:{request.url.port}/target"},
            )
        return web.json_response({"ok": True})

    app = web.Application()
    app.router.add_get("/{path:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]

    async def resolve(self, host, port=0, family=0):
        return [
            dict(
                hostname=host,
                host="127.0.0.1",
                port=port,
                family=socket.AF_INET,
                proto=0,
                flags=0,
            )
        ]

    monkeypatch.setattr(aiohttp.resolver.ThreadedResolver, "resolve", resolve)
    permission = auth("app.example", "other.example", "127.0.0.1")
    permission.allowed_ports = (port,)
    policy = HttpPolicy(permission.scope)
    policy.authorization = permission
    try:
        async with aiohttp.ClientSession(
            headers={"X-API-Key": "synthetic"},
            cookie_jar=aiohttp.CookieJar(unsafe=True),
        ) as session:
            for _ in range(2):
                assert (
                    await policy.get(session, f"http://app.example:{port}/ok")
                ).status == 200
            assert transports[0] is transports[1]
            assert (
                await policy.get(
                    session,
                    f"http://app.example:{port}/redirect",
                    allow_redirects=True,
                    headers={
                        "Authorization": "Bearer synthetic",
                        "Cookie": "session=synthetic",
                    },
                )
            ).status == 200
            assert not any(
                k.lower() in {"authorization", "cookie", "x-api-key"}
                for k in observed[-1]
            )
    finally:
        await runner.cleanup()


@pytest.mark.parametrize("value", [False, "true", 0, None])
def test_global_safety_cannot_be_disabled(load_config, value):
    from qbh.config import ConfigError

    with pytest.raises(ConfigError):
        load_config(
            [{"domain": "example.test", "in_scope": ["example.test"]}],
            extra={
                "global_safety_policy": {
                    "prohibited_operations": {"persistence": value}
                }
            },
        )


async def test_real_private_ipv6_http():
    import aiohttp
    from aiohttp import web
    from qbh.http_policy import HttpPolicy

    async def endpoint(request):
        return web.Response(text="authorized ipv6")

    app = web.Application()
    app.router.add_get("/", endpoint)
    runner = web.AppRunner(app)
    await runner.setup()
    try:
        site = web.TCPSite(runner, "::1", 0)
        await site.start()
        permission = auth("::1")
        policy = HttpPolicy(permission.scope)
        policy.authorization = permission
        async with aiohttp.ClientSession() as session:
            response = await policy.get(
                session, f"http://[::1]:{runner.addresses[0][1]}/"
            )
            assert response.text == "authorized ipv6"
    finally:
        await runner.cleanup()


def test_mapped_ipv6_deny_wins_over_ipv4_grant():
    permission = Authorization(scope=ScopeEnforcer.from_entries([{
        'in_scope':['10.0.0.0/8'], 'out_of_scope':['::ffff:10.1.2.3']}]))
    with pytest.raises(RuleForbidden):
        validate_ip(permission, '::ffff:10.1.2.3')


def test_enterprise_configuration_uses_existing_scope(load_config):
    from qbh.authorization import from_config
    cfg = load_config([{'domain':'company.example','in_scope':[
        'company.example','*.company.example','10.10.1.20','10.20.0.0/16','fd00::/64'],
        'out_of_scope':['10.20.0.1']}],extra={'network_allowed_ports':[443,8443]})
    permission=from_config(cfg)
    for target in ['company.example','api.company.example','10.10.1.20','10.20.5.6','fd00::1']:
        assert permission.is_authorized(target)
    for target in ['other.example','10.20.0.1','10.21.5.6','fd01::1']:
        assert not permission.is_authorized(target)


def test_unrecognized_infrastructure_permissions_are_not_ignored(load_config):
    from qbh.config import ConfigError
    with pytest.raises(ConfigError,match='infrastructure'):
        load_config([{'domain':'company.example','in_scope':['company.example'],
                      'infrastructure':{'allow_private_ips':True}}])

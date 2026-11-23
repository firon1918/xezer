"""Regression cases for the security-hardening audit; no public targets."""
from types import SimpleNamespace

import pytest

from qbh.authorization import Authorization, RuleForbidden
from qbh.scope import ScopeEnforcer, normalize_host, ScopeError
from qbh.context import Context
from qbh.egress import EgressController


def authorization():
    return Authorization(scope=ScopeEnforcer.from_entries([{'in_scope': ['example.test']}]),
                         request_restrictions=[{'hosts': ['EXAMPLE.TEST.'], 'paths': ['/restricted'],
                                                'methods': ['*'], 'forbidden': ['*']}])


@pytest.mark.parametrize('path', ['/restricted', '/%2572estricted', '/x/../restricted',
                                  '//restricted', '/x/%252e%252e/restricted', '/x\\../restricted'])
def test_canonical_denied_path(path):
    with pytest.raises(RuleForbidden):
        authorization().authorize_request('GET', 'https://example.test' + path)


def test_nonmatching_path_allowed():
    authorization().authorize_request('GET', 'https://example.test/restricted-other')


@pytest.mark.parametrize('url', ['ftp://example.test/a', 'https://u:p@example.test/a',
                                 'https://example.test:99999/a', 'https://example.test/\na'])
def test_ambiguous_url_rejected(url):
    with pytest.raises(ScopeError):
        authorization().authorize_request('GET', url)


def test_ipv6_canonical():
    assert normalize_host('[0:0:0:0:0:0:0:1]') == '::1'
    with pytest.raises(ScopeError):
        normalize_host('fe80::1%eth0')


def test_cli_flags_reach_authorization():
    ctx = Context(cfg=None, args=SimpleNamespace(dry_run=True, active_fuzz=False),
                  guardian=SimpleNamespace(policy=None), authorization=authorization())
    assert not ctx._auth().allows('active_fuzz')
    with pytest.raises(RuleForbidden, match='dry_run'):
        ctx._auth().authorize_request('GET', 'https://example.test/')


async def test_dry_run_rejects_process_without_targets():
    auth = authorization()
    auth.dry_run = True
    controller = EgressController(auth)
    result, _ = await controller.prepare_process(['python', '-c', 'pass'], [])
    assert result is not None and result.blocked

async def test_dry_run_transport_never_called():
    from unittest.mock import Mock
    from qbh.http_policy import HttpPolicy
    auth = authorization()
    auth.dry_run = True
    policy = HttpPolicy(auth.scope)
    policy.authorization = auth
    session = Mock()
    with pytest.raises(RuleForbidden, match='dry_run'):
        await policy.request(session, 'POST', 'https://example.test/login', json={'x': 'y'})
    session.request.assert_not_called()


async def test_cancellation_rechecked_after_concurrency_wait():
    from unittest.mock import Mock
    from qbh.http_policy import HttpPolicy
    from qbh.authorization import ScanExpired
    auth = authorization()
    policy = HttpPolicy(auth.scope)
    policy.authorization = auth
    session = Mock()
    auth.cancel()
    with pytest.raises(ScanExpired):
        await policy._fetch_once(session, 'GET', 'https://example.test/', {}, {}, 'example.test')
    session.request.assert_not_called()


def test_existing_restriction_host_globs_still_apply():
    auth = authorization()
    auth.request_restrictions[0]['hosts'] = ['EXAMPLE.*']
    with pytest.raises(RuleForbidden, match='explicit_request_restriction'):
        auth.authorize_request('GET', 'https://example.test/restricted')

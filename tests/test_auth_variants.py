"""Session transport variants: TOTP MFA, token refresh, CSRF double-submit,
stale-session behavior. All traffic stays on loopback fixtures."""
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace

import pytest
import pytest_asyncio
from aiohttp import web

from qbh import db
from qbh.brain.auth_config import validate_contexts
from qbh.brain.auth_state import AuthStateMachine, totp
from tests.test_auth_state import auth_runtime, spec  # noqa: F401


# RFC 6238 appendix B vectors (8 digits, period 30).
RFC_VECTORS = [
    (59, 'SHA1', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '94287082'),
    (59, 'SHA256', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====', '46119246'),
    (59, 'SHA512', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=', '90693936'),
    (1111111109, 'SHA1', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '07081804'),
    (1111111109, 'SHA256', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====', '68084774'),
    (1111111111, 'SHA1', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '14050471'),
    (1234567890, 'SHA1', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '89005924'),
    (2000000000, 'SHA256', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====', '90698825'),
    (20000000000, 'SHA512', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=', '47863826'),
]


@pytest.mark.parametrize('when,algorithm,secret,expected', RFC_VECTORS)
def test_totp_matches_rfc6238_vectors(when, algorithm, secret, expected):
    assert totp(secret, digits=8, period=30, algorithm=algorithm, when=when) == expected


def test_totp_default_six_digits_and_window():
    secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
    code = totp(secret, when=59)
    assert len(code) == 6 and code == '287082'
    assert totp(secret, when=59 + 30) != code


@pytest_asyncio.fixture
async def mfa_app():
    """Login requires a valid TOTP; refresh rotates the access token."""
    secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
    state = {'logins': 0, 'refreshes': 0, 'access': 'access-1', 'refresh': 'refresh-1'}

    def valid_otp(code):
        import time
        now = time.time()
        return any(totp(secret, when=now + drift) == code for drift in (-30, 0, 30))

    async def login(request):
        state['logins'] += 1
        data = await request.json()
        if data.get('username') != 'alice' or data.get('password') != 'synthetic-a-password':
            return web.json_response({'error': 'bad credentials'}, status=401)
        if not valid_otp(data.get('otp', '')):
            return web.json_response({'error': 'bad otp'}, status=401)
        response = web.json_response({'user': {'id': 'alice'}, 'access_token': state['access'],
                                      'refresh_token': state['refresh']})
        response.set_cookie('session', 'alice-session', path='/')
        response.set_cookie('csrf', 'csrf-token-1', path='/')
        return response

    async def refresh(request):
        state['refreshes'] += 1
        data = await request.json()
        if data.get('refresh_token') != state['refresh']:
            return web.json_response({'error': 'invalid refresh token'}, status=401)
        state['access'] = 'access-2'
        state['refresh'] = 'refresh-2'
        response = web.json_response({'user': {'id': 'alice'}, 'access_token': state['access'],
                                      'refresh_token': state['refresh']})
        response.set_cookie('session', 'alice-session-2', path='/')
        response.set_cookie('csrf', 'csrf-token-2', path='/')
        return response

    async def identity(request):
        auth = request.headers.get('Authorization', '')
        cookie = request.cookies.get('session', '')
        if auth == 'Bearer ' + state['access'] or cookie in ('alice-session', 'alice-session-2'):
            return web.json_response({'user': {'id': 'alice'}})
        return web.json_response({'error': 'unauthorized'}, status=401)

    app = web.Application()
    app.router.add_post('/login', login)
    app.router.add_post('/refresh', refresh)
    app.router.add_get('/me', identity)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    try:
        yield SimpleNamespace(base=f'http://127.0.0.1:{runner.addresses[0][1]}', state=state, secret=secret)
    finally:
        await runner.cleanup()


def mfa_spec(base, secret_env='TARGET_TOTP_SECRET'):
    item = spec(base)
    item.update({'refresh_url': base + '/refresh', 'csrf_cookie': 'csrf', 'csrf_header': 'X-CSRF-Token',
                 'totp_secret_env': secret_env, 'session_ttl_seconds': 60})
    return item


async def test_totp_login_refresh_and_csrf(auth_runtime, mfa_app, monkeypatch):  # noqa: F811
    monkeypatch.setenv('TARGET_TOTP_SECRET', mfa_app.secret)
    state = AuthStateMachine(auth_runtime)
    context = state.register_context('user_a', 'user', mfa_spec(mfa_app.base))
    assert await state.authenticate(context)
    assert mfa_app.state['logins'] == 1
    assert state.subject(context) == 'alice' and context.identity_verified
    first_session = context.session_id

    headers = state.headers_for(context, mfa_app.base + '/me')
    assert headers['Authorization'] == 'Bearer access-1'
    assert headers['X-CSRF-Token'] == 'csrf-token-1'
    assert 'csrf=csrf-token-1' in headers['Cookie']

    # Expire the session; one bounded refresh rotates tokens without a new login.
    context.valid_until = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert not state.is_valid(context)
    assert await state.ensure_valid(context)
    assert mfa_app.state['refreshes'] == 1 and mfa_app.state['logins'] == 1
    assert state.is_valid(context) and state.subject(context) == 'alice'
    rotated = state.headers_for(context, mfa_app.base + '/me')
    assert rotated['Authorization'] == 'Bearer access-2'
    assert rotated['X-CSRF-Token'] == 'csrf-token-2'
    # Still valid: no additional refresh call.
    assert await state.ensure_valid(context)
    assert mfa_app.state['refreshes'] == 1
    # The refresh created a new session row and rotated the refresh token.
    assert context.session_id != first_session
    assert state._payload(context)['refresh_token'] == 'refresh-2'


async def test_failed_refresh_invalidates_and_is_bounded(auth_runtime, mfa_app, monkeypatch):  # noqa: F811
    monkeypatch.setenv('TARGET_TOTP_SECRET', mfa_app.secret)
    state = AuthStateMachine(auth_runtime)
    context = state.register_context('user_a', 'user', mfa_spec(mfa_app.base))
    assert await state.authenticate(context)
    mfa_app.state['refresh'] = 'rotated-out-of-band'
    context.valid_until = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert not await state.ensure_valid(context)
    assert context.status == 'invalid' and not state.is_valid(context)
    assert mfa_app.state['refreshes'] == 1
    # Bounded: a second ensure_valid does not retry the same expired session.
    assert not await state.ensure_valid(context)
    assert mfa_app.state['refreshes'] == 1
    with pytest.raises(ValueError):
        state.headers_for(context, mfa_app.base + '/me')
    dump = '\n'.join(db.get_db().iterdump())
    assert 'refresh-1' not in dump and 'access-1' not in dump


async def test_wrong_totp_is_rejected_without_session(auth_runtime, mfa_app, monkeypatch):  # noqa: F811
    monkeypatch.setenv('TARGET_TOTP_SECRET', 'JBSWY3DPEHPK3PXP')
    state = AuthStateMachine(auth_runtime)
    context = state.register_context('user_a', 'user', mfa_spec(mfa_app.base))
    assert not await state.authenticate(context)
    assert context.status == 'failed' and not context.session_id
    assert mfa_app.state['logins'] == 1


async def test_stale_cookie_and_missing_csrf_fail_closed(auth_runtime, mfa_app, monkeypatch):  # noqa: F811
    monkeypatch.setenv('TARGET_TOTP_SECRET', mfa_app.secret)
    state = AuthStateMachine(auth_runtime)
    context = state.register_context('user_a', 'user', mfa_spec(mfa_app.base))
    assert await state.authenticate(context)
    # Expire only the CSRF cookie inside the encrypted payload.
    payload = state._payload(context)
    for cookie in payload['cookies']:
        if cookie['name'] == 'csrf':
            cookie['expires_at'] = 1.0
    from qbh.ingest.har_importer import canonical
    encrypted = auth_runtime.vault.encrypt(canonical(payload))
    with db.get_db() as conn:
        conn.execute('UPDATE auth_sessions SET payload_enc=? WHERE id=?', (encrypted, context.session_id))
    with pytest.raises(ValueError, match='csrf_cookie_unavailable'):
        state.headers_for(context, mfa_app.base + '/me')
    # Invalidated contexts cannot export credentials at all.
    state.invalidate(context, 'expired')
    with pytest.raises(ValueError):
        state.headers_for(context, mfa_app.base + '/me')


async def test_initialize_refreshes_before_relogin(auth_runtime, mfa_app, monkeypatch):  # noqa: F811
    monkeypatch.setenv('TARGET_TOTP_SECRET', mfa_app.secret)
    auth_runtime.cfg.auth_contexts = [mfa_spec(mfa_app.base)]
    state = AuthStateMachine(auth_runtime)
    await state.initialize()
    assert mfa_app.state['logins'] == 1
    context = state.contexts['user_a']
    expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    context.valid_until = datetime.now(timezone.utc) - timedelta(seconds=1)
    with db.get_db() as conn:
        conn.execute('UPDATE auth_contexts SET valid_until=? WHERE scan_id=? AND name=?',
                     (expired, state.scan_id, 'user_a'))
    reloaded = AuthStateMachine(auth_runtime)
    await reloaded.initialize()
    assert mfa_app.state['refreshes'] == 1 and mfa_app.state['logins'] == 1
    assert reloaded.is_valid(reloaded.contexts['user_a'])


def test_variant_config_validation(mfa_app):
    base = mfa_app.base
    validate_contexts([mfa_spec(base)])
    with pytest.raises(ValueError, match='refresh_origin_must_match_login'):
        validate_contexts([{**mfa_spec(base), 'refresh_url': 'http://127.0.0.1:9/refresh'}])
    with pytest.raises(ValueError, match='csrf_cookie_and_header_required_together'):
        validate_contexts([{**spec(base), 'csrf_cookie': 'csrf'}])
    with pytest.raises(ValueError, match='invalid_credential_env_reference'):
        validate_contexts([{**spec(base), 'totp_secret_env': 'not-an-env-name'}])
    with pytest.raises(ValueError, match='unsupported_auth_context_fields'):
        validate_contexts([{**spec(base), 'totp_secret': 'JBSWY3DPEHPK3PXP'}])
    with pytest.raises(ValueError, match='exactly_one_totp_secret_reference_required'):
        validate_contexts([{**spec(base), 'totp_secret_env': 'A', 'totp_secret_vault_ref': 1}])
    with pytest.raises(ValueError, match='invalid_totp_digits'):
        validate_contexts([{**mfa_spec(base), 'totp_digits': 5}])
    with pytest.raises(ValueError, match='invalid_totp_period'):
        validate_contexts([{**mfa_spec(base), 'totp_period': 5}])
    with pytest.raises(ValueError, match='invalid_totp_algorithm'):
        validate_contexts([{**mfa_spec(base), 'totp_algorithm': 'MD5'}])
    with pytest.raises(ValueError, match='totp_options_require_secret_reference'):
        validate_contexts([{**spec(base), 'totp_digits': 8}])
    with pytest.raises(ValueError, match='refresh_options_require_refresh_url'):
        validate_contexts([{**spec(base), 'refresh_method': 'POST'}])

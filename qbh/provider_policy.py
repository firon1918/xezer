"""Read-only intelligence services, separate from assessment target grants.

Only the exact compiled-in query endpoints are allowed. Provider DNS results use
HttpPolicy's connector; private addresses are never inherited from target scope.
There are no ambient cookies, proxies, target credentials or target-scope edits.
"""
from __future__ import annotations

import copy
import json
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import aiohttp

from .authorization import Authorization, RuleForbidden
from .http_policy import HttpPolicy
from .scope import ScopeEnforcer

# An operation grant, not a domain-wide grant. POST here is an OSV read query.
PROVIDERS = {
    'crtsh': ('GET', 'https://crt.sh/'),
    'kev': ('GET', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
    'epss': ('GET', 'https://api.first.org/data/v1/epss'),
    'osv': ('POST', 'https://api.osv.dev/v1/query'),
    'github_advisory': ('GET', 'https://api.github.com/advisories'),
    'nvd': ('GET', 'https://services.nvd.nist.gov/rest/json/cves/2.0'),
}
CVE_PROVIDERS = ('kev', 'epss', 'osv', 'github_advisory', 'nvd')


def _endpoint(method, url):
    parsed = urlsplit(url)
    return (method.upper(), parsed.scheme.lower(), parsed.hostname,
            parsed.port or (443 if parsed.scheme == 'https' else 80), parsed.path or '/')


class ProviderAuthorization(Authorization):
    def __init__(self, parent, endpoints, audit):
        scope = ScopeEnforcer.from_entries([{'in_scope': [urlsplit(url).hostname
                                                        for _, url in endpoints]}])
        # A target deny is also a provider deny. Target allowlists are not copied.
        scope.deny = parent.scope.deny[:] if parent.scope else []
        super().__init__(scope=scope, allowed_ports=tuple({_endpoint(m, u)[3]
                                                        for m, u in endpoints}))
        self.parent, self.audit = parent, audit
        self.endpoints = frozenset(_endpoint(m, u) for m, u in endpoints)

    def ensure_active(self):
        self.parent.ensure_active()
        if self.parent.dry_run:
            raise RuleForbidden('dry_run_network_forbidden')
        if self.parent.scope is None or self.parent.scope.is_empty:
            raise RuleForbidden('provider_requires_assessment_scope')
        self.parent.require_operation()

    def require(self, action):
        # These exact endpoints perform read queries, even OSV's POST. No target
        # state-changing permission is added. All engine/global rules still apply.
        if action != 'state_changing':
            self.parent.require(action)

    def authorize_request(self, method, url, action=None, *, destructive=False):
        try:
            self.ensure_active()
            if _endpoint(method, url) not in self.endpoints:
                raise RuleForbidden('provider_endpoint_not_authorized')
            self.request_restrictions = self.parent.request_restrictions
            result = super().authorize_request(method, url, action or self.parent.current_operation(),
                                               destructive=destructive)
        except (ValueError, RuleForbidden) as exc:
            self.audit.append({'event': 'provider_denied', 'reason': type(exc).__name__})
            raise
        self.audit.append({'event': 'provider_authorized', 'method': method.upper(),
                           'origin_path': url.split('?', 1)[0]})
        return result


class _Response:
    def __init__(self, response):
        self.status = response.status
        self.response = response

    async def json(self, **kwargs):
        if self.response.truncated:
            raise ValueError('provider_response_truncated')
        # Bound nesting before constructing Python containers. Braces inside
        # JSON strings (including escaped quotes) do not consume depth.
        depth, quoted, escaped = 0, False, False
        for char in self.response.text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in '{[':
                depth += 1
                if depth > 64:
                    raise ValueError('provider_json_nesting_exceeded')
            elif char in '}]':
                depth -= 1
        try:
            return json.loads(self.response.text)
        except RecursionError as exc:
            raise ValueError('provider_json_nesting_exceeded') from exc


class ProviderSession:
    """Small session-compatible facade for existing intelligence parsers.

    Sessions are per invocation; rate/concurrency state belongs to the scan.
    Callers cannot supply an alternate transport or dynamically grant an origin.
    """
    def __init__(self, ctx, providers):
        self.ctx = ctx
        self.auth = ProviderAuthorization(ctx._auth(), [PROVIDERS[p] for p in providers],
                                          ctx.egress_audit)
        base = getattr(ctx.guardian, 'policy', None)
        self.policy = copy.copy(base) if base is not None else HttpPolicy(self.auth.scope)
        self.policy.scope = self.auth.scope
        self.policy.authorization = self.auth
        self.policy.transport = None
        self.policy.identity_provider = None
        self.policy.cache = None
        self.session = None

    async def __aenter__(self):
        self.auth.ensure_active()
        self.session = aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar(), trust_env=False)
        return self

    async def __aexit__(self, *args):
        if self.session is not None:
            await self.session.close()

    @asynccontextmanager
    async def request(self, method, url, **kwargs):
        if self.session is None:
            raise RuntimeError('provider_session_not_open')
        # Existing helpers provide ClientTimeout; HttpPolicy owns the actual
        # configured timeouts, retries and shared request budgets.
        kwargs.pop('timeout', None)
        response = await self.policy.request(self.session, method, url,
                                             allow_redirects=True, **kwargs)
        yield _Response(response)

    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        return self.request('POST', url, **kwargs)

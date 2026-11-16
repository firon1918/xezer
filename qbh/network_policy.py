"""Connection-time policy: validated DNS answers feed the actual connector."""
import ipaddress
import socket
from urllib.parse import urlsplit

import aiohttp

from .authorization import RuleForbidden
from .scope import normalize_host


def validate_ip(auth, value):
    ip = ipaddress.ip_address(value)
    effective = getattr(ip, 'ipv4_mapped', None) or ip
    # Scope's explicit IP/CIDR rules are the laboratory opt-in. A hostname grant
    # alone never grants access to a private address returned by DNS.
    if not effective.is_global and not (auth.scope.is_authorized(str(effective)) or auth.scope.is_authorized(str(ip))):
        raise RuleForbidden('non_public_address_not_explicitly_authorized')
    if any(rule.matches(str(effective), effective) for rule in auth.scope.deny):
        raise RuleForbidden('resolved_address_denied')
    return str(ip)


def validate_options(auth, url, headers, options):
    from yarl import URL
    parts = urlsplit(url)
    host = normalize_host(parts.hostname)
    port = parts.port or (443 if parts.scheme == 'https' else 80)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if port not in auth.allowed_ports and not (ip and auth.scope.is_authorized(host)):
        raise RuleForbidden('port_not_authorized')
    for key, value in (headers or {}).items():
        key = key.lower()
        if key in {'x-http-method-override', 'x-method-override', 'x-http-method',
                   'x-original-url', 'x-rewrite-url'}:
            raise RuleForbidden('request_override_header_forbidden')
        if key == 'host' and value.lower().rstrip('.') != URL(url).authority.lower().rstrip('.'):
            raise RuleForbidden('host_header_mismatch')
    if options.get('proxy') or options.get('proxy_auth'):
        raise RuleForbidden('unmediated_proxy_forbidden')
    if options.get('ssl') is False or options.get('server_hostname'):
        raise RuleForbidden('tls_policy_override_forbidden')
    if ip:
        validate_ip(auth, host)


class PolicyResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, authorization, delegate=None):
        self.auth = authorization
        self.delegate = delegate or aiohttp.resolver.ThreadedResolver()

    async def resolve(self, host, port=0, family=socket.AF_UNSPEC):
        self.auth.ensure_active()
        self.auth.authorize_host(host)
        records = await self.delegate.resolve(host, port, family)
        if not records:
            raise RuleForbidden('empty_dns_answer')
        for record in records:
            validate_ip(self.auth, record['host'])
        # No second DNS lookup: these records are consumed by TCPConnector.
        self.auth.ensure_active()
        return records

    async def close(self):
        await self.delegate.close()

"""Explicit CONNECT/SOCKS5 egress: proxies receive numeric, validated targets.

The configured proxy is trusted transport infrastructure, never a scope grant.
No environment proxy discovery and no remote target DNS are used.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import ssl
from urllib.parse import unquote, urlsplit

import aiohttp

from .authorization import RuleForbidden
from .network_policy import PolicyResolver, validate_ip


class PinnedProxyConnector(aiohttp.TCPConnector):
    def __init__(self, authorization, proxy, proxy_auth=None, **kwargs):
        self.authorization = authorization
        self.proxy = urlsplit(str(proxy))
        p = self.proxy
        if p.scheme not in {"http", "https", "socks5"} or not p.hostname:
            raise RuleForbidden("proxy_requires_http_connect_or_socks5")
        if p.path not in {"", "/"} or p.query or p.fragment:
            raise RuleForbidden("invalid_proxy_endpoint")
        self.proxy_port = p.port or {"http": 80, "https": 443, "socks5": 1080}[p.scheme]
        self.credentials = proxy_auth
        if p.username is not None:
            if proxy_auth is not None:
                raise RuleForbidden("conflicting_proxy_credentials")
            self.credentials = aiohttp.BasicAuth(
                unquote(p.username), unquote(p.password or "")
            )
        self._tunnel_writers = set()
        super().__init__(
            resolver=PolicyResolver(authorization), use_dns_cache=False, **kwargs
        )
        self._resolver_owner = True

    async def _create_connection(self, req, traces, timeout):
        auth = self.authorization
        auth.authorize_request(req.method, str(req.url))
        records = await self._resolve_host(req.url.raw_host, req.port, traces=traces)
        last_error = None
        for record in records:
            ip = validate_ip(auth, record["host"])
            writer = None
            try:
                async with aiohttp.helpers.ceil_timeout(
                    timeout.connect or timeout.total or 30
                ):
                    # Proxy DNS is independent, explicitly configured infrastructure.
                    reader, writer = await asyncio.open_connection(
                        self.proxy.hostname,
                        self.proxy_port,
                        ssl=ssl.create_default_context()
                        if self.proxy.scheme == "https"
                        else None,
                        limit=16384,
                    )
                    if self.proxy.scheme == "socks5":
                        await self._socks(reader, writer, ip, req.port)
                    else:
                        await self._connect(reader, writer, ip, req.port)
                    auth.authorize_request(req.method, str(req.url))
                    validate_ip(auth, ip)
                    transport = writer.transport
                    transport.pause_reading()
                    if req.is_ssl():
                        transport, proto = await self._start_tls_connection(
                            transport, req=req, timeout=timeout
                        )
                    else:
                        proto = self._factory()
                        transport.set_protocol(proto)
                        proto.connection_made(transport)
                        transport.resume_reading()
                    # Keep StreamWriter alive after transferring protocol ownership.
                    self._tunnel_writers = {
                        w for w in self._tunnel_writers if not w.is_closing()
                    }
                    self._tunnel_writers.add(writer)
                    return proto
            except (OSError, aiohttp.ClientError) as exc:
                last_error = exc
                if writer:
                    writer.close()
            except BaseException:
                if writer:
                    writer.close()
                raise
        if isinstance(last_error, aiohttp.ClientError):
            raise last_error
        raise aiohttp.ClientConnectorError(
            req.connection_key, last_error or OSError("no proxy route")
        )

    async def _connect(self, reader, writer, ip, port):
        authority = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
        headers = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
        if self.credentials:
            token = base64.b64encode(
                f"{self.credentials.login}:{self.credentials.password}".encode()
            ).decode()
            headers += f"Proxy-Authorization: Basic {token}\r\n"
        writer.write((headers + "\r\n").encode("ascii"))
        await writer.drain()
        response = await reader.readuntil(b"\r\n\r\n")
        if response.split(b"\r\n", 1)[0].split()[1:2] != [b"200"]:
            raise OSError("proxy refused numeric CONNECT")
        if reader._buffer:
            raise OSError("unexpected bytes after proxy handshake")

    async def _socks(self, reader, writer, ip, port):
        writer.write(b"\x05\x01" + (b"\x02" if self.credentials else b"\x00"))
        await writer.drain()
        selected = await reader.readexactly(2)
        if selected != b"\x05" + (b"\x02" if self.credentials else b"\x00"):
            raise OSError("SOCKS authentication refused")
        if self.credentials:
            user, password = (
                self.credentials.login.encode(),
                self.credentials.password.encode(),
            )
            if not 1 <= len(user) <= 255 or not 1 <= len(password) <= 255:
                raise RuleForbidden("invalid_socks_credentials")
            writer.write(
                b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password
            )
            await writer.drain()
            if await reader.readexactly(2) != b"\x01\x00":
                raise OSError("SOCKS authentication refused")
        address = ipaddress.ip_address(ip)
        writer.write(
            b"\x05\x01\x00"
            + (b"\x01" if address.version == 4 else b"\x04")
            + address.packed
            + port.to_bytes(2, "big")
        )
        await writer.drain()
        reply = await reader.readexactly(4)
        if reply[:3] != b"\x05\x00\x00" or reply[3] not in {1, 4}:
            raise OSError("SOCKS numeric connection refused")
        await reader.readexactly((4 if reply[3] == 1 else 16) + 2)

    async def close(self, **kwargs):
        for writer in self._tunnel_writers:
            writer.close()
        self._tunnel_writers.clear()
        await super().close(**kwargs)

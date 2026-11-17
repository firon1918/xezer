"""Mandatory HTTP mediation for isolated CLI tools.

Only a Unix socket to this broker crosses the child's network boundary. HTTPS
is terminated with an ephemeral CA; every decrypted request is independently
checked by HttpPolicy. CONNECT is never a general TCP tunnel.
"""

from __future__ import annotations

import asyncio
import contextvars
import datetime
import ipaddress
from pathlib import Path
import shutil
import ssl
import tempfile
from urllib.parse import urlsplit

import aiohttp

from .adapters.base import ProcResult
from .authorization import RuleForbidden
from .http_policy import HttpPolicy
from .network_policy import validate_options

# Reviewed HTTP-only entry points. Raw TCP/DNS/headless paths need other adapters.
PROXY_FLAGS = {
    "katana": ["-proxy", "{XEzer_PROXY}", "-duc"],
    "httpx": ["-http-proxy", "{XEzer_PROXY}", "-duc"],
    "curl": ["--proxy", "{XEzer_PROXY}", "--noproxy", ""],
    "ffuf": ["-x", "{XEzer_PROXY}"],
    "nuclei": [
        "-proxy",
        "{XEzer_PROXY}",
        "-disable-update-check",
        "-no-interactsh",
    ],
    "sqlmap": ["--proxy={XEzer_PROXY}", "--batch", "--disable-coloring"],
    "dalfox": ["--proxy", "{XEzer_PROXY}"],
    "feroxbuster": ["--proxy", "{XEzer_PROXY}"],
}
_raw = contextvars.ContextVar("broker_raw", default=b"")
_response_headers = contextvars.ContextVar("broker_headers", default=())


class BrokerPolicy(HttpPolicy):
    async def _read_body(self, response):
        raw = await response.content.read(self.max_body + 1)
        _raw.set(raw[: self.max_body])
        _response_headers.set(tuple(response.raw_headers))
        return raw[: self.max_body].decode("utf-8", errors="replace"), len(
            raw
        ) > self.max_body


def broker_policy(auth, policy=None):
    result = BrokerPolicy(auth.scope, rate=5, max_concurrency=4, max_retries=0)
    if policy is not None:
        for name in (
            "rate",
            "max_concurrency",
            "per_host_concurrency",
            "connect_timeout",
            "total_timeout",
            "max_body",
            "_sem",
            "_host_sems",
            "_state",
            "_host_rate",
        ):
            setattr(result, name, getattr(policy, name))
    result.authorization = auth
    return result


class RequestBroker:
    def __init__(self, auth, directory, audit, policy=None):
        # Imports are optional: callers fail closed when mediation extras are absent.
        import h11
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        self.h11, self.x509 = h11, x509
        self.hashes, self.serialization, self.rsa = hashes, serialization, rsa
        self.auth, self.directory, self.audit = auth, Path(directory), audit
        self.policy = broker_policy(auth, policy)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "XEzer ephemeral mediation")]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        self.ca = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.key, hashes.SHA256())
        )
        (self.directory / "ca.pem").write_bytes(
            self.ca.public_bytes(serialization.Encoding.PEM)
        )
        self.tasks = set()
        self.ssl_contexts = {}
        self.slots = asyncio.Semaphore(8)
        self.requests = 0

    async def __aenter__(self):
        self.auth.ensure_active()
        if self.auth.dry_run:
            raise RuleForbidden("dry_run_process_forbidden")
        self.session = aiohttp.ClientSession(
            cookie_jar=aiohttp.DummyCookieJar(), trust_env=False
        )
        self.server = await asyncio.start_unix_server(
            self.accept, str(self.directory / "socket"), limit=65536
        )
        return self

    async def __aexit__(self, *exc):
        self.server.close()
        await self.server.wait_closed()
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.session.close()

    def tls_context(self, hostname):
        if hostname in self.ssl_contexts:
            return self.ssl_contexts[hostname]
        if len(self.ssl_contexts) >= 128:
            raise RuleForbidden("broker_certificate_limit")
        x509 = self.x509
        try:
            san = x509.IPAddress(ipaddress.ip_address(hostname))
        except ValueError:
            san = x509.DNSName(hostname)
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, hostname)])
            )
            .issuer_name(self.ca.subject)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.key.public_key()
                ),
                critical=False,
            )
            .sign(self.key, self.hashes.SHA256())
        )
        # Private key stays outside the child's bind mounts.
        keypath, certpath = self.directory / "private.key", self.directory / "leaf.pem"
        keypath.write_bytes(
            self.key.private_bytes(
                self.serialization.Encoding.PEM,
                self.serialization.PrivateFormat.PKCS8,
                self.serialization.NoEncryption(),
            )
        )
        keypath.chmod(0o600)
        certpath.write_bytes(cert.public_bytes(self.serialization.Encoding.PEM))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.set_alpn_protocols(["http/1.1"])
        ctx.load_cert_chain(certpath, keypath)
        self.ssl_contexts[hostname] = ctx
        return ctx

    def accept(self, reader, writer):
        if len(self.tasks) >= 32:
            writer.close()
            return
        task = asyncio.create_task(self.serve(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def serve(self, reader, writer):
        try:
            async with self.slots:
                await asyncio.wait_for(self.exchange(reader, writer), 60)
        except (Exception, asyncio.CancelledError):
            # No exception strings: they may contain target credentials.
            self.audit.append(
                {"event": "mediation_blocked", "reason": "invalid_or_denied_request"}
            )
            # A broker denial/transport failure is not an HTTP response from
            # the target. Close the exchange so scanners cannot turn synthetic
            # 403/502 responses into findings or suppress HTTP fallback.
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass

    async def exchange(self, reader, writer, origin=None):
        h11 = self.h11
        conn = h11.Connection(h11.SERVER, max_incomplete_event_size=32768)
        request = None
        body = bytearray()
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                data = await reader.read(65536)
                if not data:
                    return
                conn.receive_data(data)
            elif isinstance(event, h11.Request):
                request = event
                if request.method == b"CONNECT":
                    if origin is not None:
                        raise RuleForbidden("nested_connect")
                    authority = request.target.decode("ascii")
                    origin = "https://" + authority
                    self.auth.authorize_url(origin)
                    validate_options(self.auth, origin, {}, {})
                    if conn.trailing_data[0] or reader._buffer:
                        raise RuleForbidden("pipelined_connect")
                    writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    await writer.drain()
                    # Python 3.10 compatible TLS upgrade, with broker as TLS server.
                    transport = await asyncio.get_running_loop().start_tls(
                        writer.transport,
                        writer._protocol,
                        self.tls_context(urlsplit(origin).hostname),
                        server_side=True,
                        ssl_handshake_timeout=10,
                    )
                    writer._transport = transport
                    return await self.exchange(reader, writer, origin)
                if conn.they_are_waiting_for_100_continue:
                    writer.write(
                        conn.send(
                            h11.InformationalResponse(status_code=100, headers=[])
                        )
                    )
                    await writer.drain()
            elif isinstance(event, h11.Data):
                body.extend(event.data)
                if len(body) > 2_000_000:
                    raise RuleForbidden("broker_body_limit")
            elif isinstance(event, h11.EndOfMessage):
                if request is None:
                    raise RuleForbidden("missing_request")
                target = request.target.decode("ascii")
                url = (
                    origin + target
                    if origin and target.startswith("/") and not target.startswith("//")
                    else target
                )
                if origin and (urlsplit(url).scheme, urlsplit(url).netloc) != (
                    urlsplit(origin).scheme,
                    urlsplit(origin).netloc,
                ):
                    raise RuleForbidden("connect_authority_mismatch")
                # Refuse ambiguous duplicates before converting to a mapping.
                headers = {}
                for key, value in request.headers:
                    name = key.decode("ascii").lower()
                    if name in headers:
                        raise RuleForbidden("duplicate_request_header")
                    headers[name] = value.decode("latin1")
                if "upgrade" in headers:
                    raise RuleForbidden("unsupported_protocol_transition")
                for token in headers.get("connection", "").split(","):
                    if token.strip().lower() not in {"", "keep-alive", "close"}:
                        raise RuleForbidden("unsupported_connection_header")
                for name in (
                    "connection",
                    "proxy-authorization",
                    "proxy-connection",
                    "transfer-encoding",
                    "content-length",
                    "expect",
                    "upgrade",
                ):
                    headers.pop(name, None)
                self.requests += 1
                if self.requests > 1000:
                    raise RuleForbidden("broker_request_budget")
                _raw.set(b"")
                response = await self.policy.request(
                    self.session,
                    request.method.decode("ascii"),
                    url,
                    headers=headers,
                    data=bytes(body),
                    allow_redirects=False,
                    retries=0,
                )
                payload = _raw.get()
                self.audit.append(
                    {
                        "event": "mediation_response",
                        "method": request.method.decode("ascii"),
                        "status": response.status,
                        "truncated": response.truncated,
                    }
                )
                # Target cookies remain client-owned. Broker never shares session state.
                outgoing = [
                    (k, v)
                    for k, v in _response_headers.get()
                    if k.lower()
                    not in {
                        b"content-length",
                        b"transfer-encoding",
                        b"content-encoding",
                        b"connection",
                        b"keep-alive",
                        b"upgrade",
                    }
                ]
                length = (
                    response.headers.get("Content-Length", "0")
                    if request.method == b"HEAD"
                    else str(len(payload))
                )
                outgoing.extend(
                    [(b"content-length", length.encode()), (b"connection", b"close")]
                )
                writer.write(
                    conn.send(
                        h11.Response(status_code=response.status, headers=outgoing)
                    )
                )
                if request.method != b"HEAD":
                    writer.write(conn.send(h11.Data(data=payload)))
                writer.write(conn.send(h11.EndOfMessage()))
                await writer.drain()
                return
            elif isinstance(event, h11.ConnectionClosed):
                return


def sandbox_command(command, directory, outputs=None, *, offline=False, dns=False):
    """Fresh filesystem, PID/IPC/user/network namespaces; no host sockets/home."""
    executable = shutil.which(command[0])
    if executable is None:
        raise FileNotFoundError(command[0])
    root = Path(directory)
    args = [
        "bwrap",
        "--unshare-all",
        "--uid",
        "0",
        "--gid",
        "0",
        "--cap-add",
        "CAP_NET_ADMIN",
        "--cap-add",
        "CAP_SETPCAP",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/tmp/home",
        "--dir",
        "/run",
        "--dir",
        "/etc",
        "--ro-bind",
        "/etc/ssl",
        "/etc/ssl",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/tmp/home",
        "--setenv",
        "LANG",
        "C.UTF-8",
    ]
    if not offline:
        args += [
            "--dir",
            "/broker",
            "--ro-bind",
            str(root / "socket"),
            "/broker/socket",
            *([] if dns else ["--ro-bind", str(root / "ca.pem"), "/broker/ca.pem"]),
            "--ro-bind",
            str(Path(__file__).with_name("dns_child.py" if dns else "mediation_child.py")),
            "/runner.py",
        ]
    # Copy executable, never expose its entire installation/home directory.
    if not executable.startswith("/usr/"):
        args += ["--ro-bind", executable, "/tool"]
        executable = "/tool"
    # Explicit regular-file arguments only. Sockets, devices and symlink roots
    # cannot become ambient filesystem/network escape routes.
    rewritten = []
    outputs = outputs if outputs is not None else []
    output_root = root / "results"
    output_root.mkdir(exist_ok=True)
    args += ["--bind", str(output_root), "/results"]
    previous = ""
    for arg in command[1:]:
        if previous in {"-o", "--output"} and arg not in {"-", "/dev/stdout"}:
            destination = output_root / str(len(outputs))
            outputs.append((destination, Path(arg).absolute()))
            rewritten.append("/results/" + destination.name)
            previous = arg
            continue
        previous = arg
        p = Path(arg)
        if p.is_file() and not p.is_symlink():
            destination = f"/input/{len(rewritten)}"
            args += ["--ro-bind", str(p.resolve()), destination]
            rewritten.append(destination)
        else:
            rewritten.append(arg)
    if offline:
        return args + ["--chdir", "/tmp", "--", executable, *rewritten]
    return args + [
        "--chdir",
        "/tmp",
        "/usr/bin/python3",
        "/runner.py",
        executable,
        *rewritten,
    ]


async def run_mediated(
    controller, command, *, stdin=None, timeout=600, cancel_event=None
):
    from .adapters.base import run_process, set_process_guard, reset_process_guard

    controller.auth.require_command(command)
    name = Path(command[0]).name
    if name not in PROXY_FLAGS:
        return ProcResult(
            -1,
            stderr=b"egress: no reviewed mandatory mediation adapter for this tool",
            blocked=True,
        )
    if shutil.which("bwrap") is None:
        return ProcResult(
            -1,
            stderr=b"egress: mandatory bubblewrap isolation unavailable",
            blocked=True,
        )
    try:
        with tempfile.TemporaryDirectory(prefix="xezer-broker-") as directory:
            async with RequestBroker(
                controller.auth,
                directory,
                controller.audit,
                policy=controller.mediation_policy,
            ) as broker:
                outputs = []
                args = sandbox_command(
                    [*command, *PROXY_FLAGS[name]], directory, outputs
                )
                token = set_process_guard(None)
                try:
                    result = await run_process(
                        args,
                        stdin=stdin,
                        timeout=timeout,
                        cancel_event=cancel_event,
                        env={},
                    )
                finally:
                    reset_process_guard(token)
                for staged, destination in outputs:
                    if (
                        staged.is_file()
                        and not staged.is_symlink()
                        and staged.stat().st_size <= 32_000_000
                    ):
                        if destination.is_symlink():
                            raise RuleForbidden("unsafe_output_destination")
                        destination.write_bytes(staged.read_bytes())
                controller.audit.append(
                    {
                        "event": "mediated_process",
                        "tool": name,
                        "requests": broker.requests,
                        "returncode": result.returncode,
                    }
                )
                return result
    except (ImportError, FileNotFoundError, OSError):
        return ProcResult(
            -1,
            stderr=b"egress: mandatory mediation dependencies or isolation unavailable",
            blocked=True,
        )

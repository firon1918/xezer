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

# Reviewed HTTP entry points. Tools with an explicit proxy flag get it; the rest
# rely on the namespace's transparent TCP interception + proxy environment, so
# proxy-unaware clients are still mediated per request. CONNECT is never a
# general TCP tunnel and raw non-HTTP protocols fail closed at the relay.
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
    "gau": ["--proxy", "{XEzer_PROXY}"],
    "x8": ["-x", "{XEzer_PROXY}"],
    "gowitness": ["-p", "{XEzer_PROXY}"],
    "arjun": [],
    "schemathesis": [],
    "ghauri": [],
    "sstimap": [],
    "git-dumper": [],
    "kr": [],
    "waymore": [],
    "jwt_tool": [],
    "subfinder": [],
    "amass": [],
    "bbot": [],
}
# Mixed-protocol scanners need both the DNS bridge and the HTTP relay.
DNS_HTTP_TOOLS = {"subfinder", "amass", "bbot"}
# These scanners query read-only intelligence providers in addition to targets;
# the broker runs a second, separately-scoped provider realm for them.
PROVIDER_TOOLS = {"gau", "waymore", "subfinder", "amass", "bbot"}
# Flags whose value is a directory of artifacts (staged and copied back whole).
DIR_OUTPUT_FLAGS = {"--screenshot-path"}
FILE_OUTPUT_FLAGS = {"-o", "--output", "--db-path"}
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
    def __init__(self, auth, directory, audit, policy=None, provider=None):
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
        # A second, separately-scoped read-only realm for intelligence providers.
        # It never inherits target private-IP grants, credentials or cookies.
        self.provider = provider
        self.provider_policy = broker_policy(provider, policy) if provider else None
        self.provider_session = None
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
        if self.provider is not None:
            self.provider.ensure_active()
            self.provider_session = aiohttp.ClientSession(
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
        if self.provider_session is not None:
            await self.provider_session.close()

    def _realm(self, url):
        """Pick the provider realm for compiled-in provider hosts, else target."""
        if self.provider is not None:
            host = urlsplit(url).hostname
            if host and self.provider.scope.is_authorized(host):
                return self.provider, self.provider_policy, self.provider_session
        return self.auth, self.policy, self.session

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
                    realm_auth, _, _ = self._realm(origin)
                    realm_auth.authorize_url(origin)
                    validate_options(realm_auth, origin, {}, {})
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
                _, realm_policy, realm_session = self._realm(url)
                _raw.set(b"")
                response = await realm_policy.request(
                    realm_session,
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


def collect_outputs(outputs):
    """Copy staged regular-file/directory artifacts back; never follow symlinks."""
    for staged, destination in outputs:
        if destination.is_symlink():
            raise RuleForbidden("unsafe_output_destination")
        if staged.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
            total = 0
            for item in sorted(staged.rglob("*")):
                if item.is_symlink() or not item.is_file():
                    continue
                total += item.stat().st_size
                if total > 64_000_000:
                    raise RuleForbidden("output_budget_exceeded")
                target = destination / item.relative_to(staged)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(item.read_bytes())
        elif (
            staged.is_file()
            and not staged.is_symlink()
            and staged.stat().st_size <= 32_000_000
        ):
            destination.write_bytes(staged.read_bytes())


def sandbox_command(command, directory, outputs=None, *, mode="http", mounts=()):
    """Fresh filesystem, PID/IPC/user/network namespaces; no host sockets/home.

    mode: http | dns | dns+http | offline. Non-offline modes mount the trusted
    scoped_child runner, which installs transparent TCP/DNS interception so even
    proxy-unaware scanners egress only through the broker bridges.

    mounts: iterable of (host_path, writable) bound at the same absolute path,
    for tools that read/write a dedicated scratch directory (e.g. git-dumper).
    Only the named directories cross the boundary — never the surrounding tree.
    """
    executable = shutil.which(command[0])
    if executable is None:
        raise FileNotFoundError(command[0])
    # Resolve symlinks so a real regular file is bound, never a link whose target
    # lives outside the namespace (e.g. a tool symlinked into a shared bin dir).
    executable = str(Path(executable).resolve())
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
        "CAP_NET_RAW",
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
        # Namespace-private procfs: glibc expands $ORIGIN RUNPATH via
        # /proc/self/exe, so native cores with bundled libs (semgrep) need it.
        "--proc",
        "/proc",
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
    # Distro alternatives symlinks (e.g. iptables -> xtables-nft-multi) live here;
    # without them the trusted runner cannot resolve the netfilter binaries.
    if Path("/etc/alternatives").is_dir():
        args += ["--ro-bind", "/etc/alternatives", "/etc/alternatives"]
    if mode != "offline":
        args += ["--dir", "/broker"]
        if mode in {"http", "dns+http"}:
            args += [
                "--ro-bind", str(root / "socket"), "/broker/socket",
                "--ro-bind", str(root / "ca.pem"), "/broker/ca.pem",
            ]
        if mode in {"dns", "dns+http"}:
            args += ["--ro-bind", str(root / "dns"), "/broker/dns"]
        args += [
            "--ro-bind",
            str(Path(__file__).with_name("scoped_child.py")),
            "/runner.py",
        ]
    # Python tools installed in a dedicated venv: mount the whole environment
    # read-only and launch through its interpreter (entry-point shebangs point at
    # host paths that do not exist inside the namespace). An optional source tree
    # <venv>/src/<tool> (git-cloned tools) is mounted alongside it.
    interpreter = None
    exe = Path(executable)
    venv_root = exe.parent.parent
    if (venv_root / "pyvenv.cfg").is_file():
        args += ["--ro-bind", str(venv_root), "/opt/toolenv"]
        # Console-script shebangs bake in the host venv path; tools that exec
        # sibling scripts (semgrep -> pysemgrep) need that path to resolve too.
        args += ["--ro-bind", str(venv_root), str(venv_root)]
        source = venv_root / "src" / exe.name
        if source.is_dir():
            args += ["--ro-bind", str(source), f"/opt/tool-src/{exe.name}"]
            args += ["--ro-bind", str(source), str(source)]
        args += ["--setenv", "PATH", "/opt/toolenv/bin:/usr/bin:/bin"]
        executable = f"/opt/toolenv/bin/{exe.name}"
        interpreter = "/opt/toolenv/bin/python3"
    elif not executable.startswith("/usr/"):
        # Copy the executable, never expose its whole installation/home directory.
        args += ["--ro-bind", executable, "/tool"]
        executable = "/tool"
    # Dedicated scratch directories a tool reads/writes (e.g. git-dumper output,
    # semgrep input tree). Only the named paths cross the boundary, bound at the
    # same absolute path so positional/flag arguments need no rewriting.
    for path, writable in mounts:
        resolved = Path(path).resolve()
        if not resolved.is_dir():
            raise FileNotFoundError(f"mount directory missing: {path}")
        args += ["--bind" if writable else "--ro-bind", str(resolved), str(resolved)]
    # Explicit regular-file arguments only. Sockets, devices and symlink roots
    # cannot become ambient filesystem/network escape routes.
    rewritten = []
    outputs = outputs if outputs is not None else []
    output_root = root / "results"
    output_root.mkdir(exist_ok=True)
    args += ["--bind", str(output_root), "/results"]
    previous = ""
    for arg in command[1:]:
        if previous in FILE_OUTPUT_FLAGS and arg not in {"-", "/dev/stdout"}:
            destination = output_root / str(len(outputs))
            outputs.append((destination, Path(arg).absolute()))
            rewritten.append("/results/" + destination.name)
            previous = arg
            continue
        if previous in DIR_OUTPUT_FLAGS:
            destination = output_root / f"dir{len(outputs)}"
            destination.mkdir(exist_ok=True)
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
    tool_argv = [executable, *rewritten]
    if interpreter is not None:
        tool_argv = [interpreter, *tool_argv]
    if mode == "offline":
        return args + ["--chdir", "/tmp", "--", *tool_argv]
    return args + [
        "--chdir", "/tmp", "--",
        "/usr/bin/python3", "/runner.py", mode, *tool_argv,
    ]


async def run_mediated(
    controller, command, *, stdin=None, timeout=600, cancel_event=None, mounts=()
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
    mode = "dns+http" if name in DNS_HTTP_TOOLS else "http"
    provider = None
    if name in PROVIDER_TOOLS:
        from .provider_policy import ProviderAuthorization, CLI_PROVIDER_HOSTS

        provider = ProviderAuthorization(
            controller.auth,
            [("GET", f"https://{host}/") for host in CLI_PROVIDER_HOSTS],
            controller.audit,
            exact_paths=False,
        )
    try:
        with tempfile.TemporaryDirectory(prefix="xezer-broker-") as directory:
            async with RequestBroker(
                controller.auth,
                directory,
                controller.audit,
                policy=controller.mediation_policy,
                provider=provider,
            ) as broker:
                dns_server = dns_broker = None
                if mode == "dns+http":
                    from .dns_mediation import DNSBroker

                    dns_broker = DNSBroker(controller)
                    dns_server = await asyncio.start_unix_server(
                        dns_broker.handle, str(Path(directory) / "dns")
                    )
                try:
                    outputs = []
                    args = sandbox_command(
                        [*command, *PROXY_FLAGS[name]], directory, outputs,
                        mode=mode, mounts=mounts,
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
                    collect_outputs(outputs)
                    # The trusted runner exits 125 with a marker when mandatory
                    # isolation could not be established: never a silent success.
                    if result.returncode == 125 and result.stderr.startswith(
                        b"xezer-isolation:"
                    ):
                        controller.audit.append(
                            {
                                "event": "mediation_blocked",
                                "reason": "isolation_setup_failed",
                                "tool": name,
                            }
                        )
                        return ProcResult(
                            result.returncode, result.stdout, result.stderr, blocked=True
                        )
                    controller.audit.append(
                        {
                            "event": "mediated_process",
                            "tool": name,
                            "requests": broker.requests,
                            "returncode": result.returncode,
                        }
                    )
                    return result
                finally:
                    if dns_server is not None:
                        dns_server.close()
                        await dns_server.wait_closed()
                        await dns_broker.close()
    except (ImportError, FileNotFoundError, OSError):
        return ProcResult(
            -1,
            stderr=b"egress: mandatory mediation dependencies or isolation unavailable",
            blocked=True,
        )
    except RuleForbidden:
        return ProcResult(
            -1, stderr=b"egress: mediation policy denied execution", blocked=True
        )

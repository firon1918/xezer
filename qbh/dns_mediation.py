"""Scoped DNS query broker; scanner has no network except private loopback."""
import asyncio
import copy
from contextlib import suppress
from pathlib import Path
import shutil
import tempfile

import dns.asyncresolver
import dns.exception
import dns.message
import dns.rcode
import dns.rdatatype

from .authorization import AuthorizationError, RuleForbidden
from .network_policy import validate_ip
from .http_policy import HttpPolicy
from .adapters.base import ProcResult, run_process, set_process_guard, reset_process_guard
from .mediation import sandbox_command


class DNSBroker:
    def __init__(self, controller):
        self.controller = controller
        self.auth = controller.auth
        if controller.mediation_policy is None:
            controller.mediation_policy = HttpPolicy(self.auth.scope)
        self.policy = controller.mediation_policy
        self.resolver = getattr(controller, 'dns_resolver', None)
        self.tasks = set()
        self.queries = 0

    async def query(self, wire):
        self.queries += 1
        message = dns.message.from_wire(wire)
        reply = dns.message.make_response(message)
        try:
            self.auth.ensure_active()
            if self.auth.dry_run:
                raise RuleForbidden('dry_run_dns_forbidden')
            self.auth.require('dnsx')
            self.auth.require_operation()
            if message.opcode() != 0 or len(message.question) != 1:
                raise RuleForbidden('dns_single_query_required')
            question = message.question[0]
            if question.rdclass != 1 or question.rdtype in {251, 252, 255}:
                raise RuleForbidden('dns_transfer_requires_stream_adapter')
            host = self.auth.authorize_host(str(question.name).rstrip('.'))
            if self.queries > 1000:
                raise RuleForbidden('dns_query_budget_exhausted')
            await self.policy.acquire(host)
            async with self.policy._slot(host):
                self.auth.ensure_active()
                if self.auth.dry_run:
                    raise RuleForbidden('dry_run_dns_forbidden')
                self.auth.authorize_host(host)
                if self.resolver is None:
                    self.resolver = dns.asyncresolver.Resolver()
                answer = await self.resolver.resolve(host, question.rdtype, lifetime=5,
                                                     raise_on_no_answer=False, search=False)
                self.auth.ensure_active()
                # Response addresses are discovery evidence, never scope grants.
                # Do not disclose an unauthorized private endpoint as usable.
                response = copy.deepcopy(answer.response)
                accepted, denied = 0, 0
                for section in (response.answer, response.additional):
                    for rrset in list(section):
                        if rrset.rdtype in {dns.rdatatype.A, dns.rdatatype.AAAA}:
                            for record in list(rrset):
                                try:
                                    validate_ip(self.auth, record.address)
                                    accepted += 1
                                except RuleForbidden:
                                    rrset.remove(record)
                                    denied += 1
                            if not rrset:
                                section.remove(rrset)
                if denied and not accepted:
                    raise RuleForbidden('dns_no_authorized_addresses')
                reply.answer = response.answer
                reply.authority = response.authority
                reply.additional = response.additional
            self.controller.audit.append({'event': 'dns_authorized', 'host': host,
                                          'type': dns.rdatatype.to_text(question.rdtype)})
        except AuthorizationError as exc:
            reply.set_rcode(dns.rcode.REFUSED)
            self.controller.audit.append({'event': 'dns_denied', 'reason': str(exc)})
        except dns.resolver.NXDOMAIN:
            reply.set_rcode(dns.rcode.NXDOMAIN)
        except (dns.exception.DNSException, OSError):
            reply.set_rcode(dns.rcode.SERVFAIL)
        return reply.to_wire(max_size=65535)

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        if len(self.tasks) >= 16 or self.queries >= 1000:
            writer.close()
            return
        self.tasks.add(task)
        try:
            async with asyncio.timeout(10):
                size = int.from_bytes(await reader.readexactly(2), 'big')
                if not 12 <= size <= 4096:
                    return
                result = await self.query(await reader.readexactly(size))
                writer.write(len(result).to_bytes(2, 'big') + result)
                await writer.drain()
        except (dns.exception.DNSException, ValueError, OSError, asyncio.IncompleteReadError,
                TimeoutError):
            pass
        finally:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()
            self.tasks.discard(task)

    async def close(self):
        for task in tuple(self.tasks):
            task.cancel()
        await asyncio.gather(*tuple(self.tasks), return_exceptions=True)


async def run_dns_tool(controller, command, *, stdin=None, timeout=600, cancel_event=None):
    controller.auth.require_command(command)
    if shutil.which('bwrap') is None:
        return ProcResult(-1, blocked=True, stderr=b'dns: mandatory isolation unavailable')
    broker = DNSBroker(controller)
    try:
        with tempfile.TemporaryDirectory(prefix='xezer-dns-') as directory:
            server = await asyncio.start_unix_server(broker.handle, str(Path(directory) / 'socket'))
            try:
                outputs = []
                args = sandbox_command([*command, '-r', '{XEzer_DNS}', '-duc'], directory,
                                       outputs, dns=True)
                token = set_process_guard(None)
                try:
                    result = await run_process(args, stdin=stdin, timeout=timeout,
                                               cancel_event=cancel_event, env={})
                finally:
                    reset_process_guard(token)
                for staged, destination in outputs:
                    if staged.is_file() and not staged.is_symlink() and staged.stat().st_size <= 32_000_000:
                        if destination.is_symlink():
                            raise RuleForbidden('unsafe_output_destination')
                        destination.write_bytes(staged.read_bytes())
                controller.audit.append({'event': 'dns_process', 'queries': broker.queries,
                                          'returncode': result.returncode})
                return result
            finally:
                server.close()
                await server.wait_closed()
                await broker.close()
    except FileNotFoundError:
        return ProcResult(-1, missing=True)
    except OSError:
        return ProcResult(-1, blocked=True, stderr=b'dns: isolation setup failed')

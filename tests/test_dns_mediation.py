import asyncio
import json
import os
from pathlib import Path

import dns.asyncresolver
import dns.message
import dns.rrset
import pytest

from qbh.authorization import Authorization
from qbh.scope import ScopeEnforcer
from qbh.egress import EgressController
from qbh.dns_mediation import DNSBroker


@pytest.fixture
async def resolver():
    seen = []
    class Server(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport
        def datagram_received(self, wire, address):
            message = dns.message.from_wire(wire)
            question = message.question[0]
            seen.append(str(question.name))
            response = dns.message.make_response(message)
            kind = dns.rdatatype.to_text(question.rdtype)
            if kind in {'A', 'AAAA'}:
                value = '127.0.0.1' if str(question.name).startswith('private.') else '1.1.1.1'
                if kind == 'AAAA':
                    value = '2606:4700:4700::1111'
                values = [value, '127.0.0.1'] if str(question.name).startswith('mixed.') and kind == 'A' else [value]
                response.answer.append(dns.rrset.from_text(question.name, 60, 'IN', kind, *values))
            elif kind == 'CNAME':
                response.answer.append(dns.rrset.from_text(question.name, 60, 'IN', kind, 'canonical.example.test.'))
            self.transport.sendto(response.to_wire(), address)
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(Server, local_addr=('127.0.0.1', 0))
    backend = dns.asyncresolver.Resolver(configure=False)
    backend.nameservers = ['127.0.0.1']
    backend.port = transport.get_extra_info('sockname')[1]
    try:
        yield backend, seen
    finally:
        transport.close()


def controller(backend):
    result = EgressController(Authorization(scope=ScopeEnforcer.from_entries([
        {'in_scope': ['*.example.test']}])) )
    result.dns_resolver = backend
    return result


async def test_broker_scope_private_and_dry_run(resolver):
    backend, seen = resolver
    egress = controller(backend)
    broker = DNSBroker(egress)
    assert DNSBroker(egress).policy._sem is broker.policy._sem
    async def query(name, kind='A'):
        return dns.message.from_wire(await broker.query(dns.message.make_query(name, kind).to_wire()))
    assert (await query('ok.example.test')).answer
    assert (await query('ok.example.test', 'AAAA')).answer
    assert (await query('private.example.test')).rcode() == dns.rcode.REFUSED
    assert (await query('outside.test')).rcode() == dns.rcode.REFUSED
    assert 'outside.test.' not in seen
    before = len(seen)
    egress.auth.dry_run = True
    assert (await query('ok.example.test')).rcode() == dns.rcode.REFUSED
    assert len(seen) == before


@pytest.mark.skipif(not os.environ.get('XEZER_CLI_TESTS'), reason='actual DNSx binary gate')
async def test_real_dnsx_scoped_queries(resolver):
    backend, seen = resolver
    egress = controller(backend)
    binary = str(Path(os.environ['XEZER_TOOL_BIN']) / 'dnsx')
    result = await egress.run([binary, '-silent', '-json', '-a', '-aaaa', '-resp', '-retry', '1'],
                              stdin=b'ok.example.test\noutside.test\nprivate.example.test\n', timeout=30)
    assert result.ok, result.stderr.decode()
    assert b'1.1.1.1' in result.stdout and b'2606:4700:4700::1111' in result.stdout, result.stdout
    records = [json.loads(line) for line in result.stdout.splitlines()]
    assert all('127.0.0.1' not in record.get('a', []) for record in records)
    assert 'outside.test.' not in seen
    assert any(event['event'] == 'dns_denied' for event in egress.audit)
    egress.auth.dry_run = True
    before = len(seen)
    denied = await egress.run([binary, '-l', 'ok.example.test'])
    assert denied.blocked and len(seen) == before


async def test_explicit_private_grant_and_cancellation(resolver):
    backend, seen = resolver
    egress = controller(backend)
    egress.auth.scope = ScopeEnforcer.from_entries([{'in_scope': ['*.example.test', '127.0.0.1']}])
    broker = DNSBroker(egress)
    request = dns.message.make_query('private.example.test', 'A').to_wire()
    reply = dns.message.from_wire(await broker.query(request))
    assert reply.answer[0][0].address == '127.0.0.1'
    before = len(seen)
    egress.auth.cancel()
    assert dns.message.from_wire(await broker.query(request)).rcode() == dns.rcode.REFUSED
    assert len(seen) == before


@pytest.mark.skipif(not os.environ.get('XEZER_CLI_TESTS'), reason='actual namespace gate')
async def test_direct_socket_cannot_reach_host_dns(resolver):
    from qbh.dns_mediation import run_dns_tool
    backend, seen = resolver
    egress = controller(backend)
    wire = dns.message.make_query('ok.example.test', 'A').to_wire()
    script = f'''import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(0.2)
s.sendto({wire!r},('127.0.0.1',{backend.port}))
try:
 s.recv(4096)
 raise SystemExit(9)
except TimeoutError:
 pass
'''
    result = await run_dns_tool(egress, ['/usr/bin/python3', '-c', script], timeout=10)
    assert result.ok, result.stderr.decode()
    assert seen == []


async def test_mixed_answers_keep_public_candidate_and_cname(resolver):
    backend, _ = resolver
    broker = DNSBroker(controller(backend))
    request = dns.message.make_query('mixed.example.test', 'A').to_wire()
    answer = dns.message.from_wire(await broker.query(request))
    assert [r.address for r in answer.answer[0]] == ['1.1.1.1']
    request = dns.message.make_query('alias.example.test', 'CNAME').to_wire()
    answer = dns.message.from_wire(await broker.query(request))
    assert str(answer.answer[0][0].target) == 'canonical.example.test.'


async def test_query_budget_prevents_further_resolution(resolver):
    backend, seen = resolver
    broker = DNSBroker(controller(backend))
    broker.queries = 1000
    request = dns.message.make_query('ok.example.test', 'A').to_wire()
    assert dns.message.from_wire(await broker.query(request)).rcode() == dns.rcode.REFUSED
    assert seen == []

import asyncio
import socket

import pytest

from qbh.authorization import Authorization, RuleForbidden, NotAuthorized
from qbh.scope import ScopeEnforcer
from qbh.socket_namespace import SocketNamespace


def auth(*ips):
    return Authorization(scope=ScopeEnforcer.from_entries([{"in_scope": list(ips)}]))


def test_socket_policy_rejects_unauthorized_before_setup():
    with pytest.raises(NotAuthorized):
        SocketNamespace(auth("192.0.2.1"), ["192.0.2.2"], ports=[80])
    policy = auth("192.0.2.1")
    policy.dry_run = True
    with pytest.raises(RuleForbidden, match="dry_run"):
        SocketNamespace(policy, ["192.0.2.1"], ports=[80])


@pytest.mark.skipif(
    not __import__("os").environ.get("XEZER_PRIVILEGED_TESTS"),
    reason="explicit privileged network fixture required",
)
async def test_actual_nmap_and_direct_socket_denial():
    # Target is synthetic and reachable only via the task's veth address.
    policy = auth("198.19.0.0/16")
    boundary = SocketNamespace(policy, ["198.19.0.1"], ports=[18080])
    boundary.destinations = (boundary.gateway,)  # same explicit CIDR grant
    with boundary:
        listener = socket.socket()
        listener.bind((boundary.gateway, 18080))
        listener.listen()
        listener.setblocking(False)
        denied = socket.socket()
        denied.bind((boundary.gateway, 18081))
        denied.listen()
        denied.setblocking(False)
        try:
            process = await asyncio.create_subprocess_exec(
                *boundary.wrap(
                    [
                        "/usr/bin/nmap",
                        "-n",
                        "-Pn",
                        "-sT",
                        "-p",
                        "18080,18081",
                        "--max-retries",
                        "0",
                        "--host-timeout",
                        "10s",
                        boundary.gateway,
                    ]
                ),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            output, error = await asyncio.wait_for(process.communicate(), 20)
            assert process.returncode == 0, error.decode()
            assert b"18080/tcp open" in output, output.decode()
            assert b"18081/tcp filtered" in output, output.decode()
            tamper = await asyncio.create_subprocess_exec(
                *boundary.wrap(["/usr/sbin/iptables", "-P", "OUTPUT", "ACCEPT"]),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(tamper.communicate(), 5)
            assert tamper.returncode != 0
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(
                    asyncio.get_running_loop().sock_accept(denied), 0.1
                )
        finally:
            listener.close()
            denied.close()

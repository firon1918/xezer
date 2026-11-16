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
@pytest.mark.parametrize("ipv6", [False, True])
async def test_actual_nmap_and_direct_socket_denial(ipv6):
    # Target is synthetic and reachable only via the task's veth address.
    policy = auth("198.19.0.0/16", "fd42::/16")
    boundary = SocketNamespace(policy, ["198.19.0.1"], ports=[18080])
    gateway = boundary.gateway6 if ipv6 else boundary.gateway
    boundary.destinations = (gateway,)  # same explicit CIDR grant
    boundary.port_ranges = {gateway: ["18080"]}
    with boundary:
        listener = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET)
        listener.bind((gateway, 18080))
        listener.listen()
        listener.setblocking(False)
        denied = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET)
        denied.bind((gateway, 18081))
        denied.listen()
        denied.setblocking(False)
        try:
            process = await asyncio.create_subprocess_exec(
                *boundary.wrap(
                    [
                        "/usr/bin/nmap",
                        *(["-6"] if ipv6 else []),
                        "-n",
                        "-Pn",
                        "-sT",
                        "-p",
                        "18080,18081",
                        "--max-retries",
                        "0",
                        "--host-timeout",
                        "10s",
                        gateway,
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
                *boundary.wrap(
                    [
                        "/usr/sbin/ip6tables" if ipv6 else "/usr/sbin/iptables",
                        "-P",
                        "OUTPUT",
                        "ACCEPT",
                    ]
                ),
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


@pytest.mark.skipif(
    not __import__("os").environ.get("XEZER_PRIVILEGED_TESTS"),
    reason="explicit privileged network fixture required",
)
@pytest.mark.parametrize("ipv6", [False, True])
@pytest.mark.parametrize("scanner", ["nmap", "naabu"])
async def test_central_guard_real_nmap_dns_pinning(ipv6, scanner):
    from qbh.egress import EgressController
    from qbh.adapters.base import run_process

    fixture = SocketNamespace(
        auth("198.19.0.0/16", "fd42::/16"), ["198.19.0.1"], ports=[18080]
    )
    gateway = fixture.gateway6 if ipv6 else fixture.gateway
    fixture.destinations = (gateway,)
    fixture.port_ranges = {gateway: ["18080"]}
    with fixture:
        listener = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET)
        listener.bind((gateway, 18080))
        listener.listen()
        blocked_listener = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET)
        blocked_listener.bind((gateway, 18081))
        blocked_listener.listen()
        blocked_listener.setblocking(False)
        policy = auth("scan.example.test", "198.19.0.0/16", "fd42::/16")
        policy.allowed_ports = (18080,)
        resolutions = []

        def resolver(host):
            resolutions.append(host)
            return (
                [gateway] if len(resolutions) == 1 else ["::1" if ipv6 else "127.0.0.1"]
            )

        controller = EgressController(policy, resolver=resolver)
        try:
            if scanner == "nmap":
                command = [
                    "/usr/bin/nmap",
                    *(["-6"] if ipv6 else []),
                    "-n",
                    "-Pn",
                    "-sT",
                    "-p",
                    "18080,18081",
                    "--max-retries",
                    "0",
                    "--host-timeout",
                    "10s",
                    "scan.example.test",
                ]
            else:
                import os

                command = [
                    os.environ.get("XEZER_NAABU_BIN", "naabu"),
                    "-host",
                    "scan.example.test",
                    "-p",
                    "18080,18081",
                    "-rate",
                    "10",
                    "-json",
                    "-silent",
                    "-no-color",
                    "-retries",
                    "1",
                    "-warm-up-time",
                    "0",
                    "-iv",
                    "6" if ipv6 else "4",
                ]
            with controller.activate():
                result = await run_process(
                    command, targets=["scan.example.test"], timeout=30
                )
            assert result.ok, result.stderr.decode()
            if scanner == "nmap":
                assert b"18080/tcp open" in result.stdout, result.stdout.decode()
                assert b"18081/tcp filtered" in result.stdout, result.stdout.decode()
            else:
                import json

                records = [
                    json.loads(line)
                    for line in result.stdout.splitlines()
                    if line.startswith(b"{")
                ]
                assert {r["port"] for r in records} == {18080}, (
                    result.stdout,
                    result.stderr,
                )
            assert resolutions == ["scan.example.test"]
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(
                    asyncio.get_running_loop().sock_accept(blocked_listener), 0.1
                )
            assert any(e["event"] == "socket_process" for e in controller.audit)
        finally:
            listener.close()
            blocked_listener.close()


async def test_guard_dry_run_and_denied_target_never_resolve(monkeypatch):
    from qbh.egress import EgressController
    from qbh.adapters.base import run_process

    policy = auth("allowed.example.test")

    def resolver(host):
        pytest.fail("unauthorized command attempted DNS")

    controller = EgressController(policy, resolver=resolver)
    policy.dry_run = True
    with controller.activate():
        result = await run_process(
            ["/usr/bin/nmap", "allowed.example.test"], targets=["allowed.example.test"]
        )
        assert result.blocked
    policy.dry_run = False
    with controller.activate():
        result = await run_process(
            ["/usr/bin/nmap", "denied.example.test"], targets=["denied.example.test"]
        )
        assert result.blocked

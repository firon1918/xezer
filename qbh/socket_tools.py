"""Central execution adapter for approved direct TCP port-discovery commands."""

from __future__ import annotations

import asyncio
import ipaddress
from pathlib import Path
import shutil
import subprocess
import time

from .adapters.base import (
    ProcResult,
    reset_process_guard,
    run_process,
    set_process_guard,
)
from .authorization import AuthorizationError, RuleForbidden
from .network_policy import validate_ip
from .socket_namespace import SocketNamespace


def command_targets(command):
    """Extract explicit targets without treating flags or file contents as grants."""
    name = Path(command[0]).name
    if name == "naabu":
        for option in ("-host", "-h"):
            if option in command:
                index = command.index(option)
                if index + 1 < len(command):
                    return command[index + 1].split(",")
    # Nmap's explicit target list is supplied by the caller. Arbitrary hidden
    # targets in its input files remain unreachable through the firewall.
    return []


async def run_socket_tool(
    controller, command, *, targets=(), stdin=None, timeout=600, cancel_event=None
):
    auth = controller.auth
    auth.require_command(command)  # before DNS, filesystem or process creation
    if auth.request_restrictions:
        return ProcResult(
            -1,
            stderr=b"egress: application restrictions require an application-aware socket gateway",
            blocked=True,
        )
    name = Path(command[0]).name
    if name == "nmap" and any(
        arg.startswith(("--script", "-sV", "-A", "-O")) for arg in command[1:]
    ):
        return ProcResult(
            -1,
            stderr=b"egress: NSE/service probes require classified application mediation",
            blocked=True,
        )
    identities = list(dict.fromkeys([*(targets or ()), *command_targets(command)]))
    if not identities:
        return ProcResult(
            -1, stderr=b"egress: direct socket targets must be explicit", blocked=True
        )
    for identity in identities:
        auth.authorize_host(identity)
    executable = shutil.which(command[0])
    if not executable:
        return ProcResult(-1, missing=True)
    bindings, port_map = {}, {}
    for identity in identities:
        host = auth.authorize_host(identity)
        try:
            ips = [str(ipaddress.ip_address(host))]
            literal = True
        except ValueError:
            ips = await controller._resolve(host)
            literal = False
        permitted = []
        for ip in ips:
            try:
                ip = validate_ip(auth, ip)
            except (ValueError, RuleForbidden):
                continue
            permitted.append(ip)
            bindings.setdefault(ip, []).append(host)
            port_map.setdefault(ip, set()).update(
                range(1, 65536) if literal else auth.allowed_ports
            )
        if not permitted:
            return ProcResult(
                -1, stderr=b"egress: no permitted destination addresses", blocked=True
            )
    # Shared per-controller limit; namespace creation is not an unbounded fan-out.
    if not hasattr(controller, "_socket_slots"):
        controller._socket_slots = asyncio.Semaphore(2)
    stop = asyncio.Event()

    boundary = None

    async def monitor():
        while True:
            if (
                (cancel_event is not None and cancel_event.is_set())
                or auth.is_cancelled()
                or auth.expired()
            ):
                stop.set()
                if boundary is not None:
                    boundary.terminate()
                return
            await asyncio.sleep(0.1)

    async with controller._socket_slots:
        auth.require_command(command)
        # Setup/teardown are synchronous, bounded privileged operations: no
        # cancellation can strand an unfinished namespace-creation worker thread.
        try:
            with SocketNamespace(
                auth, port_map, ports=port_map, bindings=bindings
            ) as boundary:
                args = [executable, *command[1:]]
                if name == "nmap":
                    args += ["--system-dns"]
                if name == "naabu":
                    # Naabu uses its own DNS client and ignores /etc/hosts.
                    # Feed exactly the validated addresses, retaining the original
                    # identities in the execution record; never resolve twice.
                    for option in ("-host", "-h"):
                        if option in args:
                            args[args.index(option) + 1] = ",".join(port_map)
                    args += ["-s", "c", "-Pn", "-duc"]
                task = asyncio.create_task(monitor())
                token = set_process_guard(None)
                try:
                    result = await run_process(
                        boundary.wrap(args, timeout=timeout),
                        stdin=stdin,
                        timeout=timeout,
                        cancel_event=stop,
                    )
                finally:
                    reset_process_guard(token)
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                controller.audit.append(
                    {
                        "event": "socket_process",
                        "tool": name,
                        "destinations": len(port_map),
                        "identities": identities,
                        "returncode": result.returncode,
                        "timed_out": result.timed_out,
                        "at": time.time(),
                    }
                )
                return result
        except (OSError, subprocess.SubprocessError, AuthorizationError) as exc:
            controller.audit.append(
                {"event": "socket_process_blocked", "reason": type(exc).__name__}
            )
            return ProcResult(
                -1,
                stderr=b"egress: mandatory socket isolation failed; inspect namespace prerequisites and policy",
                blocked=True,
            )

"""Filesystem-isolated, networkless execution for local analysis/provision probes."""

from pathlib import Path
import tempfile
import json
import aiohttp
import asyncio
import shutil

from .authorization import AuthorizationError, RuleForbidden

from .adapters.base import (
    ProcResult,
    run_process,
    set_process_guard,
    reset_process_guard,
)
from .mediation import sandbox_command, collect_outputs

OFFLINE_TOOLS = {"alterx", "jsluice", "semgrep", "jwt_tool"}


def is_offline_command(command):
    name = Path(command[0]).name
    return name in OFFLINE_TOOLS and not (
        name == "jsluice"
        and any(arg.startswith(("http://", "https://")) for arg in command[1:])
    )


def is_version_probe(command):
    from .installer import TOOLS

    return any(
        Path(command[0]).name == tool.binary_name()
        and tuple(command[1:]) == tool.version_cmd[1:]
        for tool in TOOLS
    )


async def run_offline(
    controller, command, *, stdin=None, timeout=600, cancel_event=None, mounts=()
):
    controller.auth.require_command(command)
    if shutil.which("bwrap") is None:
        return ProcResult(
            -1,
            stderr=b"offline: mandatory bubblewrap isolation unavailable",
            blocked=True,
        )
    try:
        with tempfile.TemporaryDirectory(prefix="xezer-offline-") as directory:
            outputs = []
            args = sandbox_command(
                command, directory, outputs, mode="offline", mounts=mounts
            )
            token = set_process_guard(None)
            try:
                result = await run_process(
                    args, stdin=stdin, timeout=timeout, cancel_event=cancel_event
                )
            finally:
                reset_process_guard(token)
            try:
                collect_outputs(outputs)
            except RuleForbidden:
                return ProcResult(
                    -1, stderr=b"offline: unsafe output destination", blocked=True
                )
            controller.audit.append(
                {
                    "event": "offline_process",
                    "tool": Path(command[0]).name,
                    "returncode": result.returncode,
                }
            )
            return result
    except FileNotFoundError:
        return ProcResult(-1, missing=True)
    except OSError:
        return ProcResult(
            -1, stderr=b"offline: mandatory isolation unavailable", blocked=True
        )


async def run_remote_jsluice(
    controller, command, *, stdin=None, timeout=600, cancel_event=None
):
    """Fetch remote JS through policy, then run the genuine parser without egress.

    Go's ProxyFromEnvironment bypasses loopback destinations unconditionally;
    prefetching avoids making proxy environment variables the security boundary.
    """
    from .mediation import broker_policy, _raw

    controller.auth.require_command(command)
    metadata_options = {
        "-R",
        "--resolve-paths",
        "-C",
        "--cookie",
        "-H",
        "--header",
        "-p",
        "--patterns",
        "-P",
        "--placeholder",
        "-c",
        "--concurrency",
    }
    headers = {}
    for i, arg in enumerate(command[:-1]):
        if arg in {"-C", "--cookie"}:
            headers["Cookie"] = command[i + 1]
        elif arg in {"-H", "--header"}:
            key, separator, value = command[i + 1].partition(":")
            if not separator:
                return ProcResult(
                    -1, stderr=b"jsluice: invalid custom header", blocked=True
                )
            headers[key.strip()] = value.strip()
    if not hasattr(controller, "_js_download_policy"):
        controller._js_download_policy = broker_policy(
            controller.auth, controller.mediation_policy
        )
    policy = controller._js_download_policy
    try:
        with tempfile.TemporaryDirectory(prefix="xezer-js-input-") as directory:
            translated = list(command)
            originals = {}
            async with aiohttp.ClientSession(
                cookie_jar=aiohttp.DummyCookieJar()
            ) as session:
                for i, arg in enumerate(command[1:], 1):
                    if command[i - 1] in metadata_options or not arg.startswith(
                        ("http://", "https://")
                    ):
                        continue
                    response = await policy.request(
                        session,
                        "GET",
                        arg,
                        headers=headers,
                        allow_redirects=True,
                        retries=0,
                    )
                    if response.status >= 400 or response.truncated:
                        return ProcResult(
                            -1,
                            stderr=b"jsluice: remote input fetch failed or exceeded limits",
                        )
                    path = Path(directory) / f"{i}.js"
                    path.write_bytes(_raw.get())
                    translated[i] = str(path)
                    # sandbox_command names file mounts by argument position.
                    originals[f"/input/{i - 1}"] = arg
                    controller.audit.append(
                        {"event": "jsluice_input_fetched", "status": response.status}
                    )
            result = await run_offline(
                controller,
                translated,
                stdin=stdin,
                timeout=timeout,
                cancel_event=cancel_event,
            )
            if result.ok:
                lines = []
                for line in result.stdout.splitlines():
                    try:
                        entry = json.loads(line)
                        if (
                            isinstance(entry, dict)
                            and entry.get("filename") in originals
                        ):
                            entry["filename"] = originals[entry["filename"]]
                        lines.append(json.dumps(entry).encode())
                    except ValueError:
                        lines.append(line)
                result.stdout = b"\n".join(lines) + (b"\n" if lines else b"")
            return result
    except AuthorizationError:
        controller.audit.append(
            {"event": "mediation_blocked", "reason": "jsluice_input_denied"}
        )
        return ProcResult(
            -1, stderr=b"jsluice: remote input not authorized", blocked=True
        )
    except (aiohttp.ClientError, asyncio.TimeoutError):
        controller.audit.append(
            {"event": "jsluice_input_failed", "reason": "transport_failure"}
        )
        return ProcResult(-1, stderr=b"jsluice: remote input transport failed")

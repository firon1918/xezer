#!/usr/bin/env python3
"""Deterministic, non-destructive XEzer checks against loopback Juice Shop only."""

import argparse
import asyncio
import json
from pathlib import Path
import tempfile
from urllib.parse import quote

import aiohttp

from qbh.authorization import Authorization, RuleForbidden
from qbh.egress import EgressController
from qbh.http_policy import HttpPolicy
from qbh.scope import ScopeEnforcer


async def verify(port=3000):
    scope = ScopeEnforcer.from_entries([{"in_scope": ["127.0.0.1"]}])
    auth = Authorization(scope=scope)
    policy = HttpPolicy(scope, rate=5, max_retries=0)
    policy.authorization = auth
    controller = EgressController(auth, policy=policy)
    base = f"http://127.0.0.1:{port}"
    async with aiohttp.ClientSession() as session:
        ready = await policy.get(session, base + "/")
        assert ready.status == 200
        control = await policy.get(
            session, base + "/rest/products/search?q=xezer_no_such_product_725"
        )
        attack = await policy.get(
            session, base + "/rest/products/search?q=" + quote("')) OR 1=1--")
        )
        control_count = len(json.loads(control.text)["data"])
        attack_count = len(json.loads(attack.text)["data"])
        assert control_count == 0 and attack_count > 0
        auth.request_restrictions = [
            {
                "hosts": ["*"],
                "paths": ["/api/Users*"],
                "methods": ["*"],
                "forbidden": ["*"],
            }
        ]
        try:
            await policy.get(session, base + "/api/Users")
        except RuleForbidden:
            native_denied = True
        else:
            raise AssertionError("native forbidden route reached")
    curl = await controller.run(
        ["curl", "-fsS", "--max-time", "10", base + "/rest/products/search?q=apple"]
    )
    assert curl.ok and json.loads(curl.stdout)["data"]
    denied = await controller.run(
        ["curl", "-fsS", "--max-time", "10", base + "/api/Users"]
    )
    assert not denied.ok and any(
        e["event"] == "mediation_blocked" for e in controller.audit
    )
    with tempfile.TemporaryDirectory(prefix="xezer-lab-check-") as directory:
        words, output = Path(directory) / "paths", Path(directory) / "results.json"
        words.write_text("rest/products/search?q=apple\napi/Users\n")
        result = await controller.run(
            [
                "ffuf",
                "-w",
                str(words),
                "-u",
                base + "/FUZZ",
                "-mc",
                "200",
                "-of",
                "json",
                "-o",
                str(output),
                "-noninteractive",
                "-s",
                "-t",
                "1",
            ]
        )
        assert result.ok, result.stderr.decode()
        matches = json.loads(output.read_text())["results"]
        assert len(matches) == 1 and "/rest/products/search" in matches[0]["url"]
    return {
        "generated_by": "CodeRabbit",
        "target": base,
        "image_version": "19.0.0",
        "readiness": "PASS",
        "native_query_predicate_bypass": "PASS",
        "negative_control_rows": control_count,
        "injected_query_rows": attack_count,
        "native_forbidden_path": "PASS" if native_denied else "FAIL",
        "mediated_curl_allowed_and_denied": "PASS",
        "mediated_ffuf_result_file": "PASS",
        "classification": "Verified lab behavior and transport evidence; not a new autonomous SQLi detector",
        "public_exposure": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=3000)
    options = parser.parse_args()
    print(json.dumps(asyncio.run(verify(options.port)), indent=2))

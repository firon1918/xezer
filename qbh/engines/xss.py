"""XSS Engine — Dalfox + daxili kxss-üslub refleksiya yoxlaması.

İki mərhələli təsdiq:
  1. **Refleksiya yoxlaması (daxili)** — parametrə unikal marker yeridilir və
     cavabda `<`/`>` kimi kontekst simvolları ilə geri qayıdıbsa `candidate`.
  2. **Dalfox** — structured R/V observations retain tool evidence as candidates.
     A V record can represent a DOM selector match, not JavaScript execution.

Sübut: refleksiya edilmiş cavab fraqmenti (marker) və ya Dalfox POC.
"""
from __future__ import annotations

import asyncio
import json
import re

import aiohttp
from yarl import URL

from ..antiblock.ua_rotator import ua_for
from ..results import EngineResult
from ..scope import ScopeError
from .offensive import OffensiveEngine

MARKER = "qbProbe7531"
REFLECT_RE = re.compile(re.escape(MARKER))


class XSSEngine(OffensiveEngine):
    name = "xss"
    tool = "dalfox"
    timeout = 600
    max_targets = 15

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        if not self.ctx.allows("active_fuzz"):
            return res.skip("aktiv fuzz qadağandır — XSS atlandı")
        rows = self.candidate_urls(only_params=True, limit=self.max_targets,
                                   engine=self.name)
        if not rows:
            return res.skip("parametrli URL yoxdur — XSS atlandı")
        if not self.guardian:
            res.fail("guardian yoxdur — XSS təhlükəsiz icra oluna bilməz")
            return res
        print(f"[═══ XSS (Dalfox + refleksiya) ═══] {len(rows)} hədəf")

        reflected: list = []
        for row in rows:
            if not await self.gate(row["url"], res, host=row["subdomain"]):
                continue
            if await self._reflection(row, res):
                reflected.append(row)

        if not reflected:
            print("[-] heç bir refleksiya aşkarlanmadı — Dalfox atlandı")
            return res
        if not self.tool_present():
            res.warn("dalfox tapılmadı — yalnız refleksiya sübutu saxlanıldı")
            return res

        for row in reflected:
            await self._dalfox(row, res)
        return res

    # ------------------------------------------------------- reflection
    async def _reflection(self, row, res: EngineResult) -> bool:
        """Parametrlərə marker yerləşdirib cavabda refleksiyanı yoxlayır."""
        url = row["url"]
        try:
            target = URL(url)
        except (ValueError, TypeError):
            return False
        if not target.query:
            return False
        marker = f"{MARKER}"
        # Hər mövcud parametrə marker yerləşdirir (ilk parametr kifayətdir).
        params = dict(target.query)
        key = next(iter(params))
        params[key] = marker
        probe = str(target.with_query(params))
        if not self.cfg.in_scope(target.host or ""):
            return False

        async with aiohttp.ClientSession() as session:
            try:
                r = await self.guardian.get(
                    session, probe, allow_redirects=False,
                    headers={"User-Agent": ua_for(row["subdomain"])})
            except (aiohttp.ClientError, asyncio.TimeoutError, ScopeError):
                return False
            if r.status >= 400:
                return False
            body = r.text
        if not REFLECT_RE.search(body) or not self.cfg.in_scope(str(r.url)):
            return False
        idx = body.find(marker)
        ctx = body[max(0, idx - 40): idx + len(marker) + 40]
        fid = self.record(
            row["host_id"], "medium", "Refleksiya olunan parametr (XSS namizədi)",
            f"{probe} — marker cavabda geri qaytarılır. Kontekst manual XSS "
            f"yoxlaması üçün prioritetlidir.",
            evidence=ctx, confidence=0.4, status="candidate", source="reflection")
        _ = fid
        res.findings += 1
        print(f"[?] {row['subdomain']}: refleksiya aşkarlandı")
        return True

    # ---------------------------------------------------------- dalfox
    async def _dalfox(self, row, res: EngineResult) -> None:
        cmd = ["dalfox", "url", row["url"], "--no-spinner", "--silence",
               "--format", "jsonl", "--only-poc", "r,v", "--output-request",
               "--output-response", "--worker", str(self.cfg.effective_concurrency)]
        proc = await self.ctx.egress.run(cmd, targets=[row["url"]],
                                         timeout=self.timeout)
        if not proc.ok:
            if proc.blocked:
                reason = "authorization blocked execution"
            elif proc.missing:
                reason = "binary missing"
            elif proc.timed_out:
                reason = "timeout"
            else:
                reason = f"exit={proc.returncode}"
            res.warn(f"dalfox: {reason}")
            return
        self._ingest_dalfox(proc.stdout, row, res)

    def _ingest_dalfox(self, output, row, res):
        """Keep structured tool evidence; prose and reflection are not execution.

        Dalfox V can mean only an HTML element matched a selector, so even that
        signal awaits independent validation rather than claiming executed JS.
        """
        seen = set()
        for line in output.decode(errors="replace").splitlines():
            try:
                item = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if (not isinstance(item, dict) or not isinstance(item.get("type"), str)
                    or item["type"] not in {"R", "V"}):
                continue
            if item.get("cwe") != "CWE-79" or not isinstance(item.get("data"), str):
                continue
            proof_url = item["data"]
            try:
                self.ctx._auth().authorize_url(proof_url)
                proof, original = URL(proof_url), URL(row["url"])
                if proof.origin() != original.origin():
                    continue
            except (ScopeError, ValueError):
                continue
            # Same evidence printed twice (e.g. a tool output-file option) is one
            # observation, while distinct payloads retain their own evidence.
            key = (proof_url, item.get("param"), item.get("type"))
            if not all(isinstance(value, str) for value in key) or key in seen:
                continue
            seen.add(key)
            evidence = json.dumps(item, ensure_ascii=False)
            self.record(row["host_id"], "high", "XSS candidate (Dalfox)",
                        f"Dalfox {item['type']} observation at {proof_url}. "
                        "Tool evidence retained; JavaScript execution requires "
                        "independent verification.",
                        evidence=evidence, confidence=0.75 if item['type'] == 'V' else 0.5,
                        status="candidate", source="dalfox")
            res.findings += 1

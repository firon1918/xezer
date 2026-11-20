"""Reflection-context analysis only; confirmation requires independent browser execution proof."""
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import aiohttp

from qbh.brain.strategy import TestPlan, TestResult
from qbh.ingest.har_importer import digest

MARKER = "xezer'\"><7531"
EXECUTION_CHECKS = frozenset({'isolated_browser_context', 'controlled_payload_executed',
                              'execution_observed', 'negative_control_no_execution'})
MAX_PARAMETERS = 2


def has_confirmation(result):
    """Reflection alone can never enter the confirmed lifecycle. The required
    browser-execution evidence is produced only by an independent isolated
    verification stage, never by this reflection probe."""
    return result.status == 'confirmed' and result.confirmed and any(
        item.get('kind') == 'browser_execution_verified'
        and set(item.get('checks', {})) == EXECUTION_CHECKS
        and all(value is True for value in item['checks'].values())
        and isinstance(item.get('origin'), str) and item['origin']
        for item in result.evidence)


def _with_param(url, name, value):
    parts = urlsplit(url)
    pairs = [(k, value if k == name else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


def _context(body, index):
    window = body[max(0, index - 160):index]
    script_open = window.rfind('<script')
    if script_open != -1 and '</script' not in window[script_open:]:
        return 'script_block'
    tag_open = window.rfind('<')
    if tag_open != -1 and '>' not in window[tag_open:]:
        return 'attribute'
    return 'html_body'


class Strategy:
    vuln_class = 'xss'

    def _missing(self, context):
        missing = []
        if context.request.get('method', 'GET').upper() not in {'GET', 'HEAD'}:
            missing.append('read_only_request')
        if not parse_qsl(urlsplit(context.request['url']).query, keep_blank_values=True):
            missing.append('input_parameter')
        return tuple(missing)

    def is_applicable(self, context):
        missing = self._missing(context)
        return (False, 'missing:' + ','.join(missing)) if missing else (True, 'bounded_reflection_context_probe')

    def plan_test(self, context):
        _, reason = self.is_applicable(context)
        return TestPlan(self.vuln_class, context.request_id, context.prerequisite_hash, reason,
                        self._missing(context), tuple(context.evidence_refs))

    async def execute_test(self, context, plan):
        missing = self._missing(context)
        if missing:
            return TestResult('deferred', 'missing:' + ','.join(missing))
        runtime, url = context.runtime, context.request['url']
        evidence = []

        async def fetch(target, label):
            auth = runtime._auth()
            auth.ensure_active()
            auth.authorize_request('GET', target, self.vuln_class)
            auth.require(self.vuln_class)
            auth.require('active_fuzz')
            async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as session:
                response = await runtime.guardian.request(
                    session, 'GET', target, allow_redirects=False, retries=0, observe_block=False)
            evidence.append({'kind': 'probe_response', 'label': label, 'url': target,
                             'status': response.status, 'headers': dict(response.headers),
                             'body': response.text, 'truncated': response.truncated})
            return response

        evidence.append({'kind': 'authorization_decision', 'action': self.vuln_class, 'authorized': True})
        query = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        candidate = False
        for name in list(dict.fromkeys(k for k, _ in query))[:MAX_PARAMETERS]:
            baseline = await fetch(url, 'baseline:' + name)
            if baseline.status != 200 or baseline.truncated or MARKER in baseline.text:
                continue
            probe = await fetch(_with_param(url, name, MARKER), 'reflection_probe:' + name)
            if probe.status != 200 or probe.truncated:
                continue
            index = probe.text.find(MARKER)
            if index != -1:
                context_kind = _context(probe.text, index)
                evidence.append({'kind': 'reflection_context', 'parameter': name, 'context': context_kind,
                                 'fragment': probe.text[max(0, index - 80):index + len(MARKER) + 80],
                                 'probe_digest': digest(probe.text), 'evidence_refs': list(plan.evidence_refs)})
                candidate = True
            elif re.search(re.escape('xezer'), probe.text) and ('&lt;' in probe.text or '&#' in probe.text):
                evidence.append({'kind': 'encoded_reflection', 'parameter': name,
                                 'probe_digest': digest(probe.text)})
        if candidate:
            return TestResult('candidate', 'unescaped_reflection_requires_browser_execution_verification', evidence)
        return TestResult('completed', 'no_unescaped_reflection_observed', evidence)

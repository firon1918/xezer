"""Bounded read-only boolean differential probes; error text alone never confirms."""
from dataclasses import asdict
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import aiohttp

from qbh.brain.diff_engine import DiffEngine
from qbh.brain.strategy import TestPlan, TestResult
from qbh.ingest.har_importer import digest

CHECKS = frozenset({'read_only_get', 'baseline_usable', 'true_condition_matches_baseline',
                    'false_condition_differs_from_true', 'distinct_literals_repeat_differential',
                    'repeated_round_stable', 'negative_control_usable'})
MAX_PARAMETERS = 2


def has_confirmation(result):
    """A candidate flag, HTTP 200 or SQL error text alone can never confirm."""
    return result.status == 'confirmed' and result.confirmed and any(
        item.get('kind') == 'verified_query_semantics'
        and set(item.get('checks', {})) == CHECKS and all(value is True for value in item['checks'].values())
        and isinstance(item.get('parameter'), str) and item['parameter']
        for item in result.evidence)


def _with_param(url, name, value):
    parts = urlsplit(url)
    pairs = [(k, value if k == name else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


def _same(a, b):
    # Exact equality only: dynamic pages stay inconclusive rather than guessed.
    return a.status == b.status and a.text == b.text and not a.truncated and not b.truncated


class Strategy:
    vuln_class = 'sqli'

    def _missing(self, context):
        missing = []
        if context.request.get('method', 'GET').upper() not in {'GET', 'HEAD'}:
            missing.append('read_only_request')
        if not parse_qsl(urlsplit(context.request['url']).query, keep_blank_values=True):
            missing.append('input_parameter')
        return tuple(missing)

    def is_applicable(self, context):
        missing = self._missing(context)
        return (False, 'missing:' + ','.join(missing)) if missing else (True, 'bounded_boolean_differential_probe')

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
            # No HAR auth headers, ambient cookies or redirects: probes are paired
            # anonymous observations under the same per-request policy.
            async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as session:
                response = await runtime.guardian.request(
                    session, 'GET', target, allow_redirects=False, retries=0, observe_block=False)
            evidence.append({'kind': 'probe_response', 'label': label, 'url': target,
                             'status': response.status, 'headers': dict(response.headers),
                             'body': response.text, 'truncated': response.truncated})
            return response

        evidence.append({'kind': 'authorization_decision', 'action': self.vuln_class, 'authorized': True})
        query = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        for name in list(dict.fromkeys(k for k, _ in query))[:MAX_PARAMETERS]:
            value = next(v for k, v in query if k == name)
            baseline = await fetch(url, 'baseline:' + name)
            if baseline.status != 200 or baseline.truncated:
                continue
            true1 = await fetch(_with_param(url, name, value + "' AND '1'='1"), 'true_literal_1:' + name)
            false1 = await fetch(_with_param(url, name, value + "' AND '1'='2"), 'false_literal_1:' + name)
            control = await fetch(_with_param(url, name, value + 'xezercontrol'), 'negative_control:' + name)
            if control.status != 200 or control.truncated:
                continue
            if not (_same(baseline, true1) and not _same(true1, false1)):
                continue
            true2 = await fetch(_with_param(url, name, value + "' AND 'a'='a"), 'true_literal_2:' + name)
            false2 = await fetch(_with_param(url, name, value + "' AND 'a'='b"), 'false_literal_2:' + name)
            if not (_same(true1, true2) and _same(false1, false2) and not _same(true2, false2)):
                continue
            repeat_true = await fetch(_with_param(url, name, value + "' AND '1'='1"), 'repeat_true:' + name)
            repeat_false = await fetch(_with_param(url, name, value + "' AND '1'='2"), 'repeat_false:' + name)
            if not (_same(true1, repeat_true) and _same(false1, repeat_false)):
                continue
            evidence.append({'kind': 'verified_query_semantics', 'parameter': name,
                             'checks': dict.fromkeys(CHECKS, True),
                             'baseline_digest': digest(baseline.text), 'true_digest': digest(true1.text),
                             'false_digest': digest(false1.text), 'control_digest': digest(control.text),
                             'comparison': asdict(DiffEngine().compare(true1, false1)),
                             'evidence_refs': list(plan.evidence_refs)})
            return TestResult('confirmed', 'repeatable_boolean_query_semantics_with_paired_controls', evidence, True)
        return TestResult('inconclusive', 'no_repeatable_controlled_query_semantic_effect', evidence)

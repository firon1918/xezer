"""Bounded harmless arithmetic expressions; distinct evaluated results with negative controls."""
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import aiohttp

from qbh.brain.strategy import TestPlan, TestResult
from qbh.ingest.har_importer import digest

CHECKS = frozenset({'read_only_get', 'baseline_lacks_markers', 'expression_evaluated',
                    'distinct_expression_distinct_result', 'negative_control_clean',
                    'repeated_evaluation_stable'})
MAX_PARAMETERS = 2
#: Distinctive products: static content or reflection cannot produce both.
EXPRESSIONS = (('1337*7331', str(1337 * 7331)), ('1337*7333', str(1337 * 7333)))
SYNTAXES = ('{{%s}}', '${%s}', '<%%=%s%%>')


def has_confirmation(result):
    """Reflection of the payload text is not evaluation; only computed products confirm."""
    return result.status == 'confirmed' and result.confirmed and any(
        item.get('kind') == 'verified_template_evaluation'
        and set(item.get('checks', {})) == CHECKS and all(value is True for value in item['checks'].values())
        and isinstance(item.get('parameter'), str) and item['parameter']
        and item.get('syntax') in SYNTAXES
        for item in result.evidence)


def _with_param(url, name, value):
    parts = urlsplit(url)
    pairs = [(k, value if k == name else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


class Strategy:
    vuln_class = 'ssti'

    def _missing(self, context):
        missing = []
        if context.request.get('method', 'GET').upper() not in {'GET', 'HEAD'}:
            missing.append('read_only_request')
        if not parse_qsl(urlsplit(context.request['url']).query, keep_blank_values=True):
            missing.append('input_parameter')
        return tuple(missing)

    def is_applicable(self, context):
        missing = self._missing(context)
        return (False, 'missing:' + ','.join(missing)) if missing else (True, 'bounded_expression_evaluation_probe')

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
        markers = tuple(product for _, product in EXPRESSIONS)
        query = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        for name in list(dict.fromkeys(k for k, _ in query))[:MAX_PARAMETERS]:
            baseline = await fetch(url, 'baseline:' + name)
            if baseline.status != 200 or baseline.truncated:
                continue
            if any(marker in baseline.text for marker in markers):
                continue
            for syntax in SYNTAXES:
                payloads = [syntax % expression for expression, _ in EXPRESSIONS]
                first = await fetch(_with_param(url, name, payloads[0]), 'expression_1:' + name)
                second = await fetch(_with_param(url, name, payloads[1]), 'expression_2:' + name)
                if first.status != 200 or second.status != 200 or first.truncated or second.truncated:
                    continue
                if not (markers[0] in first.text and markers[1] in second.text
                        and markers[1] not in first.text and markers[0] not in second.text):
                    continue
                control = await fetch(_with_param(url, name, 'xezer1337x7331xezer'), 'negative_control:' + name)
                if control.status != 200 or control.truncated or any(m in control.text for m in markers):
                    continue
                repeated = await fetch(_with_param(url, name, payloads[0]), 'repeat_expression:' + name)
                if repeated.status != 200 or repeated.truncated or markers[0] not in repeated.text:
                    continue
                evidence.append({'kind': 'verified_template_evaluation', 'parameter': name, 'syntax': syntax,
                                 'checks': dict.fromkeys(CHECKS, True),
                                 'products': list(markers), 'baseline_digest': digest(baseline.text),
                                 'control_digest': digest(control.text),
                                 'evidence_refs': list(plan.evidence_refs)})
                return TestResult('confirmed', 'repeatable_distinct_expression_evaluation_with_negative_control',
                                  evidence, True)
        return TestResult('inconclusive', 'no_verified_server_side_expression_evaluation', evidence)

"""Only an operator-designated synthetic canary outside the logical root is requested."""
from pathlib import Path
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import aiohttp

from qbh.brain.strategy import TestPlan, TestResult
from qbh.ingest.har_importer import digest

CHECKS = frozenset({'read_only_get', 'canary_designated', 'baseline_lacks_canary', 'canary_disclosed',
                    'missing_file_control_clean', 'repeated_disclosure_stable'})
FILE_PARAMETERS = frozenset({'file', 'path', 'page', 'doc', 'document', 'template', 'include',
                             'load', 'read', 'download', 'filename', 'filepath', 'folder', 'dir', 'view'})
MAX_DEPTH = 4
MAX_CANARY_CHARS = 4096


def has_confirmation(result):
    """A 200 response or error text is not disclosure; only the designated canary content confirms."""
    return result.status == 'confirmed' and result.confirmed and any(
        item.get('kind') == 'verified_canary_disclosure'
        and set(item.get('checks', {})) == CHECKS and all(value is True for value in item['checks'].values())
        and isinstance(item.get('parameter'), str) and item['parameter']
        and 1 <= item.get('depth', 0) <= MAX_DEPTH
        for item in result.evidence)


def _with_param(url, name, value):
    parts = urlsplit(url)
    pairs = [(k, value if k == name else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


def _file_parameters(url):
    names = []
    for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if name.lower() in FILE_PARAMETERS or '/' in value or re.fullmatch(r'[\w-]+\.[A-Za-z0-9]{1,8}', value):
            if name not in names:
                names.append(name)
    return names


class Strategy:
    vuln_class = 'lfi_path_traversal'

    def _canary(self, context):
        path = getattr(getattr(context.runtime, 'cfg', None), 'lfi_canary_file', '')
        if not path:
            return None
        try:
            content = Path(path).read_text(encoding='utf-8')
        except (OSError, UnicodeError):
            return None
        if not content or len(content) > MAX_CANARY_CHARS:
            return None
        return Path(path).name, content

    def _missing(self, context):
        missing = []
        if context.request.get('method', 'GET').upper() not in {'GET', 'HEAD'}:
            missing.append('read_only_request')
        if not _file_parameters(context.request['url']):
            missing.append('file_parameter')
        if self._canary(context) is None:
            missing.append('synthetic_canary')
        return tuple(missing)

    def is_applicable(self, context):
        missing = self._missing(context)
        return (False, 'missing:' + ','.join(missing)) if missing else (True, 'designated_canary_traversal_probe')

    def plan_test(self, context):
        _, reason = self.is_applicable(context)
        return TestPlan(self.vuln_class, context.request_id, context.prerequisite_hash, reason,
                        self._missing(context), tuple(context.evidence_refs))

    async def execute_test(self, context, plan):
        missing = self._missing(context)
        if missing:
            return TestResult('deferred', 'missing:' + ','.join(missing))
        runtime, url = context.runtime, context.request['url']
        canary_name, canary_content = self._canary(context)
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
        baseline = await fetch(url, 'baseline')
        if baseline.status != 200 or baseline.truncated or canary_content in baseline.text:
            return TestResult('inconclusive', 'baseline_unusable_or_already_contains_canary', evidence)
        for name in _file_parameters(url)[:1]:
            for depth in range(1, MAX_DEPTH + 1):
                prefix = '../' * depth
                probe = await fetch(_with_param(url, name, prefix + canary_name), f'traversal_depth_{depth}:{name}')
                if probe.status != 200 or probe.truncated or probe.text != canary_content:
                    continue
                control = await fetch(_with_param(url, name, prefix + 'xezer-missing-canary.txt'),
                                      f'missing_file_control:{name}')
                if control.truncated or canary_content in control.text:
                    continue
                repeated = await fetch(_with_param(url, name, prefix + canary_name), f'repeat_traversal:{name}')
                if repeated.status != 200 or repeated.truncated or repeated.text != canary_content:
                    continue
                evidence.append({'kind': 'verified_canary_disclosure', 'parameter': name, 'depth': depth,
                                 'checks': dict.fromkeys(CHECKS, True),
                                 'canary_digest': digest(canary_content),
                                 'canary_reference': 'config:lfi_canary_file',
                                 'evidence_refs': list(plan.evidence_refs)})
                return TestResult('confirmed', 'designated_canary_disclosed_outside_logical_root', evidence, True)
        return TestResult('inconclusive', 'no_designated_canary_disclosure', evidence)

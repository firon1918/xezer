"""OWASP detection benchmark: planted-vulnerability positives vs hardened negatives.

Loopback-only (127.0.0.1) fixtures; every number comes from real planner
execution. A detection signal never becomes an automatic confirmation: the
brain lifecycle gates (paired controls, repetition, negative controls) decide.

Run: python tests/benchmarks/owasp_detection.py [--output report.json]
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aiohttp import web                                          # noqa: E402

from qbh import db                                               # noqa: E402
from qbh.brain import store                                      # noqa: E402
from qbh.brain.planner import BrainPlanner                       # noqa: E402
from qbh.config import Config                                    # noqa: E402
from qbh.ingest.har_importer import HarImporter                  # noqa: E402
from tests.test_injection_strategies import build_app, serve     # noqa: E402

#: (owasp category, vuln_class, endpoint key, expected planted status)
CASES = [
    ('A03', 'sqli', 'search', 'confirmed'),
    ('A03', 'ssti', 'render', 'confirmed'),
    ('A03', 'xss', 'echo', 'candidate'),
    ('A01', 'lfi_path_traversal', 'download', 'confirmed'),
    ('A01', 'idor', 'object', 'confirmed'),
    ('A07', 'jwt_implementation_weakness', 'jwt', 'candidate'),
]
ENDPOINTS = {'search': '/search?q=alice', 'render': '/render?name=world',
             'download': '/download?file=report.txt', 'echo': '/echo?msg=hello'}


def build_idor_app(mode):
    hits = []

    async def login(request):
        data = await request.json()
        if (data.get('username'), data.get('password')) not in {
                ('alice', 'synthetic-a-password'), ('bob', 'synthetic-b-password')}:
            return web.Response(status=401)
        response = web.json_response({'user': {'id': data['username']}})
        response.set_cookie('session', data['username'])
        return response

    async def me(request):
        name = request.cookies.get('session')
        return (web.json_response({'user': {'id': name}}) if name in {'alice', 'bob'}
                else web.Response(status=401))

    async def resource(request):
        name = request.cookies.get('session')
        kind = request.match_info['mode']
        hits.append((kind, name))
        if kind != 'public' and name not in {'alice', 'bob'}:
            return web.Response(status=401)
        if kind == 'secure' and name != 'alice':
            return web.Response(status=403)
        return web.json_response({'id': 7, 'owner_id': 'alice',
                                  'private_data': 'synthetic-private-object'})

    app = web.Application()
    app.router.add_post('/login', login)
    app.router.add_get('/me', me)
    app.router.add_get('/{mode}/7', resource)
    return app, hits


def auth_spec(base, suffix='A'):
    return {'name': 'user_' + suffix.lower(), 'role': 'user', 'login_url': base + '/login',
            'login_method': 'POST', 'verify_url': base + '/me',
            'login_fields': {'username_env': 'TARGET_USER_' + suffix,
                             'password_env': 'TARGET_USER_' + suffix + '_PASS'}}


def write_config(directory, base, canary):
    import yaml
    data = {
        'program': 'owasp-benchmark', 'nvd_api_key': '',
        'scope': [{'domain': '127.0.0.1', 'in_scope': ['127.0.0.1'], 'out_of_scope': []}],
        'limits': {'requests_per_second': 1000, 'max_concurrency': 5,
                   'connect_timeout': 5, 'total_timeout': 10, 'cooldown': 1},
        'proxy_file': '',
        'auth_contexts': [auth_spec(base), auth_spec(base, 'B')],
        'auth_resource_policies': [
            {'id': 'private-objects', 'origin': base, 'path_pattern': '/*/7',
             'owner_field': 'owner_id', 'object_id_field': 'id',
             'protected_fields': ['private_data'], 'roles': ['user'],
             'access_policy': 'owner_only'}],
        'lfi_canary_file': str(canary),
    }
    path = directory / 'benchmark.yaml'
    path.write_text(yaml.safe_dump(data), encoding='utf-8')
    return Config.load(str(path))


def make_runtime(cfg, scan_id):
    from qbh.antiblock.guardian import Guardian
    from qbh.antiblock.identity import IdentityManager
    from qbh.context import Context
    from qbh.http_policy import HttpPolicy
    policy = HttpPolicy(cfg.scope, rate=1000, max_concurrency=10)
    guardian = Guardian(IdentityManager('', 'lo'), policy)
    args = argparse.Namespace(rate=1000, active_fuzz=None, race_fixture=None,
                              race_count=10, race_concurrency=4)
    return Context(cfg=cfg, args=args, guardian=guardian, scan_id=scan_id)


async def run_case(mode, directory):
    """Execute the full brain lifecycle against one fixture mode."""
    directory.mkdir(parents=True, exist_ok=True)
    app, hits, canary = build_app(directory, 'planted' if mode == 'planted' else 'hardened')
    runner, base = await serve(app)
    idor_mode = 'vulnerable' if mode == 'planted' else 'secure'
    idor_app, idor_hits = build_idor_app(idor_mode)
    idor_runner, idor_base = await serve(idor_app)
    cfg = write_config(directory, idor_base, canary)
    runtime = make_runtime(cfg, None)
    try:
        if mode == 'planted':
            header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip('=')
            token = header + '.eyJzdWIiOiJ0ZXN0In0.'
            har = directory / 'jwt.har'
            har.write_text(json.dumps({'log': {'entries': [{
                'request': {'method': 'GET', 'url': base + '/api/me',
                            'headers': [{'name': 'Authorization', 'value': 'Bearer ' + token}]},
                'response': {'status': 200, 'content': {'text': '{}'}}}]}}), encoding='utf-8')
            # The importer creates its own scan; adopt it so every plan, URL
            # and finding for this case lives in one scan.
            report = HarImporter(runtime.vault).import_file(har)
            runtime.scan_id = report['scan_id']
            jwt_request_id = report['entries'][0]['request_id']
        else:
            runtime.scan_id = db.start_scan('owasp-benchmark-' + mode, 'full')
        scan_id = runtime.scan_id
        host = db.upsert_host('127.0.0.1', scan_id=scan_id)
        url_ids = {}
        for key, path in ENDPOINTS.items():
            url = base + path
            db.insert_url(host, url, 'benchmark', scan_id=scan_id)
            url_ids[key] = db.get_db().execute(
                'SELECT id FROM urls WHERE scan_id=? AND url=?', (scan_id, url)).fetchone()['id']
        object_url = idor_base + '/' + idor_mode + '/7'
        db.insert_url(host, object_url, 'benchmark', scan_id=scan_id)
        url_ids['object'] = db.get_db().execute(
            'SELECT id FROM urls WHERE scan_id=? AND url=?', (scan_id, object_url)).fetchone()['id']
        if mode == 'planted':
            url_ids['jwt'] = None
        started = time.monotonic()
        await BrainPlanner(runtime).run()
        elapsed = time.monotonic() - started
        rows = store.list_plans(scan_id)
        results = {}
        for key, url_id in url_ids.items():
            for row in rows:
                if key == 'jwt':
                    match = row['request_id'] == jwt_request_id
                else:
                    match = row['url_id'] == url_id
                if match:
                    results.setdefault(key, {})[row['vuln_class']] = row['status']
        findings = db.findings_all(scan_id)
        return {'results': results, 'elapsed_seconds': round(elapsed, 3),
                'requests': len(hits) + len(idor_hits),
                'findings': {'confirmed': sum(f['status'] == 'confirmed' for f in findings),
                             'candidate': sum(f['status'] == 'candidate' for f in findings)}}
    finally:
        await runtime.aclose()
        await runner.cleanup()
        await idor_runner.cleanup()


async def benchmark():
    env_keys = ('QBH_VAULT_KEY', 'TARGET_USER_A', 'TARGET_USER_A_PASS',
                'TARGET_USER_B', 'TARGET_USER_B_PASS')
    saved_env = {key: os.environ.get(key) for key in env_keys}
    saved_db_path = db.DB_PATH
    os.environ.setdefault('QBH_VAULT_KEY', 'synthetic-owasp-benchmark-key')
    os.environ['TARGET_USER_A'] = 'alice'
    os.environ['TARGET_USER_A_PASS'] = 'synthetic-a-password'
    os.environ['TARGET_USER_B'] = 'bob'
    os.environ['TARGET_USER_B_PASS'] = 'synthetic-b-password'
    try:
        with tempfile.TemporaryDirectory(prefix='owasp-benchmark-') as tmp:
            directory = pathlib.Path(tmp)
            db.DB_PATH = str(directory / 'benchmark.db')
            db.close_db()
            db.init_db()
            try:
                planted = await run_case('planted', directory / 'planted')
                hardened = await run_case('hardened', directory / 'hardened')
            finally:
                db.close_db()
    finally:
        db.DB_PATH = saved_db_path
        for key, value in saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    cases, detected, false_positives = [], 0, 0
    for category, name, key, expected in CASES:
        actual = planted['results'].get(key, {}).get(name, 'missing')
        hard = hardened['results'].get(key, {}).get(name, 'missing')
        ok = actual == expected
        detected += ok
        # JWT is a client-token observation, not server behavior: excluded from
        # the hardened false-positive count by design.
        hard_fp = name != 'jwt_implementation_weakness' and hard in {'confirmed', 'candidate'}
        false_positives += hard_fp
        cases.append({'owasp': category, 'vuln_class': name, 'expected': expected,
                      'planted': actual, 'hardened': hard,
                      'detected': ok, 'hardened_false_positive': hard_fp})
    return {'fixture': 'loopback-127.0.0.1', 'cases': cases,
            'planted': {k: planted[k] for k in ('elapsed_seconds', 'requests', 'findings')},
            'hardened': {k: hardened[k] for k in ('elapsed_seconds', 'requests', 'findings')},
            'score': {'expected': len(CASES), 'detected': detected,
                      'hardened_false_positives': false_positives}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', help='write the JSON report to this path')
    args = parser.parse_args(argv)
    report = asyncio.run(benchmark())
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        pathlib.Path(args.output).write_text(text + '\n', encoding='utf-8')
    print(text)
    return 0 if (report['score']['detected'] == report['score']['expected']
                 and report['score']['hardened_false_positives'] == 0) else 1


if __name__ == '__main__':
    raise SystemExit(main())

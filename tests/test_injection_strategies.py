"""Active injection strategies: planted-vulnerability positives, hardened negatives.

All traffic stays on loopback fixtures; confirmations require paired controls
and repetition, and a flag or error text alone never enters the lifecycle.
"""
import html
import importlib
import json
import os
import re
from types import SimpleNamespace

import pytest
import pytest_asyncio
from aiohttp import web

from qbh import db
from qbh.authorization import RuleForbidden
from qbh.brain.context import ContextBuilder
from qbh.brain.strategy import TestResult
from qbh.config import ConfigError

MODULES = ('sqli', 'ssti', 'lfi_path_traversal', 'xss')


def strategy_module(name):
    return importlib.import_module('qbh.brain.strategies.' + name)


def build_app(tmp_path, mode):
    hits = []
    root = tmp_path / 'public'
    root.mkdir()
    (root / 'report.txt').write_text('public report', encoding='utf-8')
    canary = tmp_path / 'canary.txt'
    canary.write_text('synthetic-canary-7531', encoding='utf-8')
    rows = {'alice': [{'id': 1, 'name': 'alice'}]}

    def document(value):
        return json.dumps({'results': value}, sort_keys=True)

    async def search(request):
        q = request.query.get('q', '')
        hits.append(('search', q))
        if mode == 'error' and "'" in q:
            return web.Response(status=500, text='SQLSTATE[42000]: syntax error near quote')
        if mode == 'planted':
            for suffix in ("' AND '1'='1", "' AND 'a'='a"):
                if q.endswith(suffix):
                    return web.Response(text=document(rows.get(q[:-len(suffix)], [])),
                                        content_type='application/json')
            for suffix in ("' AND '1'='2", "' AND 'a'='b"):
                if q.endswith(suffix):
                    return web.Response(text=document([]), content_type='application/json')
        return web.Response(text=document(rows.get(q, [])), content_type='application/json')

    async def render(request):
        name = request.query.get('name', '')
        hits.append(('render', name))
        if mode in ('planted', 'erb'):
            pattern = (r'<%=(\d+)\*(\d+)%>' if mode == 'erb'
                       else r'(?:\{\{|\$\{|<%=)(\d+)\*(\d+)(?:\}\}|%>)')
            match = re.fullmatch(pattern, name)
            if match:
                return web.Response(text=f'Hello {int(match.group(1)) * int(match.group(2))}!')
        shown = html.escape(name) if mode == 'hardened' else name
        return web.Response(text=f'Hello {shown}!')

    async def download(request):
        name = request.query.get('file', '')
        hits.append(('download', name))
        target = root / name
        if mode == 'hardened':
            resolved = target.resolve()
            if os.path.commonpath([str(resolved), str(root.resolve())]) != str(root.resolve()):
                return web.Response(status=403, text='forbidden')
        try:
            if target.is_file():
                return web.Response(text=target.read_text(encoding='utf-8'))
        except OSError:
            pass
        return web.Response(status=404, text='not found')

    async def echo(request):
        msg = request.query.get('msg', '')
        hits.append(('echo', msg))
        shown = html.escape(msg) if mode == 'hardened' else msg
        return web.Response(text=f'<html><body>{shown}</body></html>', content_type='text/html')

    app = web.Application()
    app.router.add_get('/search', search)
    app.router.add_get('/render', render)
    app.router.add_get('/download', download)
    app.router.add_get('/echo', echo)
    return app, hits, canary


async def serve(app):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    return runner, f'http://127.0.0.1:{runner.addresses[0][1]}'


@pytest_asyncio.fixture
async def planted_app(tmp_path):
    app, hits, canary = build_app(tmp_path, 'planted')
    runner, base = await serve(app)
    try:
        yield SimpleNamespace(base=base, hits=hits, canary=canary)
    finally:
        await runner.cleanup()


@pytest_asyncio.fixture
async def hardened_app(tmp_path):
    app, hits, canary = build_app(tmp_path, 'hardened')
    runner, base = await serve(app)
    try:
        yield SimpleNamespace(base=base, hits=hits, canary=canary)
    finally:
        await runner.cleanup()


@pytest_asyncio.fixture
async def error_app(tmp_path):
    app, hits, canary = build_app(tmp_path, 'error')
    runner, base = await serve(app)
    try:
        yield SimpleNamespace(base=base, hits=hits, canary=canary)
    finally:
        await runner.cleanup()


@pytest_asyncio.fixture
async def erb_app(tmp_path):
    app, hits, canary = build_app(tmp_path, 'erb')
    runner, base = await serve(app)
    try:
        yield SimpleNamespace(base=base, hits=hits, canary=canary)
    finally:
        await runner.cleanup()


@pytest.fixture
def strategy_runtime(tmp_db, make_ctx, monkeypatch):
    monkeypatch.setenv('QBH_VAULT_KEY', 'synthetic-strategy-key')
    runtime = make_ctx()
    runtime.scan_id = db.start_scan('strategy-fixture', 'full')
    return runtime


async def run_strategy(runtime, url, name):
    context = ContextBuilder(runtime).from_request({'url': url, 'method': 'GET'})
    strategy = strategy_module(name).Strategy()
    return await strategy.execute_test(context, strategy.plan_test(context))


def verified_item(result, kind):
    return next(item for item in result.evidence if item.get('kind') == kind)


async def test_sqli_confirms_repeatable_boolean_differential_with_controls(planted_app, strategy_runtime):
    result = await run_strategy(strategy_runtime, planted_app.base + '/search?q=alice', 'sqli')
    assert result.status == 'confirmed' and result.confirmed
    module = strategy_module('sqli')
    assert module.has_confirmation(result)
    item = verified_item(result, 'verified_query_semantics')
    assert item['parameter'] == 'q' and all(value is True for value in item['checks'].values())
    labels = [e['label'] for e in result.evidence if e.get('kind') == 'probe_response']
    assert 'negative_control:q' in labels and 'repeat_true:q' in labels
    assert any(e.get('kind') == 'authorization_decision' for e in result.evidence)
    assert len(planted_app.hits) <= 16


async def test_sqli_hardened_literal_search_never_confirms(hardened_app, strategy_runtime):
    result = await run_strategy(strategy_runtime, hardened_app.base + '/search?q=alice', 'sqli')
    assert result.status == 'inconclusive' and not result.confirmed
    assert not strategy_module('sqli').has_confirmation(result)


async def test_sqli_error_text_alone_never_confirms(error_app, strategy_runtime):
    result = await run_strategy(strategy_runtime, error_app.base + '/search?q=alice', 'sqli')
    assert result.status == 'inconclusive' and not result.confirmed
    assert any('SQLSTATE' in e.get('body', '') for e in result.evidence if e.get('kind') == 'probe_response')


async def test_ssti_confirms_distinct_evaluated_products(planted_app, strategy_runtime):
    result = await run_strategy(strategy_runtime, planted_app.base + '/render?name=world', 'ssti')
    assert result.status == 'confirmed' and result.confirmed
    module = strategy_module('ssti')
    assert module.has_confirmation(result)
    item = verified_item(result, 'verified_template_evaluation')
    assert item['syntax'] == '{{%s}}' and item['products'] == ['9801547', '9804221']
    labels = [e['label'] for e in result.evidence if e.get('kind') == 'probe_response']
    assert 'negative_control:name' in labels and 'repeat_expression:name' in labels
    assert len(planted_app.hits) <= 18


async def test_ssti_hardened_reflection_never_confirms(hardened_app, strategy_runtime):
    result = await run_strategy(strategy_runtime, hardened_app.base + '/render?name=world', 'ssti')
    assert result.status == 'inconclusive' and not result.confirmed


async def test_ssti_erb_syntax_is_probed_and_confirmed(erb_app, strategy_runtime):
    result = await run_strategy(strategy_runtime, erb_app.base + '/render?name=world', 'ssti')
    assert result.status == 'confirmed' and result.confirmed
    assert verified_item(result, 'verified_template_evaluation')['syntax'] == '<%%=%s%%>'


async def test_lfi_confirms_only_designated_canary_disclosure(planted_app, strategy_runtime):
    strategy_runtime.cfg.lfi_canary_file = str(planted_app.canary)
    result = await run_strategy(strategy_runtime, planted_app.base + '/download?file=report.txt',
                                'lfi_path_traversal')
    assert result.status == 'confirmed' and result.confirmed
    module = strategy_module('lfi_path_traversal')
    assert module.has_confirmation(result)
    item = verified_item(result, 'verified_canary_disclosure')
    assert item['parameter'] == 'file' and item['depth'] == 1
    labels = [e['label'] for e in result.evidence if e.get('kind') == 'probe_response']
    assert 'missing_file_control:file' in labels and 'repeat_traversal:file' in labels
    assert len(planted_app.hits) <= 7


async def test_lfi_hardened_root_containment_never_confirms(hardened_app, strategy_runtime):
    strategy_runtime.cfg.lfi_canary_file = str(hardened_app.canary)
    result = await run_strategy(strategy_runtime, hardened_app.base + '/download?file=report.txt',
                                'lfi_path_traversal')
    assert result.status == 'inconclusive' and not result.confirmed


async def test_lfi_without_designated_canary_stays_deferred(planted_app, strategy_runtime):
    result = await run_strategy(strategy_runtime, planted_app.base + '/download?file=report.txt',
                                'lfi_path_traversal')
    assert result.status == 'deferred' and 'synthetic_canary' in result.reason
    assert not planted_app.hits


async def test_xss_unescaped_reflection_is_candidate_only(planted_app, strategy_runtime):
    result = await run_strategy(strategy_runtime, planted_app.base + '/echo?msg=hello', 'xss')
    assert result.status == 'candidate' and not result.confirmed
    item = verified_item(result, 'reflection_context')
    assert item['context'] == 'html_body' and item['parameter'] == 'msg'
    assert not strategy_module('xss').has_confirmation(result)
    assert len(planted_app.hits) <= 4


async def test_xss_encoded_reflection_is_not_a_finding(hardened_app, strategy_runtime):
    result = await run_strategy(strategy_runtime, hardened_app.base + '/echo?msg=hello', 'xss')
    assert result.status == 'completed' and not result.confirmed
    assert any(e.get('kind') == 'encoded_reflection' for e in result.evidence)
    assert not any(e.get('kind') == 'reflection_context' for e in result.evidence)


@pytest.mark.parametrize('name', MODULES + ('idor',))
def test_confirmation_flag_alone_is_insufficient(name):
    assert not strategy_module(name).has_confirmation(TestResult('confirmed', 'http_200', confirmed=True))


@pytest.mark.parametrize('name', MODULES)
async def test_strategies_require_read_only_parameterized_get(strategy_runtime, planted_app, name):
    strategy_runtime.cfg.lfi_canary_file = str(planted_app.canary)
    context = ContextBuilder(strategy_runtime).from_request(
        {'url': planted_app.base + '/search', 'method': 'POST'})
    strategy = strategy_module(name).Strategy()
    applicable, reason = strategy.is_applicable(context)
    assert not applicable and 'read_only_request' in reason
    result = await strategy.execute_test(context, strategy.plan_test(context))
    assert result.status == 'deferred'
    assert not planted_app.hits


async def test_dry_run_blocks_probe_execution(planted_app, strategy_runtime):
    strategy_runtime.args.dry_run = True
    with pytest.raises(RuleForbidden):
        await run_strategy(strategy_runtime, planted_app.base + '/search?q=alice', 'sqli')
    assert not planted_app.hits


async def test_planner_lifecycle_confirms_injections_and_keeps_xss_candidate(planted_app, strategy_runtime):
    from qbh.brain import store
    from qbh.brain.planner import BrainPlanner
    strategy_runtime.cfg.lfi_canary_file = str(planted_app.canary)
    host = db.upsert_host('127.0.0.1', scan_id=strategy_runtime.scan_id)
    endpoints = {'sqli': '/search?q=alice', 'ssti': '/render?name=world',
                 'lfi_path_traversal': '/download?file=report.txt', 'xss': '/echo?msg=hello'}
    url_ids = {}
    for name, path in endpoints.items():
        url = planted_app.base + path
        db.insert_url(host, url, 'test', scan_id=strategy_runtime.scan_id)
        url_ids[name] = db.get_db().execute('SELECT id FROM urls WHERE scan_id=? AND url=?',
                                            (strategy_runtime.scan_id, url)).fetchone()['id']
    await BrainPlanner(strategy_runtime).run()
    rows = store.list_plans(strategy_runtime.scan_id)
    for name, url_id in url_ids.items():
        row = next(r for r in rows if r['url_id'] == url_id and r['vuln_class'] == name)
        expected = 'candidate' if name == 'xss' else 'confirmed'
        assert row['status'] == expected, (name, row['reason'])
        assert row['finding_id']
    findings = db.findings_all(strategy_runtime.scan_id)
    confirmed = [f for f in findings if f['status'] == 'confirmed']
    assert {f['module'] for f in confirmed} == {'brain:sqli', 'brain:ssti', 'brain:lfi_path_traversal'}
    assert all(f['module'] == 'brain:xss' for f in findings if f['status'] == 'candidate')
    assert 'synthetic-canary-7531' not in '\n'.join(db.get_db().iterdump())


async def test_planner_downgrades_forged_confirmation_without_gate_evidence(planted_app, strategy_runtime, monkeypatch):
    from qbh.brain import store
    from qbh.brain.planner import BrainPlanner

    async def forged(self, context, plan):
        return TestResult('confirmed', 'forged', [], True)

    monkeypatch.setattr('qbh.brain.strategies.sqli.Strategy.execute_test', forged)
    host = db.upsert_host('127.0.0.1', scan_id=strategy_runtime.scan_id)
    url = planted_app.base + '/search?q=alice'
    db.insert_url(host, url, 'test', scan_id=strategy_runtime.scan_id)
    url_id = db.get_db().execute('SELECT id FROM urls WHERE scan_id=? AND url=?',
                                 (strategy_runtime.scan_id, url)).fetchone()['id']
    await BrainPlanner(strategy_runtime).run()
    row = next(r for r in store.list_plans(strategy_runtime.scan_id)
               if r['url_id'] == url_id and r['vuln_class'] == 'sqli')
    assert row['status'] == 'inconclusive' and row['reason'] == 'confirmation_evidence_incomplete'
    assert not row['finding_id']


async def test_forbidden_technique_skips_plan_before_execution(planted_app, strategy_runtime):
    from qbh.brain import store
    from qbh.brain.planner import BrainPlanner
    strategy_runtime._auth().rules.forbidden.add('sqli')
    host = db.upsert_host('127.0.0.1', scan_id=strategy_runtime.scan_id)
    url = planted_app.base + '/search?q=alice'
    db.insert_url(host, url, 'test', scan_id=strategy_runtime.scan_id)
    url_id = db.get_db().execute('SELECT id FROM urls WHERE scan_id=? AND url=?',
                                 (strategy_runtime.scan_id, url)).fetchone()['id']
    await BrainPlanner(strategy_runtime).run()
    row = next(r for r in store.list_plans(strategy_runtime.scan_id)
               if r['url_id'] == url_id and r['vuln_class'] == 'sqli')
    assert row['status'] == 'skipped' and row['reason'].startswith('authorization:')
    assert not any(q.startswith('alice\'') for _, q in planted_app.hits)


def test_config_canary_validation(load_config, tmp_path):
    canary = tmp_path / 'canary.txt'
    canary.write_text('synthetic-canary-7531', encoding='utf-8')
    cfg = load_config([{'domain': '127.0.0.1', 'in_scope': ['127.0.0.1']}],
                      extra={'lfi_canary_file': str(canary)})
    assert cfg.lfi_canary_file == str(canary)
    with pytest.raises(ConfigError):
        load_config([{'domain': '127.0.0.1', 'in_scope': ['127.0.0.1']}],
                    extra={'lfi_canary_file': 5})
    with pytest.raises(ConfigError):
        load_config([{'domain': '127.0.0.1', 'in_scope': ['127.0.0.1']}],
                    extra={'lfi_canary_file': '   '})

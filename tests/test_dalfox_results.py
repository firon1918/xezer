"""Scanner prose and failed runs must never confirm a vulnerability."""
import pytest
from qbh.adapters.base import ProcResult
from qbh.engines.xss import XSSEngine
from qbh.results import EngineResult


@pytest.mark.asyncio
async def test_negative_tool_prose_is_not_xss(tmp_db, make_ctx, monkeypatch):
    ctx = make_ctx()
    host_id = tmp_db.upsert_host('127.0.0.1', ctx.scan_id)
    async def result(*args, **kwargs):
        return ProcResult(0, b'Target is not vulnerable. No XSS found.')
    monkeypatch.setattr(ctx.egress, 'run', result)
    res = EngineResult(stage='xss')
    await XSSEngine(ctx)._dalfox(dict(host_id=host_id, subdomain='127.0.0.1',
                                    url='http://127.0.0.1/?q=value'), res)
    assert res.findings == 0
    assert tmp_db.get_db().execute('SELECT COUNT(*) FROM findings').fetchone()[0] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('code,timed_out', [(1, False), (0, True)])
async def test_failed_tool_cannot_promote_partial_evidence(tmp_db, make_ctx, monkeypatch, code, timed_out):
    ctx = make_ctx()
    host_id = tmp_db.upsert_host('127.0.0.1', ctx.scan_id)
    async def result(*args, **kwargs):
        return ProcResult(code, b'{"type":"V","cwe":"CWE-79","param":"q",'
                         b'"data":"http://127.0.0.1/?q=x"}', timed_out=timed_out)
    monkeypatch.setattr(ctx.egress, 'run', result)
    res = EngineResult(stage='xss')
    await XSSEngine(ctx)._dalfox(dict(host_id=host_id, subdomain='127.0.0.1',
                                    url='http://127.0.0.1/?q=value'), res)
    assert not res.findings and res.warnings


def test_structured_dom_match_is_candidate_and_deduplicated(tmp_db, make_ctx):
    import json
    ctx = make_ctx()
    host_id = tmp_db.upsert_host('127.0.0.1', ctx.scan_id)
    res = EngineResult(stage='xss')
    item = dict(type='V', cwe='CWE-79', param='q', data='http://127.0.0.1/?q=x',
                message_str='Triggered XSS Payload (found DOM Object)', evidence='<div id=dalfox>')
    output = (json.dumps(item) + '\n') * 2
    XSSEngine(ctx)._ingest_dalfox(output.encode(), dict(host_id=host_id, url='http://127.0.0.1/?q=a'), res)
    assert res.findings == 1
    finding = tmp_db.get_db().execute('SELECT status, evidence FROM findings').fetchone()
    assert finding['status'] == 'candidate' and 'DOM Object' in finding['evidence']


def test_malformed_or_foreign_records_cannot_create_findings(tmp_db, make_ctx):
    import json
    ctx = make_ctx()
    host_id = tmp_db.upsert_host('127.0.0.1', ctx.scan_id)
    res = EngineResult(stage='xss')
    records = [None, {'type': []}, {'type': 'V', 'cwe': 'CWE-79', 'data': []},
               {'type': 'V', 'cwe': 'CWE-79', 'data': 'http://example.com/?q=x', 'param': 'q'},
               {'type': 'V', 'cwe': 'CWE-79', 'data': 'http://127.0.0.1/?q=x', 'param': []}]
    output = '\n'.join(map(json.dumps, records)).encode()
    XSSEngine(ctx)._ingest_dalfox(output, dict(host_id=host_id, url='http://127.0.0.1/?q=x'), res)
    assert res.findings == 0

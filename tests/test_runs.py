import json
import shutil
from pathlib import Path

import pytest
from flask import Flask

from rulezet_tester import FolderSampleStore, Sandbox, TestError, TestService, outcome
from rulezet_tester.web import create_blueprint

yara = pytest.importorskip('yara')

SHIPPED = Path(__file__).resolve().parents[1] / 'samples'
RULE = 'rule t { strings: $mz = "MZ" $u = "powershell" wide $lic = "GNU" condition: any of them }'
SANDBOXES = ['process'] + (['bwrap'] if shutil.which('bwrap') else [])


def run_now(fn):
    """Synchronous executor: the run is finished when start() returns."""
    fn()


def service(mode='process', **kw):
    return TestService(FolderSampleStore(SHIPPED), Sandbox(mode=mode), executor=run_now, **kw)


def by_label(run):
    return {s['label']: s for s in run['samples']}


def test_outcome_table():
    assert outcome('match', 'match') == 'detected'
    assert outcome('match', 'no_match') == 'missed'
    assert outcome('no_match', 'match') == 'false_positive'
    assert outcome('no_match', 'no_match') == 'clean'
    assert outcome('unknown', 'match') == 'matched'
    assert outcome('match', 'timeout') == 'timeout'
    assert outcome('match', 'pending') is None


def test_store_lists_shipped_sets():
    store = FolderSampleStore(SHIPPED)
    sets = {s['id']: s for s in store.sets('yara')}
    assert sets['benign-text']['kind'] == 'benign'
    assert sets['synthetic-yara']['count'] == 5
    assert store.sets('sigma') == []
    samples = store.samples('benign-text')
    assert all(s['expected'] == 'no_match' and len(s['sha256']) == 64 for s in samples)


def test_store_refuses_paths_outside_the_set(tmp_path):
    d = tmp_path / 'evil'
    d.mkdir()
    (d / 'set.json').write_text(json.dumps({'name': 'x', 'format': 'yara', 'kind': 'benign'}))
    (d / 'samples.json').write_text(json.dumps([{'file': '../../etc/passwd'}, {'file': 'set.json/../set.json'}]))
    store = FolderSampleStore(tmp_path)
    assert store.samples('evil') == []
    assert store.samples('../evil') == []


@pytest.mark.parametrize('mode', SANDBOXES)
def test_run_reports_matches_and_false_positives(mode):
    svc = service(mode)
    run = svc.start('yara', RULE, ['synthetic-yara', 'benign-text'], owner=1)
    run = svc.state(run['id'], owner=1)
    assert run['status'] == 'done', run['error']
    samples = by_label(run)
    assert samples['PE header (MZ + DOS stub)']['outcome'] == 'matched'
    assert samples['PE header (MZ + DOS stub)']['hits'][0]['where'] == {'kind': 'offset', 'offset': 0, 'length': 2}
    assert samples['gnu_agpl_license.txt']['outcome'] == 'false_positive'
    assert samples['backup.sh']['outcome'] == 'clean'
    assert run['summary']['false_positives'] == 1
    benign = next(s for s in run['sets'] if s['id'] == 'benign-text')
    assert benign['done'] == benign['total'] == 4 and benign['false_positives'] == 1
    assert 'path' not in run['samples'][0]


def test_run_is_private_to_its_owner():
    svc = service()
    run = svc.start('yara', RULE, ['benign-text'], owner=1)
    assert svc.state(run['id'], owner=2) is None
    assert svc.state(run['id'], owner=1)['status'] == 'done'


def test_compile_error_fails_the_run():
    svc = service()
    run = svc.state(svc.start('yara', 'rule broken { condition: $nope }', ['benign-text'])['id'])
    assert run['status'] == 'failed'
    assert 'undefined string' in run['error']
    assert all(s['verdict'] == 'error' for s in run['samples'])


@pytest.mark.parametrize('text, sets, message', [
    ('', ['benign-text'], 'No rule'),
    (RULE, [], 'at least one'),
    (RULE, ['nope'], 'at least one'),
    ('include "/etc/passwd"\n' + RULE, ['benign-text'], 'include'),
    ('x' * 600_000, ['benign-text'], 'too large'),
])
def test_start_refuses(text, sets, message):
    with pytest.raises(TestError, match=message):
        service().start('yara', text, sets)


def test_unknown_format():
    with pytest.raises(TestError, match='No test engine'):
        service().start('sigma', 'title: x', ['benign-text'])


def test_unavailable_sandbox_hides_tests():
    svc = TestService(FolderSampleStore(SHIPPED), Sandbox(mode='nope'), executor=run_now)
    assert svc.formats() == []
    with pytest.raises(TestError, match='not available'):
        svc.start('yara', RULE, ['benign-text'])


def test_slow_rule_times_out_per_sample(tmp_path):
    d = tmp_path / 'big'
    d.mkdir()
    (d / 'set.json').write_text(json.dumps({'name': 'big', 'format': 'yara', 'kind': 'benign'}))
    (d / 'data.bin').write_bytes(b'a' * 2_000_000)
    svc = TestService(FolderSampleStore(tmp_path), Sandbox(mode='process', sample_timeout=1), executor=run_now)
    slow = 'rule slow { strings: $r = /a.*a.*a.*b/ condition: $r }'
    run = svc.state(svc.start('yara', slow, ['big'])['id'])
    assert run['samples'][0]['verdict'] in ('timeout', 'no_match')


def test_wall_clock_limit_kills_the_worker(tmp_path):
    svc = TestService(FolderSampleStore(SHIPPED), Sandbox(mode='process', command=['sh', '-c', 'sleep 30', '--'], wall_seconds=1),
                      executor=run_now)
    run = svc.state(svc.start('yara', RULE, ['benign-text'])['id'])
    assert run['status'] == 'failed'
    assert 'stopped' in run['error']


def test_blueprint_endpoints():
    app = Flask(__name__)
    owner = {'id': 7}
    app.register_blueprint(create_blueprint(service(), owner=lambda: owner['id']), url_prefix='/test')
    c = app.test_client()
    sets = c.get('/test/sets?format=yara').json
    assert sets['available'] and {s['id'] for s in sets['sets']} >= {'benign-text', 'synthetic-yara'}
    assert c.get('/test/sets?format=sigma').json == {'available': False, 'sets': []}
    res = c.post('/test/', json={'format': 'yara', 'text': RULE, 'sets': ['benign-text']})
    assert res.status_code == 202
    run_id = res.json['id']
    assert c.get(f'/test/{run_id}').json['status'] == 'done'
    owner['id'] = 8
    assert c.get(f'/test/{run_id}').status_code == 404
    assert c.post('/test/', json={'format': 'yara', 'text': RULE}).status_code == 400
    assert c.post('/test/', json={'format': 'yara', 'text': '', 'sets': ['benign-text']}).status_code == 400


def test_cli_run_exit_code(tmp_path, capsys):
    from rulezet_tester.cli import main
    rule = tmp_path / 'r.yar'
    rule.write_text(RULE)
    assert main(['run', str(rule), '--set', 'benign-text', '--sandbox', 'process']) == 1     # GNU licence: false positive
    assert 'FALSE POSITIVE' in capsys.readouterr().out
    rule.write_text('rule quiet { strings: $a = "never-present-xyz" condition: $a }')
    assert main(['run', str(rule), '--set', 'benign-text', '--sandbox', 'process']) == 0

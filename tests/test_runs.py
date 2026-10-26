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
    assert samples['PE header (MZ + DOS stub)']['hits'][0]['data'] == '4d5a'          # "MZ", nothing around it
    assert samples['gnu_agpl_license.txt']['outcome'] == 'false_positive'
    lic = samples['gnu_agpl_license.txt']
    first = lic['hits'][0]
    assert bytes.fromhex(first['before']).endswith(b' ') or first['before'] == '' or len(bytes.fromhex(first['before'])) <= 32
    assert 0 < len(bytes.fromhex(first['after'])) <= 32
    assert lic['hit_total'] >= len(lic['hits']) and all(h['data'] == b'GNU'.hex() for h in lic['hits'])
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


def test_synthetic_pe_files_are_real_pe_with_their_traits():
    pe = yara.compile(source='''import "pe"
        rule inj { condition: pe.imports("kernel32.dll", "CreateRemoteThread") }
        rule upx { condition: for any s in pe.sections : (s.name == "UPX0") }
        rule dl  { condition: pe.imports("urlmon.dll", "URLDownloadToFileA") }''')
    d = SHIPPED / 'synthetic-pe'
    hits = lambda name: {m.rule for m in pe.match(str(d / name))}   # noqa: E731
    assert hits('pe_minimal.exe') == set()
    assert hits('pe_injection_imports.exe') == {'inj'}
    assert hits('pe_packed_upx_like.exe') == {'upx'}
    assert hits('pe_downloader.exe') == {'dl'}


def test_shipped_samples_stay_inert():
    """No real hosts, no EICAR: only reserved .test / .invalid names and TEST-NET addresses."""
    import re
    blob = b''.join(p.read_bytes() for p in SHIPPED.glob('synthetic-*/*'))
    assert b'EICAR' not in blob
    for host in re.findall(rb'https?://([^/\s\'"]+)', blob):
        assert host.endswith((b'.test', b'.invalid')) or host.startswith(b'192.0.2.'), host


def test_benign_set_copies_system_files_only(tmp_path):
    from rulezet_tester.benign import build
    n = build(tmp_path / 'benign-linux', max_files=20)
    assert n > 0
    store = FolderSampleStore(tmp_path)
    assert store.sets('yara')[0]['kind'] == 'benign'
    labels = [s['label'] for s in store.samples('benign-linux')]
    assert all(': /usr/' in label for label in labels)
    assert not any(p.stat().st_mode & 0o111 for p in (tmp_path / 'benign-linux').iterdir())


# ── encrypted (real malware) sets ────────────────────────────────────────────────────

def _encrypted_set(root, items, password='infected', set_id='mal-test'):
    """items: [(zip name, [(member name, bytes)], declared sha256)]"""
    import hashlib
    pyzipper = pytest.importorskip('pyzipper')
    d = root / set_id
    d.mkdir()
    (d / 'set.json').write_text(json.dumps({'name': 'Encrypted', 'format': 'yara', 'kind': 'malicious',
                                            'encrypted': True, 'password': password}))
    listing = []
    for name, members, sha in items:
        with pyzipper.AESZipFile(d / name, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
            z.setpassword(password.encode())
            for member, data in members:
                z.writestr(member, data)
        listing.append({'file': name, 'sha256': sha or hashlib.sha256(members[0][1]).hexdigest(), 'label': name})
    (d / 'samples.json').write_text(json.dumps(listing))
    return d


INJECTION = 'import "pe"\nrule inj { condition: pe.imports("kernel32.dll", "CreateRemoteThread") }'


@pytest.mark.parametrize('mode', SANDBOXES)
def test_encrypted_samples_are_scanned_in_memory(tmp_path, mode):
    pe = (SHIPPED / 'synthetic-pe' / 'pe_injection_imports.exe').read_bytes()
    clean = (SHIPPED / 'synthetic-pe' / 'pe_minimal.exe').read_bytes()
    d = _encrypted_set(tmp_path, [('a.zip', [('sample', pe)], None), ('b.zip', [('sample', clean)], None)])
    store = FolderSampleStore(tmp_path)
    assert store.sets('yara')[0]['encrypted'] is True
    assert 'password' not in json.dumps(store.sets('yara')) and 'infected' not in json.dumps(store.sets('yara'))
    svc = TestService(store, Sandbox(mode=mode), executor=run_now)
    run = svc.state(svc.start('yara', INJECTION, ['mal-test'])['id'])
    assert run['status'] == 'done', run['error']
    out = {s['label']: s['outcome'] for s in run['samples']}
    assert out == {'a.zip': 'detected', 'b.zip': 'missed'}
    assert 'infected' not in json.dumps(run)                       # the password never leaves the store
    assert sorted(p.name for p in d.iterdir()) == ['a.zip', 'b.zip', 'samples.json', 'set.json']   # nothing extracted


def test_encrypted_samples_refuse_tampering_and_bombs(tmp_path):
    pe = (SHIPPED / 'synthetic-pe' / 'pe_injection_imports.exe').read_bytes()
    _encrypted_set(tmp_path, [
        ('wrong_hash.zip', [('sample', pe)], 'ab' * 32),
        ('two_files.zip', [('a', pe), ('b', pe)], None),
        ('bomb.zip', [('sample', b'\0' * (70 * 1024 * 1024))], None),
    ])
    svc = TestService(FolderSampleStore(tmp_path), Sandbox(mode='process'), executor=run_now)
    run = svc.state(svc.start('yara', INJECTION, ['mal-test'])['id'])
    errors = {s['label']: s.get('error') or '' for s in run['samples']}
    assert all(s['verdict'] == 'error' for s in run['samples'])
    assert 'sha256 mismatch' in errors['wrong_hash.zip']
    assert 'exactly one file' in errors['two_files.zip']
    assert 'too large' in errors['bomb.zip']


def test_wrong_password_is_an_error_not_a_crash(tmp_path):
    pe = (SHIPPED / 'synthetic-pe' / 'pe_minimal.exe').read_bytes()
    d = _encrypted_set(tmp_path, [('a.zip', [('sample', pe)], None)])
    meta = json.loads((d / 'set.json').read_text())
    (d / 'set.json').write_text(json.dumps({**meta, 'password': 'wrong'}))
    svc = TestService(FolderSampleStore(tmp_path), Sandbox(mode='process'), executor=run_now)
    run = svc.state(svc.start('yara', INJECTION, ['mal-test'])['id'])
    assert run['samples'][0]['verdict'] == 'error' and 'cannot decrypt' in run['samples'][0]['error']


# ── lab VM: agent + client (SSH replaced by a local process speaking the same protocol) ──

import sys  # noqa: E402


def _lab(tmp_path, sandbox='process'):
    pe = (SHIPPED / 'synthetic-pe' / 'pe_injection_imports.exe').read_bytes()
    root = tmp_path / 'samples'
    root.mkdir()
    _encrypted_set(root, [('a.zip', [('sample', pe)], None)])
    config = tmp_path / 'lab.json'
    config.write_text(json.dumps({'samples': [str(root)], 'include_shipped': True, 'sandbox': sandbox}))
    from rulezet_tester import RemoteLab
    return RemoteLab('lab', command=[sys.executable, '-m', 'rulezet_tester.cli', 'lab-agent', '--config', str(config)]), config


def test_remote_lab_end_to_end(tmp_path):
    lab, _ = _lab(tmp_path)
    assert lab.check() is None and 'yara' in lab.formats()
    svc = TestService(lab, lab, executor=run_now)
    assert {'mal-test', 'benign-text'} <= {s['id'] for s in svc.sets('yara')}
    assert all('path' not in s and 'zip' not in s for s in lab.samples('mal-test'))
    run = svc.state(svc.start('yara', INJECTION, ['mal-test', 'benign-text'])['id'])
    assert run['status'] == 'done', run['error']
    assert run['summary']['detected'] == 1 and run['summary']['false_positives'] == 0
    assert 'infected' not in json.dumps(run)


@pytest.mark.parametrize('request_, message', [
    ({'op': 'shell'}, 'unknown request'),
    ({'op': 'run', 'format': 'yara', 'rule': 'rule a { condition: true }', 'samples': ['../../etc/passwd']}, 'invalid sample list'),
    ({'op': 'run', 'format': 'yara', 'rule': 'rule a { condition: true }', 'samples': ['benign-text/nope']}, 'unknown samples'),
    ({'op': 'run', 'format': 'yara', 'rule': 'include "/etc/passwd"', 'samples': ['benign-text/backup.sh']}, 'include'),
    ({'op': 'run', 'format': 'yara', 'rule': 'x' * 600_000, 'samples': ['benign-text/backup.sh']}, 'invalid rule'),
    ({'op': 'ping', 'path': '/etc'}, 'unexpected fields'),
])
def test_agent_refuses_bad_requests(tmp_path, request_, message):
    import io
    from rulezet_tester.lab import agent
    _, config = _lab(tmp_path)
    out = io.StringIO()
    assert agent(str(config), stdin=io.StringIO(json.dumps(request_)), out=out) != 0
    assert message in json.loads(out.getvalue().splitlines()[0])['message']


def test_agent_refuses_huge_requests(tmp_path):
    import io
    from rulezet_tester.lab import agent
    _, config = _lab(tmp_path)
    out = io.StringIO()
    assert agent(str(config), stdin=io.StringIO('x' * (1024 * 1024 + 10)), out=out) == 2
    assert 'too large' in out.getvalue()


def test_remote_lab_unreachable():
    from rulezet_tester import RemoteLab
    lab = RemoteLab('lab', command=['false'])
    assert lab.check() == 'the lab VM does not answer'
    svc = TestService(lab, lab, executor=run_now)
    assert svc.formats() == []
    with pytest.raises(TestError, match='not available'):
        svc.start('yara', RULE, ['benign-text'])


def test_ssh_command_is_locked_down():
    from rulezet_tester import RemoteLab
    argv = RemoteLab('rzlab@lab', key='/k', known_hosts='/kh').argv
    joined = ' '.join(argv)
    for opt in ('BatchMode=yes', 'StrictHostKeyChecking=yes', 'ForwardAgent=no', 'ClearAllForwardings=yes',
                'IdentitiesOnly=yes', 'UserKnownHostsFile=/kh', 'GlobalKnownHostsFile=/dev/null'):
        assert opt in joined
    assert argv[-2:] == ['--', 'rzlab@lab'] and '-T' in argv


# ── MalwareBazaar import (network mocked: the test never downloads anything) ──────────

def test_fetch_bazaar_keeps_samples_encrypted(tmp_path):
    import hashlib
    import io
    import urllib.parse
    pyzipper = pytest.importorskip('pyzipper')
    from rulezet_tester.bazaar import fetch
    pe = (SHIPPED / 'synthetic-pe' / 'pe_injection_imports.exe').read_bytes()
    sha = hashlib.sha256(pe).hexdigest()
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, 'w', encryption=pyzipper.WZ_AES) as z:
        z.setpassword(b'infected')
        z.writestr(f'{sha}.exe', pe)
    calls = []

    class Res(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): pass

    def opener(req, timeout):
        fields = dict(urllib.parse.parse_qsl(req.data.decode()))
        calls.append((fields['query'], req.headers.get('Auth-key')))
        if fields['query'] == 'get_siginfo':
            return Res(json.dumps({'query_status': 'ok', 'data': [
                {'sha256_hash': sha, 'file_size': len(pe), 'file_type': 'exe', 'signature': 'TestFamily'},
                {'sha256_hash': 'f' * 64, 'file_size': 999_999_999},               # too large: skipped
            ]}).encode())
        return Res(buf.getvalue())

    root = tmp_path / 'samples'
    dest = root / 'testfamily'
    assert fetch(dest, 'KEY', signature='TestFamily', allowed_roots=[root], opener=opener, log=lambda *a: None) == 1
    assert [c[0] for c in calls] == ['get_siginfo', 'get_file'] and calls[0][1] == 'KEY'
    files = sorted(p.name for p in dest.iterdir())
    assert files == [f'{sha}.zip', 'samples.json', 'set.json']                 # nothing decrypted on disk
    assert (dest / f'{sha}.zip').read_bytes() == buf.getvalue()
    assert not (dest / f'{sha}.zip').stat().st_mode & 0o222                    # read-only
    # and it runs: decrypted in memory by the sandboxed worker
    svc = TestService(FolderSampleStore(root), Sandbox(mode='process'), executor=run_now)
    run = svc.state(svc.start('yara', INJECTION, ['testfamily'])['id'])
    assert run['summary']['detected'] == 1
    # again: nothing new
    assert fetch(dest, 'KEY', signature='TestFamily', allowed_roots=[root], opener=opener, log=lambda *a: None) == 0


def test_fetch_bazaar_refuses_outside_the_lab_folders(tmp_path):
    from rulezet_tester.bazaar import BazaarError, fetch
    with pytest.raises(BazaarError, match='not inside'):
        fetch(tmp_path / 'elsewhere' / 'x', 'KEY', signature='X', allowed_roots=[tmp_path / 'samples'])
    with pytest.raises(BazaarError, match='either'):
        fetch(tmp_path / 'samples' / 'x', 'KEY', allowed_roots=[tmp_path / 'samples'], opener=lambda *a, **k: None)


def test_system_folder_set_scans_usr_bin_in_place(tmp_path):
    store = FolderSampleStore(SHIPPED)
    s = next(x for x in store.sets('yara') if x['id'] == 'benign-usr-bin')
    assert s['kind'] == 'benign' and 0 < s['count'] <= 500
    samples = store.samples('benign-usr-bin')
    assert all(x['path'].startswith('/usr/') and x['expected'] == 'no_match' for x in samples)
    assert not (SHIPPED / 'benign-usr-bin').joinpath('samples.json').exists()      # nothing copied
    svc = TestService(store, Sandbox(mode='process'), executor=run_now, max_samples=1000)
    elf = 'rule elf { condition: uint32(0) == 0x464c457f }'
    run = svc.state(svc.start('yara', elf, ['benign-usr-bin'])['id'])
    assert run['status'] == 'done' and run['summary']['false_positives'] > 0        # every ELF matches: too broad


def test_system_folder_must_stay_under_usr(tmp_path):
    for bad in ('/etc', '/home', str(tmp_path), '/usr/../etc'):
        d = tmp_path / 'sets' / bad.strip('/').replace('/', '_').replace('.', 'x')
        d.mkdir(parents=True)
        (d / 'set.json').write_text(json.dumps({'name': 'x', 'format': 'yara', 'kind': 'benign', 'path': bad}))
    store = FolderSampleStore(tmp_path / 'sets')
    for s in store.sets('yara'):
        assert all(not x['path'].startswith(('/etc', '/home', str(tmp_path))) for x in store.samples(s['id']))


def test_remote_lab_does_not_trust_the_vm():
    import sys as _sys
    from rulezet_tester import RemoteLab
    from rulezet_tester import remote
    big = RemoteLab('lab', command=[_sys.executable, '-c', f"print('x' * {remote.MAX_LINE + 10})"])
    assert list(big._stream({'op': 'ping'}, 10)) == [{'event': 'error', 'message': 'the lab VM sent an oversized answer'}]
    junk = RemoteLab('lab', command=[_sys.executable, '-c', "print('[1,2]'); print('not json'); print('{\"ok\": true}')"])
    assert list(junk._stream({'op': 'ping'}, 10)) == [{'ok': True}]

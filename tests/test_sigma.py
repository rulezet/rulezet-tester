"""Sigma driver: pySigma parses the rule, the driver evaluates its condition tree on JSON events."""
import json
import shutil
from pathlib import Path

import pytest

from rulezet_tester import FolderSampleStore, Sandbox, TestService
from rulezet_tester.drivers import DriverError, get_driver

pytest.importorskip('sigma')

SHIPPED = Path(__file__).resolve().parents[1] / 'samples'
SANDBOXES = ['process'] + (['bwrap'] if shutil.which('bwrap') else [])

RULE = """title: Certutil Download
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\\\\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'urlcache'
            - 'http'
    filter_local:
        CommandLine|contains: 'http://127.0.0.1'
    condition: all of selection_* and not filter_local
level: high
"""


def run(rule, events, tmp_path):
    d = get_driver('sigma')
    path = tmp_path / 'events.jsonl'
    path.write_text('\n'.join(json.dumps(e) for e in events))
    return d.run(d.prepare(rule), str(path), 5)


def test_match_case_insensitive_filter_and_hit_shape(tmp_path):
    r = run(RULE, [
        {'Image': 'C:\\Windows\\System32\\CERTUTIL.EXE', 'CommandLine': 'certutil -urlcache -f http://x/a'},
        {'Image': 'C:\\Windows\\System32\\certutil.exe', 'CommandLine': 'certutil -urlcache http://127.0.0.1/a'},
        {'Image': 'C:\\Windows\\notepad.exe', 'CommandLine': 'notepad urlcache http'},
    ], tmp_path)
    assert r['verdict'] == 'match' and r['hit_total'] == 1
    hit = r['hits'][0]
    assert hit['rule'] == 'Certutil Download'
    assert hit['item'] == 'selection_img, selection_cli'
    assert hit['where']['kind'] == 'event' and hit['where']['index'] == 0
    assert set(hit['where']['fields']) >= {'Image', 'CommandLine'}


@pytest.mark.parametrize('detection, event, expected', [
    ("sel:\n        CommandLine|windash|contains: '-enc'", {'CommandLine': 'powershell /enc AAA'}, True),
    ("sel:\n        Port|gt: 1000", {'Port': '8080'}, True),
    ("sel:\n        Port|lt: 1000", {'Port': 8080}, False),
    ("sel:\n        Ip|cidr: 10.0.0.0/8", {'Ip': '10.2.3.4'}, True),
    ("sel:\n        Ip|cidr: 10.0.0.0/8", {'Ip': '192.168.1.1'}, False),
    ("sel:\n        User|re: '^SYS'", {'User': 'SYSTEM'}, True),
    ("sel:\n        User|re|i: '^sys'", {'User': 'SYSTEM'}, True),
    ("sel:\n        Name|cased: 'Admin'", {'Name': 'admin'}, False),
    ("sel:\n        Name: 'Admin'", {'Name': 'admin'}, True),
    ("sel:\n        Opt|exists: false", {'Other': 1}, True),
    ("sel:\n        A|fieldref: B", {'A': 'x', 'B': 'X'}, True),
    ("sel:\n        CommandLine|base64offset|contains: 'http'", {'CommandLine': 'echo aHR0cDovL2V4'}, True),
    ("sel:\n        EventID:\n            - 4624\n            - 4625", {'EventID': 4625}, True),
    ("sel:\n        user.name: bob", {'user': {'name': 'bob'}}, True),
    ("sel:\n        - 'evil'", {'msg': 'an EVIL thing'}, True),
    ("sel:\n        Tags: admin", {'Tags': ['user', 'admin']}, True),
])
def test_modifiers(detection, event, expected, tmp_path):
    rule = f"title: M\nlogsource:\n    product: x\ndetection:\n    {detection}\n    condition: sel\n"
    assert (run(rule, [event], tmp_path)['verdict'] == 'match') is expected


def test_several_rules_and_bad_input(tmp_path):
    two = RULE + '---\n' + "title: Other\nlogsource:\n    product: x\ndetection:\n    sel:\n        Port: 22\n    condition: sel\n"
    r = run(two, [{'Port': 22}, {'Image': 'x\\certutil.exe', 'CommandLine': 'urlcache http://a'}], tmp_path)
    assert {h['rule'] for h in r['hits']} == {'Certutil Download', 'Other'}
    with pytest.raises(DriverError):
        get_driver('sigma').prepare('title: x\ndetection:\n    sel:\n        a: b\n    condition: nothing\n')
    bad = tmp_path / 'bad.jsonl'
    bad.write_text('{"a": 1}\nnot json\n')
    d = get_driver('sigma')
    assert d.run(d.prepare(RULE), str(bad), 5)['verdict'] == 'error'


@pytest.mark.parametrize('mode', SANDBOXES)
def test_shipped_sets_through_the_sandbox(mode):
    service = TestService(FolderSampleStore(SHIPPED), Sandbox(mode=mode), executor=lambda fn: fn())
    sets = [s['id'] for s in service.sets('sigma')]
    assert {'synthetic-sigma-windows', 'benign-sigma-windows'} <= set(sets)
    started = service.start('sigma', RULE, sets)
    state = service.registry.get(started['id'])
    assert state['status'] == 'done', state.get('error')
    assert state['summary']['false_positives'] == 0
    lolbins = next(s for s in state['samples'] if s['label'].startswith('process_creation — LOLBins'))
    assert lolbins['verdict'] == 'match' and lolbins['hits'][0]['where']['index'] == 0

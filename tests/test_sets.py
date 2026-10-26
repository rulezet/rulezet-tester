"""Sample sets: file types from bytes, system-folder sets (recursive, by type), add-set."""
import json
import struct
from pathlib import Path

import pytest

from rulezet_tester import samples as samples_mod
from rulezet_tester.addset import AddSetError, add_set
from rulezet_tester.filetypes import detect
from rulezet_tester.samples import FolderSampleStore


def pe_bytes():
    head = bytearray(b'MZ' + b'\0' * 0x3E)
    struct.pack_into('<I', head, 0x3C, 0x40)
    return bytes(head) + b'PE\0\0' + b'\0' * 64


def zip_head(first_name, flags=0):
    return (b'PK\x03\x04' + struct.pack('<HHH', 20, flags, 0) + b'\0' * 16
            + struct.pack('<HH', len(first_name), 0) + first_name)


def test_types_from_bytes():
    assert detect(pe_bytes()) == 'pe'
    assert detect(b'MZ' + b'\0' * 100) is None               # MZ alone is not a PE
    assert detect(b'\x7fELF\x02\x01') == 'elf'
    assert detect(b'%PDF-1.7\n') == 'pdf'
    assert detect(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1') == 'ole'
    assert detect(zip_head(b'[Content_Types].xml')) == 'ooxml'
    assert detect(zip_head(b'readme.txt')) == 'zip'
    assert detect(b'\xd4\xc3\xb2\xa1') == 'pcap' and detect(b'\x0a\x0d\x0d\x0a') == 'pcapng'
    assert detect(b'hello') is None


@pytest.fixture
def system_root(tmp_path, monkeypatch):
    """A fake /usr: system-folder sets only ever read under SYSTEM_ROOTS."""
    root = tmp_path / 'usr'
    (root / 'share' / 'doc' / 'a').mkdir(parents=True)
    (root / 'share' / 'doc' / 'a' / 'manual.pdf').write_bytes(b'%PDF-1.4\n...')
    (root / 'share' / 'doc' / 'a' / 'fake.pdf').write_bytes(b'not a pdf')            # wrong bytes: skipped
    (root / 'share' / 'doc' / 'tool.exe').write_bytes(pe_bytes())
    (root / 'share' / 'doc' / 'notes.txt').write_text('text')
    monkeypatch.setattr(samples_mod, 'SYSTEM_ROOTS', (root,))
    samples_mod._system_cache.clear()
    return root


def make_set(base, set_id, meta):
    d = base / set_id
    d.mkdir(parents=True)
    (d / 'set.json').write_text(json.dumps({'format': 'yara', 'kind': 'benign', **meta}))
    return d


def test_system_set_recursive_by_type(tmp_path, system_root):
    sets = tmp_path / 'sets'
    make_set(sets, 'docs', {'paths': [str(system_root / 'share')], 'recursive': True, 'types': ['pdf']})
    make_set(sets, 'pe', {'paths': [str(system_root / 'share')], 'recursive': True, 'types': ['pe']})
    make_set(sets, 'empty', {'paths': [str(system_root / 'share')], 'recursive': True, 'types': ['pcap']})
    make_set(sets, 'outside', {'paths': ['/etc'], 'recursive': True})
    store = FolderSampleStore(sets)
    assert {s['id']: s['count'] for s in store.sets('yara')} == {'docs': 1, 'pe': 1}   # empty / outside: not offered
    assert [s['label'].endswith('manual.pdf') for s in store.samples('docs')] == [True]
    assert store.samples('pe')[0]['expected'] == 'no_match'


def test_add_benign_set(tmp_path):
    src = tmp_path / 'in'
    (src / 'sub').mkdir(parents=True)
    (src / 'a.dll').write_bytes(pe_bytes())
    (src / 'sub' / 'b.pdf').write_bytes(b'%PDF-1.4\n')
    dest = tmp_path / 'sets' / 'goodware-windows'
    assert add_set(dest, [src], fmt='yara', kind='benign', name='Goodware', labels={'platform': 'windows'}, log=lambda m: None) == 2
    assert add_set(dest, [src / 'a.dll'], fmt='yara', kind='benign', log=lambda m: None) == 0          # same sha: not twice
    listing = json.loads((dest / 'samples.json').read_text())
    assert {e['type'] for e in listing} == {'pe', 'pdf'}
    store = FolderSampleStore(tmp_path / 'sets')
    assert store.sets('yara')[0]['count'] == 2 and store.sets('yara')[0]['name'] == 'Goodware'
    with pytest.raises(AddSetError):
        add_set(dest, [src / 'a.dll'], fmt='yara', kind='synthetic', log=lambda m: None)      # kind differs


def test_symlinks_refused(tmp_path):
    (tmp_path / 'real').write_text('x')
    (tmp_path / 'link').symlink_to(tmp_path / 'real')
    with pytest.raises(AddSetError):
        add_set(tmp_path / 'sets' / 's', [tmp_path / 'link'], fmt='yara', kind='benign', log=lambda m: None)


def test_malicious_only_encrypted_and_only_in_the_lab(tmp_path):
    sha = 'a' * 64
    enc = tmp_path / f'{sha}.zip'
    enc.write_bytes(zip_head(b'sample', flags=1))
    plain = tmp_path / f'{"b" * 64}.zip'
    plain.write_bytes(zip_head(b'sample', flags=0))
    lab = tmp_path / 'lab'
    with pytest.raises(AddSetError):                                       # no lab config
        add_set(lab / 'emotet', [enc], fmt='yara', kind='malicious', log=lambda m: None)
    with pytest.raises(AddSetError):                                       # outside the lab folders
        add_set(tmp_path / 'elsewhere' / 'emotet', [enc], fmt='yara', kind='malicious', allowed_roots=[lab], log=lambda m: None)
    n = add_set(lab / 'emotet', [enc, plain], fmt='yara', kind='malicious', allowed_roots=[lab], log=lambda m: None)
    assert n == 1                                                          # the clear zip is refused
    meta = json.loads((lab / 'emotet' / 'set.json').read_text())
    assert meta['encrypted'] is True and meta['password'] == 'infected'
    assert json.loads((lab / 'emotet' / 'samples.json').read_text())[0]['sha256'] == sha
    assert oct((lab / 'emotet' / f'{sha}.zip').stat().st_mode)[-3:] == '440'


def test_system_sets_can_be_switched_off(tmp_path, system_root):
    sets = tmp_path / 'sets'
    make_set(sets, 'docs', {'paths': [str(system_root / 'share')], 'recursive': True, 'types': ['pdf']})
    assert FolderSampleStore(sets, system_sets=False).sets('yara') == []
    assert FolderSampleStore(sets, system_sets=False).samples('docs') == []

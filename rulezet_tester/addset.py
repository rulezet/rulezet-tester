"""
Add your own samples to a set — any format, any kind — in one command:

    rulezet-tester add-set /srv/samples/goodware-windows --format yara --kind benign \\
        --name "Benign — Windows system files" --label platform=windows  C:/copied/*.dll  ./installers/
    rulezet-tester add-set /srv/rulezet-lab/samples/emotet --format yara --kind malicious \\
        --name "Emotet" --label family=Emotet --config /etc/rulezet-lab/lab.json  ./downloads/*.zip

The set folder is created (set.json) or extended (samples.json); the files are *copied* into it,
read-only. What it never does: open, run or decompress a sample.

benign / synthetic: regular files (folders are walked; symlinks refused), each one recorded with
its sha256, size and type (filetypes.py: pe, pdf, pcap…).

malicious: only for the lab VM (docs/lab.md) — a lab config (--config) is required and the set
must be inside its sample folders. Only encrypted zips are accepted, one sample each, as malware
repositories ship them (password "infected" by default): the zip is never opened here; its
sample's sha256 comes from the file name (<sha256>.zip, the MalwareBazaar convention) or --sha256,
and the sandboxed worker checks it when it decrypts the sample in memory.

The format is free text (yara today; suricata, sigma… later): each format's driver says which
kind of sample it reads (drivers.py: sample_kind), the set only declares it.
"""
import hashlib
import json
import os
import re
import shutil
import struct
from pathlib import Path

from .filetypes import detect_file

KINDS = ('benign', 'malicious', 'synthetic')
_SET_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$')
_FORMAT = re.compile(r'^[a-z0-9][a-z0-9_-]{0,31}$')
_SHA = re.compile(r'^[0-9a-f]{64}$')
MAX_FILE = 50 * 1024 * 1024


class AddSetError(Exception):
    pass


def _sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def _files(sources):
    """Regular files of the given files / folders (walked), symlinks refused."""
    out = []
    for src in sources:
        src = Path(src)
        if src.is_symlink():
            raise AddSetError(f'{src}: symlinks are refused (copy the file itself)')
        if src.is_dir():
            for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
                dirnames.sort()
                for name in sorted(filenames):
                    p = Path(dirpath) / name
                    if not p.is_symlink() and p.is_file():
                        out.append(p)
        elif src.is_file():
            out.append(src)
        else:
            raise AddSetError(f'{src}: not found')
    return out


def _encrypted_single_zip(path):
    """True for a zip whose first entry is encrypted (general purpose flag bit 0) — read from the
    local header only, nothing is decompressed or decrypted."""
    with open(path, 'rb') as f:
        head = f.read(30)
    if len(head) < 30 or head[:4] != b'PK\x03\x04':
        return False
    flags = struct.unpack_from('<H', head, 6)[0]
    return bool(flags & 1)


def add_set(dest, sources, *, fmt, kind, name=None, description='', labels=None, tlp='clear',
            source='', expected=None, sha256=None, password='infected', allowed_roots=None, log=print):
    dest = Path(dest).resolve()
    if not _SET_NAME.match(dest.name):
        raise AddSetError('the set folder name may only use letters, digits, _ . -')
    if kind not in KINDS:
        raise AddSetError(f'kind must be one of {", ".join(KINDS)}')
    if not _FORMAT.match(fmt or ''):
        raise AddSetError('format: lower-case letters, digits, _ -  (yara, suricata…)')
    if expected not in (None, 'match', 'no_match'):
        raise AddSetError('expected must be match or no_match')
    malicious = kind == 'malicious'
    if malicious:
        if allowed_roots is None:
            raise AddSetError('real malware belongs on the lab VM only: give its lab config (--config), see docs/lab.md')
        if not any(Path(r).resolve() in dest.parents for r in allowed_roots):
            raise AddSetError(f'{dest} is not inside the lab sample folders')

    files = _files(sources)
    if not files:
        raise AddSetError('no file to add')
    if sha256 and len(files) != 1:
        raise AddSetError('--sha256 goes with one file only')

    set_json = dest / 'set.json'
    if set_json.is_file():
        meta = json.loads(set_json.read_text(encoding='utf-8'))
        if meta.get('kind') != kind or (meta.get('format') or '').lower() != fmt:
            raise AddSetError(f'{dest.name} is a {meta.get("format")} / {meta.get("kind")} set')
        if meta.get('path') or meta.get('paths'):
            raise AddSetError(f'{dest.name} is a system-folder set: nothing is copied into it')
    else:
        meta = {'name': name or dest.name, 'format': fmt, 'kind': kind, 'description': description,
                'labels': labels or {}, 'tlp': tlp, 'source': source}
        if malicious:
            meta.update(encrypted=True, password=password)

    dest.mkdir(parents=True, exist_ok=True)
    listing_path = dest / 'samples.json'
    listing = json.loads(listing_path.read_text(encoding='utf-8')) if listing_path.is_file() else []
    have = {e.get('sha256') for e in listing if e.get('sha256')}
    taken = {e.get('file') for e in listing}

    added = 0
    for src in files:
        size = src.stat().st_size
        if not 0 < size <= MAX_FILE:
            log(f'skip {src}: size {size}')
            continue
        if malicious:
            if not _encrypted_single_zip(src):
                log(f'skip {src}: not an encrypted zip (malware is only added encrypted)')
                continue
            sha = (sha256 or src.stem).lower()
            if not _SHA.match(sha):
                log(f'skip {src}: name it <sha256>.zip or give --sha256')
                continue
            target_name = f'{sha}.zip'
            entry = {'file': target_name, 'sha256': sha, 'label': src.name}
        else:
            sha = _sha256(src)
            target_name = src.name if src.name not in taken and src.name not in ('set.json', 'samples.json') \
                else f'{sha[:12]}_{src.name}'
            entry = {'file': target_name, 'sha256': sha, 'size': size, 'label': src.name,
                     'type': detect_file(src)}
            if expected:
                entry['expected'] = expected
        if sha in have:
            continue
        target = dest / target_name
        tmp = dest / f'.{target_name}.part'
        shutil.copyfile(src, tmp, follow_symlinks=False)
        os.chmod(tmp, 0o440 if malicious else 0o444)
        os.replace(tmp, target)
        listing.append(entry)
        have.add(sha)
        taken.add(target_name)
        added += 1

    listing_path.write_text(json.dumps(listing, indent=2) + '\n', encoding='utf-8')
    set_json.write_text(json.dumps(meta, indent=2) + '\n', encoding='utf-8')
    return added

"""
Sample stores: where the test samples are and what they are. A store gives metadata and paths;
it never parses a sample (only the sandboxed worker opens them for the engine).

    sets(fmt)          -> [{ id, name, format, kind, description, labels, tlp, source, count }]
    samples(set_id)    -> [{ id, set, label, sha256, size, expected, path }]

kind: 'benign' (must not match: false positives), 'malicious' (should match), 'synthetic'
(crafted test files, each with its own `expected`).

Encrypted sets (real malware): set.json has "encrypted": true (and "password", default
"infected", the convention of malware repositories). Every sample is then a zip holding exactly
one file, listed in samples.json with the sha256 of that file:
    [{ "file": "<sha256>.zip", "sha256": "<sha256>", "label": "...", "size": 12345 }]
The store never opens these zips: only the sandboxed worker decrypts them, in memory, and checks
the sha256 before scanning. On disk the samples stay encrypted (no antivirus alert, no accidental
double-click). An encrypted set must list every sample with its sha256; entries without one are
ignored.

FolderSampleStore reads a folder, one sub-folder per set:

    <root>/<set id>/set.json        { name, format, kind, description?, labels?, tlp?, source? }
    <root>/<set id>/samples.json    optional: [{ file, label?, expected? }]; default: every file
    <root>/<set id>/<files>         named freely; real malware should be named by sha256, no extension

System-folder sets (benign only): set.json has "path": "/usr/bin" (and optionally "max": 500).
The files of that installed system folder are scanned where they are, read-only, without a copy:
the best false-positive check, always up to date with the machine. Only folders under /usr are
accepted (SYSTEM_ROOTS), symlinks are followed only when they stay there, no recursion.

A host with its own database (Rulezet) can subclass SampleStore, or keep the files in a
FolderSampleStore and only add its own metadata on top.
"""
import hashlib
import json
import re
from pathlib import Path

KINDS = ('benign', 'malicious', 'synthetic')
SYSTEM_ROOTS = (Path('/usr'),)
_SET_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$')


def _system_folder(meta):
    """The installed system folder a benign set points at, or None (refused when outside /usr)."""
    raw = meta.get('path')
    if not raw:
        return None
    try:
        folder = Path(raw).resolve()
    except OSError:
        return None
    return folder if folder.is_dir() and any(folder == r or r in folder.parents for r in SYSTEM_ROOTS) else None


def _valid_sha(value):
    return bool(re.fullmatch(r'[0-9a-f]{64}', str(value or '').lower()))


def _public(s):
    """A set as callers see it: never the zip password."""
    return {k: v for k, v in s.items() if not k.startswith('_')}


class SampleStore:
    def sets(self, fmt):
        return []

    def samples(self, set_id):
        return []


def _sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


class FolderSampleStore(SampleStore):
    def __init__(self, *roots, max_size=50 * 1024 * 1024):
        self.roots = [Path(r).resolve() for r in roots if r]
        self.max_size = max_size
        self._hashes = {}

    def _set_dirs(self):
        for root in self.roots:
            if not root.is_dir():
                continue
            for d in sorted(root.iterdir()):
                if d.is_dir() and _SET_ID.match(d.name) and (d / 'set.json').is_file():
                    yield d

    def _read_set(self, d):
        try:
            meta = json.loads((d / 'set.json').read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return None
        kind = meta.get('kind')
        if kind not in KINDS:
            return None
        return {
            'id': d.name, 'name': meta.get('name') or d.name, 'format': (meta.get('format') or '').lower(),
            'kind': kind, 'description': meta.get('description') or '', 'labels': meta.get('labels') or {},
            'tlp': meta.get('tlp') or 'clear', 'source': meta.get('source') or '',
            'encrypted': bool(meta.get('encrypted')),
            '_system': _system_folder(meta) if kind == 'benign' else None,
            '_max': int(meta['max']) if str(meta.get('max', '')).isdigit() else 500,
            '_password': str(meta.get('password') or 'infected') if meta.get('encrypted') else None,
        }

    def _system_entries(self, folder, limit):
        out, seen = [], set()
        for p in sorted(folder.iterdir()):
            try:
                real = p.resolve()
                if real in seen or not real.is_file() or not any(r in real.parents for r in SYSTEM_ROOTS):
                    continue
                seen.add(real)
                size = real.stat().st_size
            except OSError:
                continue
            if 0 < size <= self.max_size:
                out.append(({'file': p.name, 'label': str(p)}, real, size))
            if len(out) >= limit:
                break
        return out

    def _entries(self, d):
        s = self._read_set(d)
        if s and s.get('_system'):
            return self._system_entries(s['_system'], s['_max'])
        listed = d / 'samples.json'
        if listed.is_file():
            try:
                items = json.loads(listed.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                items = []
        else:
            items = [{'file': p.name} for p in sorted(d.iterdir()) if p.is_file() and p.name not in ('set.json', 'samples.json')]
        out = []
        for item in items:
            name = str(item.get('file') or '')
            path = (d / name).resolve()
            # a samples.json entry may never point outside its set folder
            if not name or path.parent != d.resolve() or not path.is_file() or path.name in ('set.json', 'samples.json'):
                continue
            size = path.stat().st_size
            if size > self.max_size:
                continue
            out.append((item, path, size))
        return out

    def sets(self, fmt):
        fmt = (fmt or '').lower()
        out = []
        for d in self._set_dirs():
            s = self._read_set(d)
            if s and (not fmt or s['format'] == fmt):
                count = len([e for e in self._entries(d) if not s['encrypted'] or _valid_sha(e[0].get('sha256'))])
                out.append({**_public(s), 'count': count})
        return out

    def _dir(self, set_id):
        if not _SET_ID.match(str(set_id or '')):
            return None
        return next((d for d in self._set_dirs() if d.name == set_id), None)

    def get_set(self, set_id):
        d = self._dir(set_id)
        s = self._read_set(d) if d else None
        return _public(s) if s else None

    def samples(self, set_id):
        d = self._dir(set_id)
        s = self._read_set(d) if d else None
        if not s:
            return []
        default = {'benign': 'no_match', 'malicious': 'match'}.get(s['kind'], 'unknown')
        out = []
        for item, path, size in self._entries(d):
            expected = item.get('expected') if item.get('expected') in ('match', 'no_match') else default
            label = str(item.get('label') or path.name)
            if s['encrypted']:
                sha = str(item.get('sha256') or '').lower()
                if not _valid_sha(sha) or path.suffix.lower() != '.zip':
                    continue
                out.append({'id': f'{set_id}/{path.name}', 'set': set_id, 'label': label, 'sha256': sha,
                            'size': int(item['size']) if str(item.get('size', '')).isdigit() else None,
                            'expected': expected, 'path': str(path),
                            'zip': {'password': s['_password']}})
                continue
            key = (str(path), path.stat().st_mtime_ns)
            if key not in self._hashes:
                self._hashes[key] = _sha256(path)
            out.append({'id': f"{set_id}/{item.get('file') or path.name}", 'set': set_id, 'label': label,
                        'sha256': self._hashes[key], 'size': size, 'expected': expected, 'path': str(path)})
        return out

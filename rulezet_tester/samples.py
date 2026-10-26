"""
Sample stores: where the test samples are and what they are. A store gives metadata and paths;
it never parses a sample (only the sandboxed worker opens them for the engine).

    sets(fmt)          -> [{ id, name, format, kind, description, labels, tlp, source, count }]
    samples(set_id)    -> [{ id, set, label, sha256, size, expected, path }]

kind: 'benign' (must not match: false positives), 'malicious' (should match), 'synthetic'
(crafted test files, each with its own `expected`).

FolderSampleStore reads a folder, one sub-folder per set:

    <root>/<set id>/set.json        { name, format, kind, description?, labels?, tlp?, source? }
    <root>/<set id>/samples.json    optional: [{ file, label?, expected? }]; default: every file
    <root>/<set id>/<files>         named freely; real malware should be named by sha256, no extension

A host with its own database (Rulezet) can subclass SampleStore, or keep the files in a
FolderSampleStore and only add its own metadata on top.
"""
import hashlib
import json
import re
from pathlib import Path

KINDS = ('benign', 'malicious', 'synthetic')
_SET_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$')


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
        }

    def _entries(self, d):
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
                out.append({**s, 'count': len(self._entries(d))})
        return out

    def _dir(self, set_id):
        if not _SET_ID.match(str(set_id or '')):
            return None
        return next((d for d in self._set_dirs() if d.name == set_id), None)

    def get_set(self, set_id):
        d = self._dir(set_id)
        return self._read_set(d) if d else None

    def samples(self, set_id):
        d = self._dir(set_id)
        s = self._read_set(d) if d else None
        if not s:
            return []
        default = {'benign': 'no_match', 'malicious': 'match'}.get(s['kind'], 'unknown')
        out = []
        for item, path, size in self._entries(d):
            key = (str(path), path.stat().st_mtime_ns)
            if key not in self._hashes:
                self._hashes[key] = _sha256(path)
            expected = item.get('expected') if item.get('expected') in ('match', 'no_match') else default
            out.append({'id': f'{set_id}/{path.name}', 'set': set_id, 'label': item.get('label') or path.name,
                        'sha256': self._hashes[key], 'size': size, 'expected': expected, 'path': str(path)})
        return out

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

System-folder sets (benign only): set.json has "path": "/usr/bin" (or "paths": [...]) and
optionally "max": 500. The files of those installed system folders are scanned where they are,
read-only, without a copy: the best false-positive check, always up to date with the machine.
Only folders under /usr are accepted (SYSTEM_ROOTS), symlinks are followed only when they stay
there. With "recursive": true the folders are walked; with "types": ["pdf", "ole"] only files of
those types are kept (recognised from their first bytes, filetypes.py) — e.g. every PDF and Office
document of /usr/share, or later every pcap of a folder for Suricata. "scan_limit" bounds the walk
(default 1000000 names); the list is cached (SYSTEM_CACHE_SECONDS) so a page never waits for it.

A host with its own database (Rulezet) can subclass SampleStore, or keep the files in a
FolderSampleStore and only add its own metadata on top.
"""
import hashlib
import json
import os
import re
import time
from pathlib import Path

from .filetypes import TYPES, detect_file, extensions

KINDS = ('benign', 'malicious', 'synthetic')
SYSTEM_ROOTS = (Path('/usr'),)
SYSTEM_CACHE_SECONDS = 6 * 3600
_system_cache = {}          # (folders, types, recursive, max) -> (time, entries)
_SET_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$')


def _system_folder(meta):
    """The installed system folders a benign set points at ("path" or "paths"), or None: a folder
    outside /usr refuses the whole set."""
    raw = meta.get('paths') or ([meta['path']] if meta.get('path') else [])
    if not raw or not isinstance(raw, list):
        return None
    folders = []
    for item in raw:
        try:
            folder = Path(str(item)).resolve()
        except OSError:
            return None
        if not any(folder == r or r in folder.parents for r in SYSTEM_ROOTS):
            return None
        if folder.is_dir():
            folders.append(folder)
    return tuple(folders) or None


def _inside_system(real):
    return any(r in real.parents for r in SYSTEM_ROOTS)


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
    def __init__(self, *roots, max_size=50 * 1024 * 1024, system_sets=True):
        self.roots = [Path(r).resolve() for r in roots if r]
        self.max_size = max_size
        # system-folder sets show what is installed on the machine (paths, packages): fine on a
        # workstation or the lab VM, never on a public server — the host switches them off there
        self.system_sets = system_sets
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
        if (meta.get('path') or meta.get('paths')) and not self.system_sets:
            return None             # system-folder sets switched off (public server)
        system = _system_folder(meta) if kind == 'benign' else None
        if (meta.get('path') or meta.get('paths')) and not system:
            return None             # points at a system folder that is refused (outside /usr) or missing
        return {
            'id': d.name, 'name': meta.get('name') or d.name, 'format': (meta.get('format') or '').lower(),
            'kind': kind, 'description': meta.get('description') or '', 'labels': meta.get('labels') or {},
            'tlp': meta.get('tlp') or 'clear', 'source': meta.get('source') or '',
            'encrypted': bool(meta.get('encrypted')),
            '_system': system,
            '_max': int(meta['max']) if str(meta.get('max', '')).isdigit() else 500,
            '_recursive': bool(meta.get('recursive')),
            '_types': tuple(t for t in (meta.get('types') or []) if t in TYPES),
            '_scan_limit': int(meta['scan_limit']) if str(meta.get('scan_limit', '')).isdigit() else 1000000,
            '_password': str(meta.get('password') or 'infected') if meta.get('encrypted') else None,
        }

    def _system_entries(self, s):
        key = (s['_system'], s['_types'], s['_recursive'], s['_max'])
        cached = _system_cache.get(key)
        if cached and time.monotonic() - cached[0] < SYSTEM_CACHE_SECONDS:
            return cached[1]
        out = self._walk_system(*key, scan_limit=s['_scan_limit'])
        _system_cache[key] = (time.monotonic(), out)
        return out

    def _walk_system(self, folders, types, recursive, limit, scan_limit):
        exts = extensions(types) if types else None
        out, seen, scanned = [], set(), 0
        # several types: each one gets its share of `max`, so 300 PDFs never crowd out the rest
        share = -(-limit // len(types)) if len(types) > 1 else limit
        per_type = {}

        def consider(p, folder):
            nonlocal scanned
            scanned += 1
            if exts is not None and not p.name.lower().endswith(exts):
                return
            try:
                real = p.resolve()
                if real in seen or not real.is_file() or not _inside_system(real):
                    return
                size = real.stat().st_size
            except OSError:
                return
            if not 0 < size <= self.max_size:
                return
            kind = detect_file(real) if types else None
            if types and (kind not in types or per_type.get(kind, 0) >= share):
                return
            per_type[kind] = per_type.get(kind, 0) + 1
            seen.add(real)
            # id stays short and stable: the path inside its folder (/usr/bin: the program name)
            out.append(({'file': str(p.relative_to(folder)), 'label': str(p)}, real, size))

        for folder in folders:
            if recursive:
                for dirpath, dirnames, filenames in os.walk(folder, followlinks=False):
                    dirnames.sort()
                    for name in sorted(filenames):
                        consider(Path(dirpath) / name, folder)
                        if len(out) >= limit or scanned >= scan_limit:
                            return out
            else:
                for p in sorted(folder.iterdir()):
                    consider(p, folder)
                    if len(out) >= limit or scanned >= scan_limit:
                        return out
        return out

    def _entries(self, d):
        s = self._read_set(d)
        if s and s.get('_system'):
            return self._system_entries(s)
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
                if s.get('_system') and not count:
                    continue            # nothing of that kind on this machine: not offered
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

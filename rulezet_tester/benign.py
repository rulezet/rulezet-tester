"""
Builds a benign sample set from this machine's own system files, for false-positive tests:
ELF programs and libraries, Python modules, package documentation, icons, man pages.

    rulezet-tester benign-set /srv/samples/benign-linux --max 300

Safe by construction: it only *copies* files that are already installed on the machine, from
fixed system folders under /usr (never /home, /etc, /root or /var); nothing is downloaded and
nothing is run. The set is not meant to be committed (licences, size): build it where the
samples live.
"""
import json
import random
import shutil
from pathlib import Path

# (label, folder, glob, max share of the set)
SOURCES = [
    ('ELF program', '/usr/bin', '*', 0.30),
    ('ELF shared library', '/usr/lib/x86_64-linux-gnu', '*.so*', 0.25),
    ('Python module', '/usr/lib/python3', '**/*.py', 0.15),
    ('Package documentation', '/usr/share/doc', '*/copyright', 0.10),
    ('Icon', '/usr/share/icons', '**/*.png', 0.10),
    ('Man page', '/usr/share/man/man1', '*.gz', 0.10),
]
ALLOWED_ROOT = Path('/usr')
MAX_FILE = 5 * 1024 * 1024


def _candidates(folder, pattern):
    base = Path(folder)
    if not base.is_dir():
        # /usr/lib/python3 may be /usr/lib/python3.12 only
        parent = base.parent
        matches = sorted(parent.glob(base.name + '*')) if parent.is_dir() else []
        base = next((m for m in matches if m.is_dir()), None)
        if not base:
            return []
    out = []
    for p in base.glob(pattern):
        try:
            real = p.resolve()
            if (real.is_file() and ALLOWED_ROOT in real.parents and 0 < real.stat().st_size <= MAX_FILE):
                out.append(real)
        except OSError:
            continue
    return sorted(set(out))


def build(dest, max_files=300, seed=42):
    dest = Path(dest).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    rnd = random.Random(seed)
    listing, used = [], set()
    for label, folder, pattern, share in SOURCES:
        files = _candidates(folder, pattern)
        rnd.shuffle(files)
        for src in files[:max(1, int(max_files * share))]:
            name = f'{src.parent.name}__{src.name}'.replace('/', '_')
            if name in used:
                continue
            used.add(name)
            shutil.copyfile(src, dest / name)
            (dest / name).chmod(0o444)            # samples are data: never executable
            listing.append({'file': name, 'label': f'{label}: {src}'})
    (dest / 'set.json').write_text(json.dumps({
        'name': f'Benign — this machine ({len(listing)} system files)', 'format': 'yara', 'kind': 'benign',
        'description': 'Files copied from /usr on the machine that runs the tests: programs, libraries, '
                       'Python modules, docs, icons, man pages. A rule that matches here is too broad.',
        'labels': {'platform': 'linux'}, 'tlp': 'clear', 'source': 'rulezet-tester benign-set',
    }, indent=2) + '\n')
    (dest / 'samples.json').write_text(json.dumps(listing, indent=2) + '\n')
    return len(listing)

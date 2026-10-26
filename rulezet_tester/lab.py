"""
The lab agent: what runs on the isolated lab VM, behind SSH.

Rulezet (or any client, see remote.py) connects with a key that is only allowed to run this
agent (authorized_keys: command="rulezet-tester lab-agent --config ...",restrict). Each SSH
connection carries exactly one JSON request on stdin; the answer is JSON lines on stdout.

    { "op": "ping" }                                   -> { ok, version, formats, unavailable }
    { "op": "sets",    "format": "yara" }              -> { sets: [...] }
    { "op": "samples", "set": "emotet-2025" }          -> { samples: [...] }   (no paths, no passwords)
    { "op": "run", "format": "yara", "rule": "...", "samples": ["set/file", ...] }
                                                       -> the sandbox events, one per line

The agent trusts nothing it receives: one request of at most 1 MB, known keys only, sample ids
resolved against its own store (a client never sends a path), the rule size-capped and run in the
bwrap sandbox like everywhere else. Configuration (root-owned, read-only for the agent user):

    /etc/rulezet-tester/lab.json
    { "samples": ["/srv/rulezet-lab/samples"], "include_shipped": true, "sandbox": "bwrap",
      "memory_mb": 1024, "sample_timeout": 10, "wall_seconds": 900, "max_samples": 2000 }

`rulezet-tester lab-check` verifies the VM before it is used (see docs/lab.md).
"""
import json
import os
import re
import socket
import sys
from pathlib import Path

MAX_REQUEST = 1024 * 1024
MAX_RULE = 512 * 1024
_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[^/\0]{1,255}$')
_KEYS = {'ping': set(), 'sets': {'format'}, 'samples': {'set'}, 'run': {'format', 'rule', 'samples'}}

DEFAULTS = {'samples': [], 'include_shipped': True, 'sandbox': 'bwrap', 'memory_mb': 1024, 'cpu_seconds': 600,
            'sample_timeout': 10, 'wall_seconds': 900, 'max_samples': 2000}


def load_config(path):
    config = dict(DEFAULTS)
    if path:
        config.update(json.loads(Path(path).read_text(encoding='utf-8')))
    return config


def _build(config):
    from .samples import FolderSampleStore
    from .sandbox import Sandbox
    from .web import SAMPLES
    roots = ([SAMPLES] if config['include_shipped'] else []) + list(config['samples'])
    store = FolderSampleStore(*roots)
    sandbox = Sandbox(mode=config['sandbox'], memory_mb=config['memory_mb'], cpu_seconds=config['cpu_seconds'],
                      sample_timeout=config['sample_timeout'], wall_seconds=config['wall_seconds'])
    return store, sandbox


def _emit(obj, out):
    out.write(json.dumps(obj) + '\n')
    out.flush()


def _public_sample(s):
    return {k: v for k, v in s.items() if k not in ('path', 'zip')}


def handle(request, config, out=sys.stdout):
    """Answers one request. Returns the process exit code."""
    from . import __version__
    from .drivers import DRIVERS, get_driver

    def fail(message):
        _emit({'event': 'error', 'message': message}, out)
        return 2

    if not isinstance(request, dict) or request.get('op') not in _KEYS:
        return fail('unknown request')
    op = request['op']
    if set(request) - {'op'} - _KEYS[op]:
        return fail('unexpected fields')
    store, sandbox = _build(config)
    unavailable = sandbox.check()
    formats = [] if unavailable else [f for f, d in DRIVERS.items() if d.available()]

    if op == 'ping':
        _emit({'ok': not unavailable, 'version': __version__, 'formats': formats, 'unavailable': unavailable}, out)
        return 0
    if op == 'sets':
        fmt = str(request.get('format') or '')[:32]
        _emit({'sets': store.sets(fmt) if (fmt in formats or (fmt == '' and formats)) else []}, out)
        return 0
    if op == 'samples':
        set_id = str(request.get('set') or '')[:100]
        _emit({'samples': [_public_sample(s) for s in store.samples(set_id)]}, out)
        return 0

    # run
    fmt = str(request.get('format') or '')[:32]
    rule = request.get('rule')
    ids = request.get('samples')
    if fmt not in formats:
        return fail(f'no test engine for {fmt!r} on the lab')
    if not isinstance(rule, str) or not rule.strip() or len(rule) > MAX_RULE:
        return fail('invalid rule')
    refused = get_driver(fmt).check_rule(rule)
    if refused:
        return fail(refused)
    if not isinstance(ids, list) or not ids or len(ids) > config['max_samples'] \
            or not all(isinstance(i, str) and _ID.match(i) for i in ids):
        return fail('invalid sample list')
    wanted = set(ids)
    resolved = []
    for set_id in sorted({i.split('/', 1)[0] for i in wanted}):
        resolved += [s for s in store.samples(set_id) if s['id'] in wanted]
    if len(resolved) != len(wanted):
        return fail('unknown samples')
    for event in sandbox.run(fmt, rule, resolved):
        _emit(event, out)
    return 0


def agent(config_path=None, stdin=None, out=None):
    """Entry point of the forced SSH command: one request, then exit."""
    stdin = stdin or sys.stdin
    out = out or sys.stdout
    raw = stdin.read(MAX_REQUEST + 1)
    if len(raw) > MAX_REQUEST:
        _emit({'event': 'error', 'message': 'request too large'}, out)
        return 2
    try:
        request = json.loads(raw or '{}')
    except ValueError:
        _emit({'event': 'error', 'message': 'invalid JSON'}, out)
        return 2
    try:
        return handle(request, load_config(config_path), out)
    except Exception as e:                      # never a traceback to the client
        _emit({'event': 'error', 'message': f'lab error ({type(e).__name__})'}, out)
        return 1


# ── lab-check: is this machine fit to hold real malware? ─────────────────────────────

def _can_connect(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check(config_path=None, out=sys.stdout):
    """Runs every check, prints PASS / FAIL lines, returns 0 only when all pass."""
    config = load_config(config_path)
    results = []

    def item(ok, label, detail=''):
        results.append(ok)
        out.write(f"{'PASS' if ok else 'FAIL'}  {label}{f'  ({detail})' if detail else ''}\n")

    item(os.geteuid() != 0, 'the agent does not run as root', f'uid {os.geteuid()}')
    item(config['sandbox'] == 'bwrap', 'sandbox mode is bwrap', config['sandbox'])
    store, sandbox = _build(config)
    reason = sandbox.check()
    item(reason is None, 'bubblewrap is installed', reason or '')
    if reason is None:
        from .drivers import get_driver
        ok, detail = True, ''
        try:
            events = list(sandbox.run('yara', 'rule probe { condition: true }', []))
            ok = any(e.get('event') == 'done' for e in events)
            detail = '' if ok else json.dumps(events)[:200]
        except Exception as e:
            ok, detail = False, type(e).__name__
        item(ok and get_driver('yara') is not None, 'the sandbox starts and YARA runs in it', detail)
    try:
        import pyzipper  # noqa: F401
        item(True, 'pyzipper is installed (encrypted samples)')
    except ImportError:
        item(False, 'pyzipper is installed (encrypted samples)', 'pip install pyzipper')
    for host, port in (('1.1.1.1', 443), ('9.9.9.9', 53), ('mb-api.abuse.ch', 443)):
        item(not _can_connect(host, port), f'no outbound network to {host}:{port}', 'this user can reach the internet')
    for root in config['samples']:
        p = Path(root)
        item(p.is_dir(), f'sample folder exists: {root}')
        if p.is_dir():
            item(not os.access(p, os.W_OK), f'sample folder is read-only for the agent: {root}')
            loose = [f for f in p.rglob('*') if f.is_file() and f.stat().st_mode & 0o111]
            item(not loose, f'no executable file in {root}', f'{len(loose)} found' if loose else '')
            for s in store.sets(''):
                if s.get('kind') == 'malicious':
                    item(bool(s.get('encrypted')), f"malicious set is encrypted: {s['id']}")
    if config_path:
        c = Path(config_path)
        item(not os.access(c, os.W_OK), f'config is read-only for the agent: {config_path}')
    failed = results.count(False)
    out.write(f"\n{'OK' if not failed else f'{failed} check(s) failed'}: {len(results)} checks\n")
    return 0 if not failed else 1

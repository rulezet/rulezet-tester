"""
RemoteLab: the client side of the lab VM. It is both the sample store and the sandbox of a
TestService, so nothing else changes for the caller (Rulezet, the editor server, the CLI):

    lab = RemoteLab('rzlab@lab.internal', key='/etc/rulezet/lab_ed25519',
                    known_hosts='/etc/rulezet/lab_known_hosts')
    service = TestService(lab, lab)

Every call is one SSH connection running the forced command on the VM (see lab.py), with:
  - key authentication only, no agent, no password prompt (BatchMode), host key pinned in a
    dedicated known_hosts file (StrictHostKeyChecking=yes: a changed VM key stops everything);
  - no forwarding of any kind, no tty; the key itself is restricted on the VM side.
The samples never leave the VM; only metadata and verdicts come back.
"""
import json
import subprocess
import threading
import time

from .samples import SampleStore
from .sandbox import SandboxUnavailable

MAX_LINE = 4 * 1024 * 1024          # one answer line from the VM; anything longer is dropped
MAX_LINES = 20000                   # events per call (2000 samples, a few events each, with room)


class RemoteLab(SampleStore):
    def __init__(self, target, key=None, known_hosts=None, port=22, ssh='ssh', connect_timeout=8,
                 wall_seconds=900, cache_seconds=30, command=None):
        self.target = target
        self.wall_seconds = wall_seconds
        self.cache_seconds = cache_seconds
        self._cache = {}
        if command is not None:                 # tests, or another transport with the same protocol
            self.argv = list(command)
            return
        argv = [ssh, '-T', '-p', str(port),
                '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', f'ConnectTimeout={connect_timeout}',
                '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no', '-o', 'ClearAllForwardings=yes',
                '-o', 'PermitLocalCommand=no', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=4']
        if key:
            argv += ['-i', str(key), '-o', 'IdentitiesOnly=yes']
        if known_hosts:
            argv += ['-o', f'UserKnownHostsFile={known_hosts}', '-o', 'GlobalKnownHostsFile=/dev/null']
        self.argv = argv + ['--', target]

    # ── transport ─────────────────────────────────────────────────────────────────
    def _stream(self, request, timeout):
        proc = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)
        timer = threading.Timer(timeout, proc.kill)
        timer.start()
        try:
            proc.stdin.write(json.dumps(request))
            proc.stdin.close()
            # the VM is not trusted either: bounded lines, bounded count, JSON objects only
            for _ in range(MAX_LINES):
                line = proc.stdout.readline(MAX_LINE + 1)
                if not line:
                    break
                if len(line) > MAX_LINE:
                    proc.kill()
                    yield {'event': 'error', 'message': 'the lab VM sent an oversized answer'}
                    break
                try:
                    value = json.loads(line)
                except ValueError:
                    continue
                if isinstance(value, dict):
                    yield value
            proc.wait()
        finally:
            timer.cancel()
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def _call(self, request, timeout=30):
        out = list(self._stream(request, timeout))
        return out[0] if out else None

    def _cached(self, key, fn):
        hit = self._cache.get(key)
        if hit and time.monotonic() - hit[0] < self.cache_seconds:
            return hit[1]
        value = fn()
        self._cache[key] = (time.monotonic(), value)
        return value

    # ── sandbox side ──────────────────────────────────────────────────────────────
    def _ping(self):
        return self._cached('ping', lambda: self._call({'op': 'ping'}, timeout=15) or {})

    def check(self):
        ping = self._ping()
        if not ping:
            return 'the lab VM does not answer'
        return None if ping.get('ok') else (ping.get('unavailable') or ping.get('message') or 'the lab is not ready')

    def formats(self):
        return list(self._ping().get('formats') or [])

    def run(self, fmt, rule, samples):
        if self.check():
            raise SandboxUnavailable(self.check())
        request = {'op': 'run', 'format': fmt, 'rule': rule, 'samples': [s['id'] for s in samples]}
        done = False
        for event in self._stream(request, self.wall_seconds + 30):
            if event.get('event') in ('done', 'error'):
                done = True
            yield event
        if not done:
            yield {'event': 'error', 'message': 'the lab VM stopped answering'}

    # ── store side ────────────────────────────────────────────────────────────────
    def sets(self, fmt):
        return self._cached(f'sets:{fmt}', lambda: (self._call({'op': 'sets', 'format': fmt}) or {}).get('sets') or [])

    def samples(self, set_id):
        return self._cached(f'samples:{set_id}', lambda: (self._call({'op': 'samples', 'set': set_id}) or {}).get('samples') or [])

    def get_set(self, set_id):
        return next((s for s in self.sets('') if s['id'] == set_id), None)

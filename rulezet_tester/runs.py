"""
TestService: start a test run (a document of rules × sample sets) and follow it live.

    service = TestService(FolderSampleStore('/srv/samples'))
    run = service.start('yara', text, ['benign-linux', 'emotet-2025'], owner=user_id)
    service.state(run['id'], owner=user_id)        # poll: samples turn from pending to a verdict

Hooks for the host application (Rulezet), all optional:
  registry    where run states live (default: in memory, one process). Several web processes
              (gunicorn) need a shared one: get(id) / save(run).
  executor    how a run is started: executor(fn) runs fn() in the background (default: a thread
              pool of `max_concurrent`). Rulezet can hand it to its job worker.
  on_finish   called with the final run (store results, notify...).

A run state (sent as is to the browser):
  { id, format, status: queued | running | done | failed, error, created, finished,
    sets:    [{ id, name, kind, labels, total, done, matched, false_positives, missed }],
    samples: [{ id, set, label, sha256, size, expected, verdict, outcome, hits, time_ms }],
    summary: { total, done, detected, missed, false_positives, clean, timeouts, errors } }

verdict: pending | match | no_match | timeout | error
outcome (from expected + verdict): detected | missed | false_positive | clean | matched | not_matched | timeout | error
"""
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from .drivers import get_driver, DRIVERS
from .sandbox import Sandbox, SandboxUnavailable

MAX_RULE_SIZE = 512 * 1024


class TestError(Exception):
    """The run cannot start; the message is for the user."""
    __test__ = False


def outcome(expected, verdict):
    if verdict in ('pending', 'timeout', 'error'):
        return verdict if verdict != 'pending' else None
    hit = verdict == 'match'
    if expected == 'match':
        return 'detected' if hit else 'missed'
    if expected == 'no_match':
        return 'false_positive' if hit else 'clean'
    return 'matched' if hit else 'not_matched'


class MemoryRegistry:
    def __init__(self, ttl=3600, max_runs=500):
        self.ttl = ttl
        self.max_runs = max_runs
        self._runs = {}
        self._lock = threading.Lock()

    def save(self, run):
        with self._lock:
            self._runs[run['id']] = run
            if len(self._runs) > self.max_runs:
                now = time.time()
                for k in [k for k, r in self._runs.items() if r.get('finished') and now - r['finished'] > self.ttl]:
                    del self._runs[k]

    def get(self, run_id):
        with self._lock:
            return self._runs.get(run_id)


class TestService:
    __test__ = False                # not a pytest class

    def __init__(self, store, sandbox=None, registry=None, executor=None, on_finish=None,
                 max_samples=1000, max_concurrent=2, max_rule_size=MAX_RULE_SIZE):
        self.store = store
        self.sandbox = sandbox or Sandbox()
        self.registry = registry or MemoryRegistry()
        self.on_finish = on_finish
        self.max_samples = max_samples
        self.max_rule_size = max_rule_size
        if executor is None:
            pool = ThreadPoolExecutor(max_workers=max_concurrent, thread_name_prefix='rze-test')
            executor = pool.submit
        self.executor = executor

    # ── what can be tested ────────────────────────────────────────────────────────
    def unavailable(self):
        """Why tests cannot run on this server (for admins), or None."""
        return self.sandbox.check()

    def formats(self):
        """Formats that can run: the sandbox's own list when it is remote (the lab VM), else the
        engines installed here."""
        if self.unavailable():
            return []
        remote = getattr(self.sandbox, 'formats', None)
        return remote() if callable(remote) else [f for f, d in DRIVERS.items() if d.available()]

    def sets(self, fmt):
        return self.store.sets(fmt) if fmt in self.formats() else []

    # ── start / follow ────────────────────────────────────────────────────────────
    def start(self, fmt, text, set_ids, owner=None):
        reason = self.unavailable()
        if reason:
            raise TestError('Tests are not available on this server.')
        if fmt not in self.formats():
            raise TestError(f'No test engine for {fmt} on this server.')
        driver = get_driver(fmt)            # None when the engine only exists on the lab VM
        text = text if isinstance(text, str) else ''
        if not text.strip():
            raise TestError('No rule to test.')
        if len(text) > self.max_rule_size:
            raise TestError(f'Rules too large (max {self.max_rule_size // 1024} KB).')
        refused = driver.check_rule(text) if driver else None
        if refused:
            raise TestError(refused)
        known = {s['id']: s for s in self.store.sets(fmt)}
        chosen = [known[i] for i in dict.fromkeys(set_ids or []) if i in known]
        if not chosen:
            raise TestError('Choose at least one sample set.')
        samples = []
        for s in chosen:
            samples += self.store.samples(s['id'])
        if not samples:
            raise TestError('The chosen sets have no samples.')
        if len(samples) > self.max_samples:
            raise TestError(f'Too many samples at once (max {self.max_samples}).')

        run = {
            'id': uuid.uuid4().hex, 'format': fmt, 'owner': owner, 'status': 'queued', 'error': None,
            'created': time.time(), 'finished': None,
            'sets': [{'id': s['id'], 'name': s['name'], 'kind': s['kind'], 'labels': s.get('labels') or {},
                      'total': 0, 'done': 0, 'matched': 0, 'false_positives': 0, 'missed': 0} for s in chosen],
            'samples': [{k: v for k, v in smp.items() if k not in ('path', 'zip')} | {'verdict': 'pending', 'outcome': None, 'hits': [], 'hit_total': 0, 'time_ms': None}
                        for smp in samples],
        }
        for s in run['sets']:
            s['total'] = sum(1 for smp in samples if smp['set'] == s['id'])
        self._summarise(run)
        self.registry.save(run)
        paths = [{k: smp[k] for k in ('id', 'path', 'zip', 'sha256') if k in smp} for smp in samples]
        self.executor(lambda: self._execute(run['id'], fmt, text, paths))
        return self.public(run)

    def state(self, run_id, owner=None):
        run = self.registry.get(run_id)
        if not run or (owner is not None and run.get('owner') != owner):
            return None
        return self.public(run)

    @staticmethod
    def public(run):
        return {k: v for k, v in run.items() if k != 'owner'}

    # ── execution ─────────────────────────────────────────────────────────────────
    def _execute(self, run_id, fmt, text, paths):
        run = self.registry.get(run_id)
        if not run:
            return
        by_id = {s['id']: s for s in run['samples']}
        run['status'] = 'running'
        self.registry.save(run)
        try:
            for event in self.sandbox.run(fmt, text, paths):
                kind = event.get('event')
                if kind == 'sample' and event.get('id') in by_id:
                    smp = by_id[event['id']]
                    smp.update(verdict=event.get('verdict', 'error'), hits=event.get('hits') or [],
                               hit_total=event.get('hit_total', len(event.get('hits') or [])),
                               time_ms=event.get('time_ms'), error=event.get('error'))
                    smp['outcome'] = outcome(smp['expected'], smp['verdict'])
                    self._summarise(run)
                    self.registry.save(run)
                elif kind == 'error':
                    run['error'] = run['error'] or event.get('message') or 'The test failed'
            run['status'] = 'failed' if run['error'] else 'done'
        except SandboxUnavailable:
            run.update(status='failed', error='Tests are not available on this server.')
        except Exception as e:                      # never leave a run "running" forever
            run.update(status='failed', error=f'The test failed ({type(e).__name__})')
        for smp in run['samples']:
            if smp['verdict'] == 'pending':
                smp.update(verdict='error' if run['status'] == 'failed' else 'pending')
                smp['outcome'] = outcome(smp['expected'], smp['verdict'])
        run['finished'] = time.time()
        self._summarise(run)
        self.registry.save(run)
        if self.on_finish:
            try:
                self.on_finish(self.public(run) | {'owner': run.get('owner')})
            except Exception:
                pass

    @staticmethod
    def _summarise(run):
        samples = run['samples']
        count = lambda key, value: sum(1 for s in samples if s.get(key) == value)   # noqa: E731
        for st in run['sets']:
            mine = [s for s in samples if s['set'] == st['id']]
            st.update(done=sum(1 for s in mine if s['verdict'] != 'pending'),
                      matched=sum(1 for s in mine if s['verdict'] == 'match'),
                      false_positives=sum(1 for s in mine if s['outcome'] == 'false_positive'),
                      missed=sum(1 for s in mine if s['outcome'] == 'missed'))
        run['summary'] = {
            'total': len(samples), 'done': sum(1 for s in samples if s['verdict'] != 'pending'),
            'detected': count('outcome', 'detected'), 'missed': count('outcome', 'missed'),
            'false_positives': count('outcome', 'false_positive'), 'clean': count('outcome', 'clean'),
            'timeouts': count('verdict', 'timeout'), 'errors': count('verdict', 'error'),
        }

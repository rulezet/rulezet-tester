"""
Runs worker.py in a sandbox and streams its events.

Isolation (mode 'bwrap', the default, needs bubblewrap: apt install bubblewrap):
  - new namespaces for everything (no network, own pids, no host IPC), dies with its parent;
  - an empty file system with only what Python needs, read-only: the interpreter, its
    libraries, this package, and the sample folders. Nothing else of the machine is visible
    (no .env, no database, no home);
  - /tmp is an empty tmpfs, the environment is cleared, all capabilities dropped;
  - resource limits: memory, CPU time, open files, no file written (RLIMIT_FSIZE = 0);
  - a wall-clock limit for the whole run: the process group is killed when it is reached.

Mode 'process' keeps only the resource limits and the clean environment: for development, or
when the whole service already runs in an isolated machine. It must be chosen explicitly.
A custom `command` (nsjail, a container, ssh to a lab machine...) can replace bwrap: it gets the
worker command appended and must keep stdin / stdout.
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]       # the folder that holds rulezet_tester/


class SandboxUnavailable(Exception):
    pass


class Sandbox:
    def __init__(self, mode='bwrap', command=None, memory_mb=512, cpu_seconds=120, wall_seconds=300,
                 sample_timeout=5, python=None):
        self.mode = mode
        self.command = command
        self.memory_mb = memory_mb
        self.cpu_seconds = cpu_seconds
        self.wall_seconds = wall_seconds
        self.sample_timeout = sample_timeout
        self.python = python or sys.executable

    # ── availability ──────────────────────────────────────────────────────────────
    def check(self):
        """None when runs can start, else the reason (shown to admins, not to users)."""
        if self.command:
            return None
        if self.mode == 'bwrap':
            return None if shutil.which('bwrap') else 'bubblewrap (bwrap) is not installed'
        if self.mode == 'process':
            return None
        return f'unknown sandbox mode {self.mode!r}'

    # ── command line ──────────────────────────────────────────────────────────────
    def _ro_paths(self, sample_dirs):
        paths = {'/usr', '/lib', '/lib64', '/bin', '/etc/ld.so.cache', '/etc/ld.so.conf', '/etc/ld.so.conf.d',
                 sys.prefix, sys.base_prefix, str(PACKAGE_ROOT), str(Path(self.python).resolve().parent)}
        paths |= {p for p in sys.path if p and p.endswith(('site-packages', 'dist-packages'))}
        paths |= {str(d) for d in sample_dirs}
        return sorted(p for p in paths if os.path.exists(p))

    def argv(self, sample_dirs):
        # -I: no environment variables, no user site, no current folder on the path; the package
        # folder is added explicitly (installed or not, the worker runs this very copy)
        boot = (f'import sys; sys.path.insert(0, {str(PACKAGE_ROOT)!r}); import runpy; '
                "runpy.run_module('rulezet_tester.worker', run_name='__main__')")
        worker = [self.python, '-I', '-c', boot]
        if self.command:
            return list(self.command) + worker
        if self.mode == 'process':
            return worker
        args = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
                '--cap-drop', 'ALL', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
                '--chdir', '/tmp']
        for p in self._ro_paths(sample_dirs):
            args += ['--ro-bind', p, p]
        return args + worker

    def _limits(self):
        import resource
        mem = self.memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        resource.setrlimit(resource.RLIMIT_CPU, (self.cpu_seconds, self.cpu_seconds))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    # ── run ───────────────────────────────────────────────────────────────────────
    def run(self, fmt, rule, samples):
        """Yields the worker's events. samples: [{ id, path }], paths readable by this process."""
        reason = self.check()
        if reason:
            raise SandboxUnavailable(reason)
        dirs = {str(Path(s['path']).resolve().parent) for s in samples}
        job = {'format': fmt, 'rule': rule, 'timeout': self.sample_timeout,
               'samples': [{'id': s['id'], 'path': str(Path(s['path']).resolve())} for s in samples]}
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
        proc = subprocess.Popen(self.argv(dirs), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=env, cwd='/tmp', text=True,
                                preexec_fn=self._limits, start_new_session=True)
        killed = threading.Event()

        def kill():
            killed.set()
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        timer = threading.Timer(self.wall_seconds, kill)
        timer.start()
        started = time.monotonic()
        try:
            proc.stdin.write(json.dumps(job))
            proc.stdin.close()
            done = False
            for line in proc.stdout:
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get('event') in ('done', 'error'):
                    done = True
                yield event
            proc.wait()
            if not done:
                if killed.is_set():
                    yield {'event': 'error', 'message': f'The test took more than {self.wall_seconds} s and was stopped'}
                else:
                    yield {'event': 'error', 'message': f'The test engine stopped (exit {proc.returncode}): '
                                                        'out of memory or CPU time, or a crash'}
        finally:
            timer.cancel()
            if proc.poll() is None:
                kill()
                proc.wait()
            self.last_duration = time.monotonic() - started

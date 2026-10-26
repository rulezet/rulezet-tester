"""
Sandboxed worker: the only code that opens a sample. Started by sandbox.py, one process per run:

    stdin   one JSON object { format, rule, samples: [{ id, path }], timeout }
    stdout  one JSON line per event:
              { "event": "error", "message" }                     the rule cannot run
              { "event": "sample", "id", "verdict", "hits", "time_ms", "error"? }
              { "event": "done" }

It never writes a file, never opens the network (the sandbox removes it anyway) and never sends
sample bytes back: only verdicts, rule items and offsets.
"""
import json
import sys
import time


def emit(obj):
    sys.stdout.write(json.dumps(obj) + '\n')
    sys.stdout.flush()


def main():
    from rulezet_tester.drivers import DriverError, get_driver

    job = json.loads(sys.stdin.read() or '{}')
    driver = get_driver(job.get('format'))
    if not driver:
        emit({'event': 'error', 'message': f"No test engine for {job.get('format')!r} here"})
        return
    try:
        prepared = driver.prepare(job.get('rule') or '')
    except DriverError as e:
        emit({'event': 'error', 'message': str(e)})
        return
    timeout = job.get('timeout') or 5
    for sample in job.get('samples') or []:
        start = time.monotonic()
        try:
            result = driver.run(prepared, sample['path'], timeout)
        except Exception as e:          # a driver bug must not stop the other samples
            result = {'verdict': 'error', 'hits': [], 'error': type(e).__name__}
        emit({'event': 'sample', 'id': sample['id'], 'time_ms': int((time.monotonic() - start) * 1000), **result})
    emit({'event': 'done'})


if __name__ == '__main__':
    main()

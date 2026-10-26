"""
Sandboxed worker: the only code that opens a sample. Started by sandbox.py, one process per run:

    stdin   one JSON object { format, rule, samples: [{ id, path }], timeout }
    stdout  one JSON line per event:
              { "event": "error", "message" }                     the rule cannot run
              { "event": "sample", "id", "verdict", "hits", "time_ms", "error"? }
              { "event": "done" }

It never writes a file, never opens the network (the sandbox removes it anyway) and never sends
the sample back: only verdicts, rule items, offsets, the bytes each string matched (≤ 64) and 32
bytes around each match.
"""
import hashlib
import json
import sys
import time

MAX_SAMPLE = 64 * 1024 * 1024        # decrypted size accepted for one sample (zip bombs stop here)


class SampleError(Exception):
    pass


def decrypt(path, password, expected_sha256):
    """The one file inside an encrypted sample zip, in memory. Checked before it is read: exactly
    one regular member, a sane declared size; checked after: the sha256 the set lists."""
    try:
        import pyzipper
    except ImportError as e:
        raise SampleError('encrypted samples need pyzipper (pip install "rulezet-tester[lab]")') from e
    try:
        with pyzipper.AESZipFile(path) as z:
            members = [m for m in z.infolist() if not m.is_dir()]
            if len(members) != 1:
                raise SampleError(f'the zip must hold exactly one file ({len(members)} found)')
            member = members[0]
            if member.file_size > MAX_SAMPLE:
                raise SampleError(f'sample too large once decrypted ({member.file_size} bytes)')
            z.setpassword(password.encode())
            with z.open(member) as f:
                data = f.read(MAX_SAMPLE + 1)
    except SampleError:
        raise
    except Exception as e:
        raise SampleError(f'cannot decrypt the sample ({type(e).__name__})') from e
    if len(data) > MAX_SAMPLE:
        raise SampleError('sample larger than its zip declares')
    if hashlib.sha256(data).hexdigest() != (expected_sha256 or '').lower():
        raise SampleError('sha256 mismatch: the sample is not the one the set lists')
    return data


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
            if sample.get('zip'):
                data = decrypt(sample['path'], sample['zip'].get('password') or 'infected', sample.get('sha256'))
                try:
                    result = driver.run_data(prepared, data, timeout)
                finally:
                    del data
            else:
                result = driver.run(prepared, sample['path'], timeout)
        except SampleError as e:
            result = {'verdict': 'error', 'hits': [], 'error': str(e)}
        except Exception as e:          # a driver bug must not stop the other samples
            result = {'verdict': 'error', 'hits': [], 'error': type(e).__name__}
        emit({'event': 'sample', 'id': sample['id'], 'time_ms': int((time.monotonic() - start) * 1000), **result})
    emit({'event': 'done'})


if __name__ == '__main__':
    main()

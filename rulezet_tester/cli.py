"""
rulezet-tester command line.

    rulezet-tester sets  [--samples DIR] [--format yara]
    rulezet-tester run   rules.yar --set benign-text --set synthetic-yara [--samples DIR] [--json]
    rulezet-tester serve [--samples DIR] [--port 5175]

`run` exits with 1 when a sample gives a false positive or a miss: usable in CI.
"""
import argparse
import json
import sys
from pathlib import Path

SAMPLES = Path(__file__).resolve().parents[1] / 'samples'
MARK = {'detected': 'DETECTED', 'missed': 'MISSED', 'false_positive': 'FALSE POSITIVE', 'clean': 'clean',
        'matched': 'match', 'not_matched': '-', 'timeout': 'TIMEOUT', 'error': 'ERROR'}


def _service(args):
    from .runs import TestService
    from .samples import FolderSampleStore
    from .sandbox import Sandbox
    return TestService(FolderSampleStore(SAMPLES, *args.samples), Sandbox(mode=args.sandbox), executor=lambda fn: fn())


def main(argv=None):
    parser = argparse.ArgumentParser(prog='rulezet-tester')
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--samples', action='append', default=[], help='folder of sample sets (repeatable)')
    common.add_argument('--sandbox', choices=['bwrap', 'process'], default='bwrap',
                        help='bwrap (default) or process (limits only: development)')
    sub = parser.add_subparsers(dest='command', required=True)

    p_sets = sub.add_parser('sets', parents=[common], help='list the sample sets')
    p_sets.add_argument('--format', default='')

    p_run = sub.add_parser('run', parents=[common], help='run a rule file on sample sets')
    p_run.add_argument('rules', type=Path)
    p_run.add_argument('--format', default='yara')
    p_run.add_argument('--set', dest='sets', action='append', default=[], help='set id (repeatable); default: every set of the format')
    p_run.add_argument('--json', action='store_true')

    p_serve = sub.add_parser('serve', parents=[common], help='HTTP API (needs flask)')
    p_serve.add_argument('--host', default='127.0.0.1')
    p_serve.add_argument('--port', type=int, default=5175)

    args = parser.parse_args(argv)

    if args.command == 'sets':
        for s in _service(args).store.sets(args.format):
            print(f"{s['id']:<28} {s['format']:<10} {s['kind']:<10} {s['count']:>5}  {s['name']}")
        return 0

    if args.command == 'run':
        from .runs import TestError
        svc = _service(args)
        if svc.unavailable():
            print(f'Tests unavailable: {svc.unavailable()}', file=sys.stderr)
            return 2
        sets = args.sets or [s['id'] for s in svc.sets(args.format)]
        try:
            run = svc.start(args.format, args.rules.read_text(encoding='utf-8'), sets)
        except TestError as e:
            print(e, file=sys.stderr)
            return 2
        run = svc.state(run['id'])
        if args.json:
            print(json.dumps(run, indent=2))
        else:
            if run['error']:
                print(f"error: {run['error']}")
            for smp in run['samples']:
                items = ', '.join(sorted({h['item'] or h['rule'] for h in smp['hits']}))
                print(f"{MARK.get(smp['outcome'], smp['verdict']):<15} {smp['set']}/{smp['label']}  {items}")
            print(json.dumps(run['summary']))
        bad = run['status'] != 'done' or run['summary']['false_positives'] or run['summary']['missed']
        return 1 if bad else 0

    from .web import create_app
    app = create_app(samples=args.samples, sandbox=args.sandbox)
    print(f'\n  Tests API: http://{args.host}:{args.port}/test/  ({app.config["TEST_SERVICE"].unavailable() or args.sandbox + " sandbox"})\n')
    app.run(host=args.host, port=args.port)
    return 0


if __name__ == '__main__':
    sys.exit(main())

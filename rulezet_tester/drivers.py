"""
Test drivers: one per rule format. A driver runs a rule on one sample and says whether it fired
and where. It only runs inside the sandboxed worker (worker.py), never in the web process.

    prepare(rule_text)               -> compiled rule (once per run), raises DriverError
    run(prepared, path, timeout)     -> { verdict: match | no_match | timeout | error, hits, error? }

A hit is { rule, item, where: { kind, ... } }: `item` is what matched inside the rule (YARA: the
string id), `where` is format-specific (YARA: { kind: 'offset', offset, length }). The verdicts
and the shape are the same for every format; only `where` changes.
"""
import importlib

MAX_HITS = 50                 # per sample: enough to show, never the whole file


class DriverError(Exception):
    """The rule cannot be run (does not compile, forbidden feature)."""


class Driver:
    format = ''
    sample_kind = 'file'      # file | pcap | events | log_lines | http
    module = None             # Python module the engine needs (checked by available())

    def available(self):
        if not self.module:
            return True
        try:
            importlib.import_module(self.module)
            return True
        except ImportError:
            return False

    def check_rule(self, text):
        """Refused before anything runs (also checked in the web process, before queueing)."""
        return None

    def prepare(self, text):
        raise NotImplementedError

    def run(self, prepared, path, timeout):
        raise NotImplementedError


class YaraDriver(Driver):
    format = 'yara'
    sample_kind = 'file'
    module = 'yara'

    def check_rule(self, text):
        import re
        if re.search(r'^\s*include\s+"', text, re.M):
            return 'include is not allowed in tests'
        return None

    def prepare(self, text):
        import yara
        error = self.check_rule(text)
        if error:
            raise DriverError(error)
        try:
            # no include, no external variables: the rule gets nothing from the machine
            return yara.compile(source=text, includes=False)
        except yara.Error as e:
            raise DriverError(str(e)) from e

    def run(self, prepared, path, timeout):
        import yara
        try:
            matches = prepared.match(path, timeout=max(1, int(timeout)), fast=False)
        except yara.TimeoutError:
            return {'verdict': 'timeout', 'hits': []}
        except yara.Error as e:
            return {'verdict': 'error', 'hits': [], 'error': str(e)}
        hits = []
        for m in matches:
            if not m.strings:
                hits.append({'rule': m.rule, 'item': None, 'where': {'kind': 'file'}})
            for s in m.strings:
                for inst in s.instances:
                    if len(hits) >= MAX_HITS:
                        break
                    hits.append({'rule': m.rule, 'item': s.identifier,
                                 'where': {'kind': 'offset', 'offset': inst.offset, 'length': inst.matched_length}})
        return {'verdict': 'match' if matches else 'no_match', 'hits': hits}


DRIVERS = {d.format: d for d in (YaraDriver(),)}


def get_driver(fmt):
    driver = DRIVERS.get((fmt or '').lower())
    return driver if driver and driver.available() else None

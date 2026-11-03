"""
Test drivers: one per rule format. A driver runs a rule on one sample and says whether it fired
and where. It only runs inside the sandboxed worker (worker.py), never in the web process.

    prepare(rule_text)               -> compiled rule (once per run), raises DriverError
    run(prepared, path, timeout)     -> { verdict: match | no_match | timeout | error, hits, error? }

A hit is { rule, item, where: { kind, ... }, data? }: `item` is what matched inside the rule (YARA:
the string id), `where` is format-specific (YARA: { kind: 'offset', offset, length }), `data` the
matched bytes in hex, at most MAX_HIT_BYTES, and `before` / `after` the CONTEXT_BYTES around them
(hex), so a UI can show the match in its surroundings. Never more of the sample than that.
A run result also has `hit_total` when there were more hits than MAX_HITS.
The verdicts and the shape are the same for every format; only `where` changes.
"""
import importlib

MAX_HITS = 50                 # per sample: enough to show, never the whole file
MAX_HIT_BYTES = 64            # matched bytes returned per hit (what the rule's own string matched)
CONTEXT_BYTES = 32            # bytes shown before / after a match, so a reader sees where it hit


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

    def run_data(self, prepared, data, timeout):
        """Same as run() on bytes already in memory (decrypted samples: never written to disk)."""
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
        def read(offset, size):
            with open(path, 'rb') as f:
                f.seek(offset)
                return f.read(size)
        return self._match(prepared, timeout, read, filepath=path)

    def run_data(self, prepared, data, timeout):
        return self._match(prepared, timeout, lambda offset, size: data[offset:offset + size], data=data)

    def _match(self, prepared, timeout, read, **target):
        import yara
        try:
            matches = prepared.match(**target, timeout=max(1, int(timeout)), fast=False)
        except yara.TimeoutError:
            return {'verdict': 'timeout', 'hits': []}
        except yara.Error as e:
            return {'verdict': 'error', 'hits': [], 'error': str(e)}
        hits, total = [], 0
        for m in matches:
            if not m.strings:
                total += 1
                hits.append({'rule': m.rule, 'item': None, 'where': {'kind': 'file'}})
            for s in m.strings:
                for inst in s.instances:
                    total += 1
                    if len(hits) >= MAX_HITS:
                        continue
                    start = max(0, inst.offset - CONTEXT_BYTES)
                    shown = min(inst.matched_length, MAX_HIT_BYTES)
                    try:
                        after = read(inst.offset + inst.matched_length, CONTEXT_BYTES)
                        before = read(start, inst.offset - start)
                    except OSError:
                        before = after = b''
                    hits.append({'rule': m.rule, 'item': s.identifier,
                                 'where': {'kind': 'offset', 'offset': inst.offset, 'length': inst.matched_length},
                                 'data': bytes(inst.matched_data[:shown]).hex(),
                                 'before': before.hex(), 'after': after.hex()})
        return {'verdict': 'match' if matches else 'no_match', 'hits': hits, 'hit_total': total}


MAX_EVENTS = 100_000          # events read from one sample (a JSON Lines log, a JSON array)
MAX_FIELD_CHARS = 200         # characters of a matched field value returned per hit


class SigmaDriver(Driver):
    """Sigma rules on events (JSON Lines: one JSON object per line, or a JSON array / object).

    The rule is parsed by pySigma (the library Rulezet validates with): its condition tree comes
    back with every modifier already applied (contains / startswith / endswith as wildcards,
    windash and base64offset as expansions, re, cidr, gt / lt, exists, fieldref…), and this driver
    only evaluates that tree on each event — so a rule means here exactly what pySigma says.
    Matching is case-insensitive except |cased, as in the Sigma specification. A hit is one
    matching event: item = the search identifiers that matched it, where = { kind: 'event',
    index (0-based event number), fields (the event fields those identifiers looked at) }."""
    format = 'sigma'
    sample_kind = 'events'
    module = 'sigma'

    def check_rule(self, text):
        if 'correlation:' in text and 'detection:' not in text:
            return 'correlation rules are not supported in tests'
        return None

    def prepare(self, text):
        from sigma.collection import SigmaCollection
        from sigma.conditions import SigmaCondition
        from sigma.rule import SigmaRule
        error = self.check_rule(text)
        if error:
            raise DriverError(error)
        try:
            collection = SigmaCollection.from_yaml(text)
        except Exception as e:
            raise DriverError(str(e)) from e
        rules = []
        for rule in collection.rules:
            if not isinstance(rule, SigmaRule):
                continue                      # correlation / filter rules
            try:
                conditions = [c.parsed for c in rule.detection.parsed_condition]
                searches = {name: SigmaCondition(name, rule.detection).parsed for name in rule.detection.detections}
            except Exception as e:
                raise DriverError(f'{rule.title}: {e}') from e
            ls = rule.logsource
            rules.append({'title': rule.title, 'conditions': conditions, 'searches': searches,
                          'logsource': (str(ls.category or '').lower(), str(ls.product or '').lower(), str(ls.service or '').lower())})
        if not rules:
            raise DriverError('No Sigma detection rule in the text')
        return rules

    def run(self, prepared, path, timeout):
        try:
            with open(path, 'rb') as f:
                data = f.read(64 * 1024 * 1024 + 1)
        except OSError as e:
            return {'verdict': 'error', 'hits': [], 'error': str(e)}
        return self.run_data(prepared, data, timeout)

    def run_data(self, prepared, data, timeout):
        import time
        try:
            events = _events(data)
        except ValueError as e:
            return {'verdict': 'error', 'hits': [], 'error': str(e)}
        deadline = time.monotonic() + max(1, timeout)
        hits, total = [], 0
        for index, event in enumerate(events):
            if index % 500 == 0 and time.monotonic() > deadline:
                return {'verdict': 'timeout', 'hits': hits, 'hit_total': total}
            for rule in prepared:
                if not _logsource_fits(rule['logsource'], event):
                    continue
                if not any(_eval(c, event) for c in rule['conditions']):
                    continue
                total += 1
                if len(hits) >= MAX_HITS:
                    continue
                matched = [name for name, tree in rule['searches'].items() if _eval(tree, event)]
                fields = {}
                for name in matched:
                    for field in _fields(rule['searches'][name]):
                        value = _get(event, field)
                        if value is not None:
                            fields[field] = str(value)[:MAX_FIELD_CHARS]
                hits.append({'rule': rule['title'], 'item': ', '.join(matched) or None,
                             'where': {'kind': 'event', 'index': index, 'fields': fields}})
        return {'verdict': 'match' if total else 'no_match', 'hits': hits, 'hit_total': total}


SYSMON = 'microsoft-windows-sysmon/operational'
POWERSHELL = 'microsoft-windows-powershell/operational'
# What a SIEM's Windows pipeline does: a log source category is a set of (channel, EventID). Only
# applied to events that say where they come from (Channel + EventID); other events (a proxy log,
# hand-made samples) are matched as they are.
CATEGORY_EVENTS = {
    'process_creation': {(SYSMON, 1), ('security', 4688)}, 'network_connection': {(SYSMON, 3)},
    'process_termination': {(SYSMON, 5), ('security', 4689)}, 'driver_load': {(SYSMON, 6)}, 'image_load': {(SYSMON, 7)},
    'create_remote_thread': {(SYSMON, 8)}, 'raw_access_thread': {(SYSMON, 9)}, 'process_access': {(SYSMON, 10)},
    'file_event': {(SYSMON, 11)}, 'registry_add': {(SYSMON, 12)}, 'registry_delete': {(SYSMON, 12)}, 'registry_set': {(SYSMON, 13)},
    'registry_rename': {(SYSMON, 14)}, 'registry_event': {(SYSMON, 12), (SYSMON, 13), (SYSMON, 14)}, 'create_stream_hash': {(SYSMON, 15)},
    'pipe_created': {(SYSMON, 17), (SYSMON, 18)}, 'wmi_event': {(SYSMON, 19), (SYSMON, 20), (SYSMON, 21)}, 'dns_query': {(SYSMON, 22)},
    'file_delete': {(SYSMON, 23), (SYSMON, 26)}, 'ps_script': {(POWERSHELL, 4104)}, 'ps_module': {(POWERSHELL, 4103)},
}
SERVICE_CHANNELS = {'security': 'security', 'system': 'system', 'sysmon': SYSMON, 'powershell': POWERSHELL,
                    'application': 'application', 'taskscheduler': 'microsoft-windows-taskscheduler/operational'}


def _logsource_fits(logsource, event):
    """May this rule's log source see this event? Only events with a Windows Channel are filtered."""
    channel = str(event.get('Channel') or '').lower()
    if not channel:
        return True
    category, product, service = logsource
    if product and product != 'windows':
        return False
    try:
        eid = int(event.get('EventID'))
    except (TypeError, ValueError):
        eid = None
    if category in CATEGORY_EVENTS:
        return (channel, eid) in CATEGORY_EVENTS[category]
    if service in SERVICE_CHANNELS:
        return channel == SERVICE_CHANNELS[service]
    return True


def _events(data):
    """The events of a sample: JSON Lines, a JSON array or one JSON object, optionally gzip-compressed
    (.jsonl.gz). Raises ValueError."""
    import gzip
    import json
    if data[:2] == b'\x1f\x8b':
        with gzip.GzipFile(fileobj=__import__('io').BytesIO(data)) as g:
            data = g.read(256 * 1024 * 1024 + 1)
        if len(data) > 256 * 1024 * 1024:
            raise ValueError('sample too large once decompressed')
    text = data.decode('utf-8-sig', errors='replace').strip()
    if not text:
        return []
    if text[0] == '[' or (text[0] == '{' and '\n' not in text):
        value = json.loads(text)
        events = value if isinstance(value, list) else [value]
    else:
        events = []
        for n, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except ValueError as e:
                raise ValueError(f'line {n} is not JSON: {e}') from e
            if len(events) >= MAX_EVENTS:
                break
    return [e for e in events[:MAX_EVENTS] if isinstance(e, dict)]


def _get(event, field):
    """A field of the event: exact key, a dotted path (a.b.c), or the key in another case."""
    if field in event:
        return event[field]
    node = event
    for part in field.split('.'):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            node = None
            break
    if node is not None:
        return node
    low = field.lower()
    for k, v in event.items():
        if isinstance(k, str) and k.lower() == low:
            return v
    return None


def _strings(value):
    """Every scalar of a field value (lists are matched item by item), as strings."""
    if isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif value is not None:
        yield 'true' if value is True else 'false' if value is False else str(value)


_REGEX_CACHE = {}


def _sigma_string_regex(value, cased):
    """A SigmaString (with * and ? wildcards) as an anchored regular expression."""
    import re
    from sigma.types import SpecialChars
    key = (id(value), cased)
    rx = _REGEX_CACHE.get(key)
    if rx is None:
        parts = []
        for p in value.s:
            if p == SpecialChars.WILDCARD_MULTI:
                parts.append('.*')
            elif p == SpecialChars.WILDCARD_SINGLE:
                parts.append('.')
            elif isinstance(p, str):
                parts.append(re.escape(p))
        rx = re.compile('^' + ''.join(parts) + '$', re.S | (0 if cased else re.I))
        _REGEX_CACHE[key] = (rx, value)          # keep the value alive: its id stays valid
        return rx
    return rx[0]


def _match_value(value, field_value, event):
    """Does one pySigma value match one event field value?"""
    import ipaddress
    import re
    from sigma import types as T
    if isinstance(value, T.SigmaExpansion):
        return any(_match_value(v, field_value, event) for v in value.values)
    if isinstance(value, T.SigmaExists):
        return (field_value is not None) == bool(value.exists)
    if isinstance(value, T.SigmaNull):
        return field_value is None or field_value == ''
    if field_value is None:
        return False
    if isinstance(value, T.SigmaFieldReference):
        other = _get(event, value.field)
        return other is not None and any(a.lower() == b.lower() for a in _strings(field_value) for b in _strings(other))
    if isinstance(value, T.SigmaRegularExpression):
        flags = 0
        for f in value.flags:
            flags |= {T.SigmaRegularExpressionFlag.IGNORECASE: re.I, T.SigmaRegularExpressionFlag.MULTILINE: re.M,
                      T.SigmaRegularExpressionFlag.DOTALL: re.S}.get(f, 0)
        try:
            rx = re.compile(str(value.regexp), flags)
        except re.error:
            return False
        return any(rx.search(s) for s in _strings(field_value))
    if isinstance(value, T.SigmaCIDRExpression):
        for s in _strings(field_value):
            try:
                if ipaddress.ip_address(s.strip()) in value.network:
                    return True
            except ValueError:
                continue
        return False
    if isinstance(value, T.SigmaCompareExpression):
        n = value.number.number
        ops = {T.SigmaCompareExpression.CompareOperators.LT: lambda x: x < n, T.SigmaCompareExpression.CompareOperators.LTE: lambda x: x <= n,
               T.SigmaCompareExpression.CompareOperators.GT: lambda x: x > n, T.SigmaCompareExpression.CompareOperators.GTE: lambda x: x >= n}
        test = ops.get(value.op)
        for s in _strings(field_value):
            try:
                if test and test(float(s)):
                    return True
            except ValueError:
                continue
        return False
    if isinstance(value, T.SigmaNumber):
        for s in _strings(field_value):
            try:
                if float(s) == float(value.number):
                    return True
            except ValueError:
                continue
        return False
    if isinstance(value, T.SigmaBool):
        return any(s.lower() == str(value.boolean).lower() for s in _strings(field_value))
    if isinstance(value, T.SigmaString):
        rx = _sigma_string_regex(value, isinstance(value, T.SigmaCasedString))
        return any(rx.match(s) for s in _strings(field_value))
    return False                  # a value type tests do not support (timestamp parts…): no match


def _eval(node, event):
    """Evaluates a pySigma condition tree on one event."""
    from sigma.conditions import (ConditionAND, ConditionFieldEqualsValueExpression, ConditionNOT, ConditionOR,
                                  ConditionValueExpression)
    if isinstance(node, ConditionAND):
        return all(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _match_value(node.value, _get(event, node.field), event)
    if isinstance(node, ConditionValueExpression):
        # a keyword: searched inside every value of the event (full-text, as SIEM backends do)
        from sigma import types as T
        values = list(_strings(list(event.values())))
        if isinstance(node.value, T.SigmaString):
            import re
            rx = _sigma_string_regex(node.value, isinstance(node.value, T.SigmaCasedString))
            inner = re.compile(rx.pattern[1:-1], rx.flags)
            return any(inner.search(v) for v in values)
        return any(_match_value(node.value, v, event) for v in values)
    return False


def _fields(node):
    """The field names a condition tree looks at (for the hit's fields)."""
    from sigma.conditions import ConditionFieldEqualsValueExpression
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return [node.field]
    out = []
    for a in getattr(node, 'args', None) or []:
        out += [f for f in _fields(a) if f not in out]
    return out


DRIVERS = {d.format: d for d in (YaraDriver(), SigmaDriver())}


def get_driver(fmt):
    driver = DRIVERS.get((fmt or '').lower())
    return driver if driver and driver.available() else None

# Design

## 1. Goal

Answer one question, the same way for every detection format:

> **Run a rule on a sample, in a safe place, and say whether it fired and where.**

Then do it over whole **sample sets** — malicious ones (what the rule should catch) and benign
ones (what it must never catch) — and report live, sample by sample.

Why a project of its own, and not part of the editor or of Rulezet:

- the editor (Test panel), Rulezet (the Lab: rule pages, bundles, scores), a CI pipeline, a MISP
  module, a SOC lab all need it — none of them should have to import the others;
- the machine that holds real malware must run as little code as possible: this package, an
  engine, nothing else.

## 2. Architecture

```
 caller (editor server, Rulezet, CLI)              sandbox (bubblewrap), one process per run
┌────────────────────────────────────┐            ┌─────────────────────────────────────────┐
│ TestService                        │  rule text │ worker.py                               │
│  · store: sets + sample metadata   │  sample    │  driver = DRIVERS[format]               │
│    and paths — never opens a file  │  ids+paths │  prepared = driver.prepare(rule)  once  │
│  · checks: size, format, refused   │ ─────────► │  for each sample:                       │
│    features, max samples           │   stdin    │     driver.run(prepared, path, timeout) │
│  · registry: run states            │ ◄───────── │  → { verdict, hits, time_ms }           │
│  · executor: background            │  JSON lines│                                         │
│  · on_finish: host persistence     │  (stdout)  │  no network · read-only · limits        │
└────────────────────────────────────┘            └─────────────────────────────────────────┘
```

| File | Role |
|---|---|
| `drivers.py` | one class per format: `check_rule`, `prepare`, `run`; registry `DRIVERS` |
| `worker.py` | the only code that opens a sample; reads one job on stdin, writes JSON lines |
| `sandbox.py` | builds the bubblewrap command, resource limits, wall-clock kill, streams events |
| `samples.py` | `SampleStore` interface and `FolderSampleStore` |
| `runs.py` | `TestService`: start a run, follow it, outcomes and counters; `MemoryRegistry` |
| `web.py` | optional Flask blueprint (`/sets`, `POST /`, `GET /<id>`) and `create_app` |
| `cli.py` | `rulezet-tester sets | run | serve` |

## 3. The contract (same for every format)

### 3.1 Run state

What `start()` and `state()` return, and what the HTTP API sends:

```json
{
  "id": "…", "format": "yara", "status": "queued | running | done | failed", "error": null,
  "created": 1761470000.0, "finished": null,
  "sets": [
    { "id": "benign-text", "name": "Benign — text files", "kind": "benign", "labels": {},
      "total": 4, "done": 4, "matched": 1, "false_positives": 1, "missed": 0 }
  ],
  "samples": [
    { "id": "benign-text/gnu_agpl_license.txt", "set": "benign-text", "label": "gnu_agpl_license.txt",
      "sha256": "…", "size": 34523, "expected": "no_match",
      "verdict": "match", "outcome": "false_positive", "time_ms": 1,
      "hit_total": 17,
      "hits": [{ "rule": "t", "item": "$lic", "where": { "kind": "offset", "offset": 112, "length": 3 }, "data": "474e55" }] }
  ],
  "summary": { "total": 9, "done": 9, "detected": 0, "missed": 0, "false_positives": 1,
               "clean": 3, "timeouts": 0, "errors": 0 }
}
```

- `verdict` (from the driver): `pending`, `match`, `no_match`, `timeout`, `error`.
- `expected` (from the set): `match` (malicious), `no_match` (benign), `unknown` (synthetic,
  unless `samples.json` says otherwise).
- `outcome` (computed here, never by a driver):

  | expected \ verdict | match | no_match |
  |---|---|---|
  | `match` | **detected** | **missed** |
  | `no_match` | **false_positive** | clean |
  | `unknown` | matched | not_matched |

  plus `timeout` and `error`.
- `hits` holds at most 50 hits per sample; `hit_total` is the real count. `data` is the matched
  bytes in hex (at most 64), `before` / `after` the 32 bytes around them, so a UI can show the
  match in its surroundings. Never more of the sample than that.
- Only `hits[].where` depends on the format. `item` is the part of the rule that matched
  (YARA: the string id), so a UI can jump to it.

| Format | `where` |
|---|---|
| YARA | `{ kind: 'offset', offset, length }`, or `{ kind: 'file' }` for a condition without strings |
| Suricata (planned) | `{ kind: 'packet', packet, flow }` with `item` = the sid |
| Sigma (planned) | `{ kind: 'event', index, fields }` |
| Log formats (planned) | `{ kind: 'line', line }` |

### 3.2 Driver

```python
class Driver:
    format = 'yara'
    sample_kind = 'file'      # file | pcap | events | log_lines | http
    module = 'yara'           # engine import; missing -> the format is not offered

    def check_rule(self, text) -> str | None      # refusal message, checked before queueing
    def prepare(self, text)                       # once per run; raise DriverError
    def run(self, prepared, path, timeout) -> dict   # { verdict, hits, error? }
```

Rules for drivers: never write a file, never use the network, never return sample bytes, cap the
number of hits (`MAX_HITS`), turn every engine error into a verdict instead of raising.

### 3.3 Sample store

```python
class SampleStore:
    def sets(self, fmt) -> list[dict]       # { id, name, format, kind, description, labels, tlp, source, count }
    def samples(self, set_id) -> list[dict] # { id, set, label, sha256, size, expected, path }
```

`FolderSampleStore(*roots)` reads the folder layout of the README. It refuses set ids with path
characters, `samples.json` entries that point outside their set folder, and files over 50 MB.
A host with a database can subclass `SampleStore` and keep the files in folders.

### 3.4 Hooks for the host

| `TestService(...)` argument | Default | Rulezet will use |
|---|---|---|
| `store` | — | its sets (database) over sample folders |
| `sandbox` | `Sandbox()` (bwrap) | `Sandbox(command=[...])` to reach the isolated lab machine |
| `registry` | `MemoryRegistry` (one process) | a registry in the database: several gunicorn workers must see the same run |
| `executor` | thread pool (`max_concurrent=2`) | its background job worker |
| `on_finish` | none | store results per rule version, update the Lab score |
| `max_samples`, `max_rule_size` | 1000, 512 KB | settings |

## 4. Security

A YARA scan never *executes* a sample, but three risks are real and apply to every format:
storing / leaking live malware, hostile input reaching a parser (a crafted file, pcap, EVTX or
rule), and denial of service (a slow rule over many samples).

### 4.1 Isolation (sandbox.py)

Default mode `bwrap` (bubblewrap must be installed, otherwise tests are reported unavailable —
there is no silent fallback):

| Measure | How |
|---|---|
| No network | `--unshare-all` (new net, pid, ipc, uts, user, cgroup namespaces) |
| Nothing of the machine visible | empty root; read-only binds of `/usr`, `/lib*`, the interpreter, its site-packages, this package and the sample folders of the run only. No home, no `/etc/passwd`, no `.env`, no database socket |
| Nothing written | read-only binds, `/tmp` is an empty tmpfs, `RLIMIT_FSIZE = 0` |
| No privileges | `--cap-drop ALL`, `--new-session`, non-root user |
| Clean start | `--clearenv`, `python -I` (no env vars, no user site, no current folder) |
| Bounded | `RLIMIT_AS` (512 MB), `RLIMIT_CPU` (120 s), `RLIMIT_NOFILE` (64), no core dump, per-sample timeout (5 s, the engine's own), wall clock per run (300 s, the whole process group is killed) |
| Tied to the caller | `--die-with-parent` |

Mode `process` keeps the limits and the clean environment only; it must be chosen explicitly
(development, or when the whole service already runs in an isolated VM). A custom `command`
(nsjail, a container runtime, ssh to the lab machine) replaces bwrap and receives the worker
command line; it must keep stdin / stdout.

The test suite checks the isolation (`tests/test_runs.py`), and it can be checked by hand:
inside the sandbox the home, `.env` and `/etc/passwd` do not exist, a socket fails, a write fails,
the environment holds only `LC_CTYPE` and `PWD`.

### 4.2 Rules

- size cap (512 KB) and a non-empty text, checked before queueing;
- `check_rule` per driver — YARA: no `include` (it could read files), compiled with
  `includes=False`;
- compiled **inside** the sandbox, never in the caller's process;
- per-sample engine timeout and per-run wall clock.

### 4.3 Samples

- Kept on the machine that runs the sandbox, outside any web root, read-only for the service.
- Real malware: named by sha256, no extension; the folder excluded from the host antivirus on
  purpose (it would quarantine them) — document it on the machine.
- **Never served.** Results carry hashes, sizes, rule items, offsets, the matched bytes (≤ 64 per hit) and 32 bytes
  of context on each side — never the sample itself. A download, if a
  host ever adds one, is the host's decision: admins, password-protected archive, logged.
- Separate from the host's backups (or a separate encrypted backup).
- Real malware only once the sandbox runs on a **separate machine or VM** (`command=`); the
  shipped sets (synthetic, benign) are safe anywhere.

### 4.4 Access

The service has an `owner` per run: `state(id, owner=…)` returns nothing to anyone else. Who may
start runs, how often (rate limit) and on which sets (TLP) is the host's job — the HTTP blueprint
takes `owner=` and is mounted behind the host's login.

## 5. Adding a format

1. A driver in `drivers.py` (or its own module): `format`, `sample_kind`, `module`,
   `check_rule`, `prepare`, `run` returning the common shape with its own `where`.
2. Add it to `DRIVERS`.
3. A small safe sample set in `samples/` (`format` = the new format).
4. Tests: a rule that matches, one that does not, one that the engine refuses, a timeout.
5. Nothing else changes: `TestService`, the sandbox, the HTTP API, the CLI and the callers'
   UIs already handle it. If they do not, the contract (§3) is wrong — fix the contract.

Engines that are binaries (`suricata -r`, `zeek -r`, `wazuh-logtest`) run from the worker as
subprocesses, inside the same sandbox; their binary folder is added to the read-only binds.

## 6. Plan

| Step | Content | Status |
|---|---|---|
| 1 | Contract, YARA driver, bwrap sandbox, folder store, service, HTTP, CLI | done |
| 2 | Test panel in rulezet-editor (live rows, hits → jump to the string) | done |
| 3 | Rulezet: `/editor-api/test`, DB registry, "test on Create", results per rule version + badge (done); sample sets themselves stay folders | done |
| 4 | Relevance: choose the sets from the rule (file type it targets, tags / CVE / ATT&CK) — next, see Rulezet's docs/future/yara_editor.md §8 | |
| 5 | Lab VM for real malware: encrypted samples scanned in memory, SSH agent + `RemoteLab`, provisioning, `lab-check`, MalwareBazaar import ([lab.md](lab.md)) | done (provisioning not yet run on a real VM) |
| 6 | Suricata driver (pcap) — proof that a new format needs nothing else | |

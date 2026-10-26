"""
Testing rules on samples. Same pipeline for every format; only the driver changes.

    web process                         sandbox (bubblewrap)
    TestService ── store: metadata ──►  worker.py ── driver.prepare / driver.run ── verdicts
                   paths only           (no network, read-only samples, limits)

Used by rulezet-editor (the Test panel) and Rulezet (the Lab), or alone (CLI, HTTP API).
See docs/design.md.
"""
from .drivers import DRIVERS, Driver, DriverError, YaraDriver, get_driver
from .runs import MemoryRegistry, TestError, TestService, outcome
from .samples import FolderSampleStore, SampleStore
from .sandbox import Sandbox, SandboxUnavailable

__version__ = '0.1.0'

__all__ = [
    'DRIVERS', 'Driver', 'DriverError', 'FolderSampleStore', 'MemoryRegistry', 'SampleStore', 'Sandbox',
    'SandboxUnavailable', 'TestError', 'TestService', 'YaraDriver', 'get_driver', 'outcome',
]

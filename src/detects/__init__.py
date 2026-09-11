"""detects - a standalone agent-execution verification harness.

An agent claims it completed a task. ``detects`` turns that claim into an
immutable, Ed25519-signed evidence receipt that binds *task*, *run*, and
*source/runtime* identity, and gives you a pure verifier
(:func:`detects.verify_receipt`) you can point at receipts it did not create.

See ``README.md`` for the failure model and ``ARCHITECTURE.md`` for the
receipt lifecycle and the full list of checks. ``SECURITY.md`` and the
README's "What this harness does not verify" section cover the limits.
"""

from __future__ import annotations

from .canon import canon_bytes, canon_str, digest, sha256_hex
from .clock import Clock, ManualClock, SystemClock
from .fixtures import Fixture, get_fixture, registry_hash
from .harness import Harness
from .identity import (
    generate_private_key,
    load_private_key,
    runtime_fingerprint,
    save_private_key,
    sign,
    verify,
    worker_id_for,
)
from .lease import LeaseHeld, LeaseManager
from .ledger import GENESIS, Ledger
from .protocols import LeaseReadView, LedgerReadView
from .reexec import (
    InProcessReexecutor,
    ReexecOutcome,
    Reexecutor,
    SubprocessReexecutor,
)
from .schema import (
    SCHEMA_VERSION,
    Check,
    DetectsError,
    DetectsParseError,
    Receipt,
    Run,
    TaskSpec,
    VerdictReport,
    parse_receipt,
    signing_payload,
    task_id_for,
)
from .verifier import verify_receipt

__version__ = "0.1.0"

__all__ = [
    "GENESIS",
    # schema
    "SCHEMA_VERSION",
    "Check",
    # clocks
    "Clock",
    "DetectsError",
    "DetectsParseError",
    # fixtures
    "Fixture",
    # runtime pieces
    "Harness",
    "InProcessReexecutor",
    "LeaseHeld",
    "LeaseManager",
    "LeaseReadView",
    "Ledger",
    "LedgerReadView",
    "ManualClock",
    "Receipt",
    "ReexecOutcome",
    "Reexecutor",
    "Run",
    "SubprocessReexecutor",
    "SystemClock",
    "TaskSpec",
    "VerdictReport",
    "__version__",
    # serialization
    "canon_bytes",
    "canon_str",
    "digest",
    # identity
    "generate_private_key",
    "get_fixture",
    "load_private_key",
    "parse_receipt",
    "registry_hash",
    "runtime_fingerprint",
    "save_private_key",
    "sha256_hex",
    "sign",
    "signing_payload",
    "task_id_for",
    "verify",
    # the verifier
    "verify_receipt",
    "worker_id_for",
]

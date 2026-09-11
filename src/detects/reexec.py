"""Independent re-execution.

The cheap witness check in :mod:`detects.fixtures` proves a *necessary*
property of a result. For some tasks that is also *sufficient*; for others -
``nth_prime`` is the example in this repo - it is not: any prime passes the
witness check, so a worker can sign a wrong prime and slip past.

Re-execution closes that gap for deterministic fixtures: run the task again,
independently, and compare output digests. It is deliberately *not* baked
into :func:`detects.verifier.verify_receipt` unconditionally - that function
stays pure. You opt in by passing a ``reexecutor``. Two are provided:

* :class:`InProcessReexecutor` - fast, re-runs in this process. Used by the
  harness's own submit path (``Harness(..., reexecutor=...)``) and by tests.
* :class:`SubprocessReexecutor` - re-runs in a clean child process
  (``python -m detects.reexec``), so nothing the worker's process mutated can
  influence the result. Slower; used by ``detects verify --reexecute``.

Non-deterministic fixtures (``slow_task``, ``flaky_task``) report
``nondeterministic`` and the verifier marks the check *skipped*.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from typing import Literal, Protocol

from .canon import digest
from .fixtures import get_fixture

ReexecStatus = Literal["ok", "nondeterministic", "error"]


@dataclass
class ReexecOutcome:
    status: ReexecStatus
    output_digest: str | None
    detail: str


class Reexecutor(Protocol):
    def __call__(self, task_name: str, inputs: dict) -> ReexecOutcome: ...


def _guard(task_name: str) -> ReexecOutcome | None:
    fx = get_fixture(task_name)
    if fx is None:
        return ReexecOutcome("error", None, f"unknown fixture {task_name!r}")
    if not fx.deterministic:
        return ReexecOutcome(
            "nondeterministic", None, f"fixture {task_name!r} is not marked deterministic"
        )
    return None


class InProcessReexecutor:
    """Re-run the fixture in this process. Fast; no isolation from process state."""

    def __call__(self, task_name: str, inputs: dict) -> ReexecOutcome:
        bad = _guard(task_name)
        if bad is not None:
            return bad
        fx = get_fixture(task_name)
        assert fx is not None
        try:
            out = fx.run(dict(inputs), 1)
        except Exception as exc:
            return ReexecOutcome("error", None, f"re-execution raised {type(exc).__name__}: {exc}")
        return ReexecOutcome("ok", digest(out), "re-executed in-process")


class SubprocessReexecutor:
    """Re-run the fixture in a clean child process (``python -m detects.reexec``)."""

    def __init__(self, python: str | None = None, timeout_s: float = 15.0) -> None:
        self.python = python or sys.executable
        self.timeout_s = timeout_s

    def __call__(self, task_name: str, inputs: dict) -> ReexecOutcome:
        bad = _guard(task_name)
        if bad is not None:
            return bad
        payload = json.dumps({"task_name": task_name, "inputs": inputs})
        try:
            proc = subprocess.run(
                [self.python, "-m", "detects.reexec"],
                input=payload,
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ReexecOutcome("error", None, f"re-execution timed out after {self.timeout_s}s")
        if proc.returncode != 0:
            return ReexecOutcome(
                "error", None, f"re-execution exited {proc.returncode}: {proc.stderr.strip()[:200]}"
            )
        try:
            got = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return ReexecOutcome("error", None, "re-execution produced no parseable result")
        return ReexecOutcome("ok", got["output_digest"], "re-executed in a clean subprocess")


def _main() -> int:
    try:
        data = json.loads(sys.stdin.read())
        fx = get_fixture(data["task_name"])
        if fx is None:
            print(f"unknown fixture {data['task_name']!r}", file=sys.stderr)
            return 2
        out = fx.run(dict(data["inputs"]), 1)
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"output_digest": digest(out)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

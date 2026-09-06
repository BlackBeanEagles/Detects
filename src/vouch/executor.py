"""Run a fixture with a per-attempt timeout and bounded retries.

Rules:

* A raised exception is a *transient failure*: retry with exponential
  backoff, up to ``max_attempts``.
* Exceeding ``deadline_s`` on an attempt is a *timeout*: not retried.
* The timeout races a worker thread, so it uses real elapsed time. Every
  timestamp recorded on the result comes from the injected ``clock`` so the
  rest of the harness stays deterministic. A timed-out worker thread cannot
  be force-killed in Python; it is abandoned and finishes in the background.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from typing import Any

from .clock import Clock
from .fixtures import Fixture


@dataclass
class ExecResult:
    outcome: str  # "success" | "failure" | "timeout"
    output: Any
    attempts: int
    started_at: float
    finished_at: float
    detail: str


def execute(
    fixture: Fixture,
    inputs: dict,
    *,
    deadline_s: float,
    max_attempts: int,
    backoff_base_s: float,
    clock: Clock,
) -> ExecResult:
    started_at = clock.now()
    last_detail = ""

    for attempt in range(1, max_attempts + 1):
        pool = ThreadPoolExecutor(max_workers=1)
        t0 = time.monotonic()
        fut = pool.submit(fixture.run, inputs, attempt)
        try:
            output = fut.result(timeout=deadline_s)
        except FutureTimeout:
            pool.shutdown(wait=False, cancel_futures=True)
            elapsed = time.monotonic() - t0
            return ExecResult(
                "timeout",
                None,
                attempt,
                started_at,
                started_at + deadline_s,
                f"attempt {attempt} exceeded deadline of {deadline_s}s "
                f"(ran >= {elapsed:.2f}s; worker thread abandoned)",
            )
        except Exception as exc:
            pool.shutdown(wait=False, cancel_futures=True)
            last_detail = f"attempt {attempt} raised {type(exc).__name__}: {exc}"
            if attempt < max_attempts:
                time.sleep(backoff_base_s * (2 ** (attempt - 1)))
                continue
            return ExecResult("failure", None, attempt, started_at, clock.now(), last_detail)
        else:
            pool.shutdown(wait=False, cancel_futures=True)
            return ExecResult(
                "success",
                output,
                attempt,
                started_at,
                clock.now(),
                f"succeeded on attempt {attempt}",
            )

    return ExecResult(
        "failure", None, max_attempts, started_at, clock.now(), last_detail or "exhausted attempts"
    )

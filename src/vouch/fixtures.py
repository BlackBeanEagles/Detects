"""Synthetic, deterministic task fixtures.

Each fixture is a pure function plus a *witness* pair:

* ``run(inputs, attempt)``          - produce the output.
* ``make_witness(inputs, output)``  - the proof material the agent submits.
* ``check_witness(inputs, witness)``- recompute cheaply from inputs only and
  decide whether the claimed output can be believed. This is the piece that
  catches a lying worker that a signature check never would.

The cheap check is *necessary* but not always *sufficient*: ``nth_prime``
only proves the claimed output is prime, so a worker can sign a wrong prime
and pass it. Fixtures marked ``deterministic`` can be re-run independently
by :mod:`vouch.reexec` to close that gap.

No fixture touches the network, the filesystem, or the wall clock (except
``slow_task``, which sleeps on purpose so timeouts can be tested, and
``flaky_task``, which fails by attempt number - both ``deterministic=False``).
"""

from __future__ import annotations

import hashlib
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .canon import digest


@dataclass(frozen=True)
class Fixture:
    name: str
    postconditions: tuple[str, ...]
    run: Callable[[dict, int], Any]
    make_witness: Callable[[dict, Any], dict]
    check_witness: Callable[[dict, dict], tuple[bool, str]]
    deterministic: bool = True
    """True iff re-running with the same inputs always yields the same output,
    so :mod:`vouch.reexec` can verify it by independent re-execution."""


def _H(v: Any) -> Any:
    return v if isinstance(v, (int, float, str, bool)) or v is None else repr(v)


# --------------------------------------------------------------------------- #
# sum_range: output = 0 + 1 + ... + n
# --------------------------------------------------------------------------- #
def _sum_range_run(inputs: dict, attempt: int) -> int:
    n = int(inputs["n"])
    if n < 0:
        raise ValueError("n must be >= 0")
    return n * (n + 1) // 2


def _closed_form_witness(inputs: dict, output: Any) -> dict:
    return {"claimed_output": output}


def _sum_range_check(inputs: dict, witness: dict) -> tuple[bool, str]:
    n = int(inputs["n"])
    expected = n * (n + 1) // 2
    got = witness.get("claimed_output")
    if got == expected:
        return True, f"n(n+1)/2 == {expected}"
    return False, f"claimed {got!r}, closed form gives {expected}"


# --------------------------------------------------------------------------- #
# sort_list
# --------------------------------------------------------------------------- #
def _sort_run(inputs: dict, attempt: int) -> list:
    return sorted(inputs["items"])


def _list_witness(inputs: dict, output: Any) -> dict:
    return {"claimed_output": list(output)}


def _sort_check(inputs: dict, witness: dict) -> tuple[bool, str]:
    src = list(inputs["items"])
    out = witness.get("claimed_output")
    if not isinstance(out, list):
        return False, "claimed_output is not a list"
    if Counter(map(_H, out)) != Counter(map(_H, src)):
        return False, "claimed_output is not a permutation of the input"
    if any(out[i] > out[i + 1] for i in range(len(out) - 1)):
        return False, "claimed_output is not in non-decreasing order"
    return True, "permutation + ordered"


# --------------------------------------------------------------------------- #
# dedupe: first occurrence wins, order preserved
# --------------------------------------------------------------------------- #
def _dedupe_run(inputs: dict, attempt: int) -> list:
    return list(dict.fromkeys(inputs["items"]))


def _dedupe_check(inputs: dict, witness: dict) -> tuple[bool, str]:
    src = list(inputs["items"])
    out = witness.get("claimed_output")
    if not isinstance(out, list):
        return False, "claimed_output is not a list"
    if len(out) != len({_H(v) for v in out}):
        return False, "claimed_output still contains duplicates"
    if {_H(v) for v in out} != {_H(v) for v in src}:
        return False, "claimed_output is not the input's distinct set"
    first: dict = {}
    for i, v in enumerate(src):
        first.setdefault(_H(v), i)
    idxs = [first[_H(v)] for v in out]
    if idxs != sorted(idxs):
        return False, "claimed_output does not preserve first-seen order"
    return True, "distinct set + first-seen order"


# --------------------------------------------------------------------------- #
# sha_blob
# --------------------------------------------------------------------------- #
def _sha_run(inputs: dict, attempt: int) -> str:
    return hashlib.sha256(bytes.fromhex(inputs["blob_hex"])).hexdigest()


def _sha_check(inputs: dict, witness: dict) -> tuple[bool, str]:
    expected = hashlib.sha256(bytes.fromhex(inputs["blob_hex"])).hexdigest()
    got = witness.get("claimed_output")
    return (got == expected), (
        "digest recomputes" if got == expected else f"claimed {got!r}, recomputed {expected}"
    )


# --------------------------------------------------------------------------- #
# nth_prime: the n-th prime (1-indexed). The cheap check can only test that
# the claimed output is *prime* - necessary, not sufficient - so this fixture
# is what makes independent re-execution earn its place.
# --------------------------------------------------------------------------- #
def _nth_prime_run(inputs: dict, attempt: int) -> int:
    n = int(inputs["n"])
    if n < 1:
        raise ValueError("n must be >= 1")
    count, cand = 0, 1
    while count < n:
        cand += 1
        if all(cand % d for d in range(2, int(cand**0.5) + 1)):
            count += 1
    return cand


def _is_prime(x: Any) -> bool:
    return (
        isinstance(x, int)
        and not isinstance(x, bool)
        and x > 1
        and all(x % d for d in range(2, int(x**0.5) + 1))
    )


def _nth_prime_check(inputs: dict, witness: dict) -> tuple[bool, str]:
    got = witness.get("claimed_output")
    if _is_prime(got):
        return True, "claimed_output is prime (necessary, not sufficient)"
    return False, f"claimed_output {got!r} is not prime"


# --------------------------------------------------------------------------- #
# slow_task: sleeps, then behaves like sum_range(n). For timeout tests.
# --------------------------------------------------------------------------- #
def _slow_run(inputs: dict, attempt: int) -> int:
    time.sleep(float(inputs.get("sleep_s", 1.0)))
    n = int(inputs["n"])
    return n * (n + 1) // 2


# --------------------------------------------------------------------------- #
# flaky_task: fails on attempts <= inputs["fail_times"], then behaves like
# sum_range(n). Deterministic in the attempt number. For retry tests.
# --------------------------------------------------------------------------- #
def _flaky_run(inputs: dict, attempt: int) -> int:
    if attempt <= int(inputs.get("fail_times", 0)):
        raise RuntimeError(f"transient failure on attempt {attempt}")
    n = int(inputs["n"])
    return n * (n + 1) // 2


REGISTRY: dict[str, Fixture] = {
    f.name: f
    for f in (
        Fixture(
            "sum_range",
            ("output_equals_closed_form",),
            _sum_range_run,
            _closed_form_witness,
            _sum_range_check,
        ),
        Fixture(
            "sort_list", ("is_permutation", "is_ordered"), _sort_run, _list_witness, _sort_check
        ),
        Fixture(
            "dedupe",
            ("distinct_set", "first_seen_order"),
            _dedupe_run,
            _list_witness,
            _dedupe_check,
        ),
        Fixture("sha_blob", ("digest_recomputes",), _sha_run, _closed_form_witness, _sha_check),
        Fixture(
            "nth_prime",
            ("output_is_prime",),
            _nth_prime_run,
            _closed_form_witness,
            _nth_prime_check,
        ),
        Fixture(
            "slow_task",
            ("output_equals_closed_form",),
            _slow_run,
            _closed_form_witness,
            _sum_range_check,
            deterministic=False,
        ),
        Fixture(
            "flaky_task",
            ("output_equals_closed_form",),
            _flaky_run,
            _closed_form_witness,
            _sum_range_check,
            deterministic=False,
        ),
    )
}


def get_fixture(name: str) -> Fixture | None:
    return REGISTRY.get(name)


def registry_hash() -> str:
    """Content address of the fixture registry, recorded in every receipt's
    runtime block so a verifier can tell whether it shares the caller's
    notion of what each task means."""
    return digest(
        {
            name: {"postconditions": list(f.postconditions), "deterministic": f.deterministic}
            for name, f in sorted(REGISTRY.items())
        }
    )

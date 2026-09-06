"""Named invariants - the properties vouch is supposed to guarantee, each
backed by a property-based test.

  I1  A task_id has at most one terminal `success` in the ledger.
  I2  A verdict does not change as wall-clock time moves forward.
  I3  Any single unsigned mutation of an accepted receipt yields REJECT,
      and never removes an existing failure (monotonic under tampering).
  I4  Re-signing a lie does not launder it - a valid signature is necessary,
      never sufficient.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from vouch import (
    Harness,
    LeaseManager,
    Ledger,
    ManualClock,
    TaskSpec,
    generate_private_key,
    verify_receipt,
)
from vouch.canon import canon_bytes, digest
from vouch.identity import sign

PCS = ["output_equals_closed_form"]


def _harness() -> tuple[Harness, ManualClock]:
    clock = ManualClock()
    h = Harness(
        private_key=generate_private_key(),
        ledger=Ledger(),
        leases=LeaseManager(),
        clock=clock,
    )
    return h, clock


# --- I1 -------------------------------------------------------------------- #
@given(st.lists(st.integers(min_value=0, max_value=4), min_size=1, max_size=15))
@settings(max_examples=40, deadline=None)
def test_at_most_one_terminal_success_per_task(ns):
    h, _ = _harness()
    for n in ns:
        spec = TaskSpec(name="sum_range", inputs={"n": n}, declared_postconditions=PCS)
        h.submit(h.execute_and_sign(spec), spec)

    successes: dict[str, int] = {}
    for entry in h.ledger.entries():
        rc = entry["receipt"]
        if rc["outcome"] == "success":
            successes[rc["task_id"]] = successes.get(rc["task_id"], 0) + 1
    assert successes  # at least one landed
    assert all(count == 1 for count in successes.values())


# --- I2 -------------------------------------------------------------------- #
@given(st.integers(min_value=1, max_value=10_000_000))
@settings(max_examples=25, deadline=None)
def test_verdict_is_stable_as_time_advances(jump):
    h, clock = _harness()
    spec = TaskSpec(name="sum_range", inputs={"n": 42}, declared_postconditions=PCS)
    r = h.execute_and_sign(spec)
    h.submit(r, spec)

    before = verify_receipt(r, spec=spec, now=clock.now())
    clock.advance(jump)
    after = verify_receipt(r, spec=spec, now=clock.now())

    assert before.ok == after.ok
    assert [(c.name, c.passed, c.skipped) for c in before.checks] == [
        (c.name, c.passed, c.skipped) for c in after.checks
    ]


# --- I3 -------------------------------------------------------------------- #
_MUTABLE = [
    "task_id",
    "task_name",
    "run_id",
    "attempt",
    "lease_epoch",
    "worker_id",
    "outcome",
    "output_digest",
    "nonce",
    "prev_ledger_hash",
    "started_at",
    "finished_at",
    "deadline_at",
]


def _perturb(value, salt):
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1 + (salt % 7)
    if isinstance(value, float):
        return value + 1.0 + (salt % 7)
    if isinstance(value, str):
        return value + "~" + str(salt % 10)
    return "perturbed"


@given(st.sampled_from(_MUTABLE), st.integers(min_value=0, max_value=9999))
@settings(max_examples=80, deadline=None)
def test_unsigned_mutation_is_monotonic_and_always_rejected(field, salt):
    h, clock = _harness()
    spec = TaskSpec(name="sum_range", inputs={"n": 20}, declared_postconditions=PCS)
    r = h.execute_and_sign(spec)

    base = verify_receipt(
        r,
        spec=spec,
        ledger=h.ledger,
        leases=h.leases,
        now=clock.now(),
        expected_prev_hash=h.ledger.head_hash(),
    )
    assert base.ok  # sanity: the untouched receipt is accepted

    mutated = dict(r)
    mutated[field] = _perturb(mutated[field], salt)
    after = verify_receipt(
        mutated,
        spec=spec,
        ledger=h.ledger,
        leases=h.leases,
        now=clock.now(),
        expected_prev_hash=h.ledger.head_hash(),
    )

    assert not after.ok  # any single unsigned change breaks acceptance
    assert {c.name for c in base.failed()} <= {c.name for c in after.failed()}


# --- I4 -------------------------------------------------------------------- #
@given(st.integers(min_value=1, max_value=300))
@settings(max_examples=40, deadline=None)
def test_resigning_a_lie_does_not_launder_it(n):
    h, clock = _harness()
    spec = TaskSpec(name="sum_range", inputs={"n": n}, declared_postconditions=PCS)
    r = dict(h.execute_and_sign(spec))

    lie = n * (n + 1) // 2 + 1
    r["witness"] = {"claimed_output": lie}
    r["output_digest"] = digest(lie)
    r["signature"] = sign(h.key, canon_bytes({k: v for k, v in r.items() if k != "signature"}))

    report = verify_receipt(r, spec=spec, now=clock.now())
    assert report.by_name("signature_valid").passed  # the re-sign worked
    assert report.by_name("witness_recheck").passed is False  # ...the lie is still caught
    assert not report.ok

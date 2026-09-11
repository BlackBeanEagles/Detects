"""Failure mode 5: timeout and retry - a slow run is timed out (and its late
receipt rejected), a flaky run is retried, an always-failing run gives up."""

from vouch.canon import digest
from vouch.identity import sign
from vouch.schema import TaskSpec, signing_payload
from vouch.verifier import verify_receipt


def test_slow_task_times_out(harness):
    spec = TaskSpec(
        name="slow_task",
        inputs={"sleep_s": 0.5, "n": 10},
        declared_postconditions=["output_equals_closed_form"],
    )
    r = harness.execute_and_sign(spec, deadline_s=0.1, max_attempts=1)
    assert r["outcome"] == "timeout"
    assert r["witness"] == {}
    assert r["output_digest"] is None
    assert "exceeded deadline" in r["detail"]


def test_late_success_after_timeout_is_rejected(harness, key):
    spec = TaskSpec(
        name="slow_task",
        inputs={"sleep_s": 0.5, "n": 10},
        declared_postconditions=["output_equals_closed_form"],
    )
    r = dict(harness.execute_and_sign(spec, deadline_s=0.1, max_attempts=1))
    r["outcome"] = "success"
    r["finished_at"] = r["deadline_at"] + 5.0
    r["witness"] = {"claimed_output": 55}
    r["output_digest"] = digest(55)
    r["signature"] = sign(key, signing_payload(r))

    report = verify_receipt(
        r,
        spec=spec,
        ledger=harness.ledger,
        leases=harness.leases,
        now=harness.clock.now(),
        expected_prev_hash=harness.ledger.head_hash(),
    )
    assert not report.ok
    assert report.by_name("within_deadline").passed is False


def test_flaky_task_retries_then_succeeds(harness):
    spec = TaskSpec(
        name="flaky_task",
        inputs={"n": 10, "fail_times": 2},
        declared_postconditions=["output_equals_closed_form"],
    )
    r = harness.execute_and_sign(spec, max_attempts=3, backoff_base_s=0.001)
    assert r["outcome"] == "success"
    assert r["attempt"] == 3
    assert r["witness"]["claimed_output"] == 55
    assert "attempt 3" in r["detail"]


def test_flaky_task_gives_up_after_max_attempts(harness):
    spec = TaskSpec(
        name="flaky_task",
        inputs={"n": 10, "fail_times": 9},
        declared_postconditions=["output_equals_closed_form"],
    )
    r = harness.execute_and_sign(spec, max_attempts=3, backoff_base_s=0.001)
    assert r["outcome"] == "failure"
    assert r["attempt"] == 3
    assert r["output_digest"] is None
    assert "RuntimeError" in r["detail"]

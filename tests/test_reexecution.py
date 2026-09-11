"""Independent re-execution: the check that catches a lie the cheap witness
check cannot (a wrong-but-still-prime nth_prime result)."""

import io
import json

from vouch import reexec
from vouch.canon import digest
from vouch.harness import Harness
from vouch.identity import sign
from vouch.reexec import InProcessReexecutor, SubprocessReexecutor
from vouch.schema import TaskSpec, signing_payload
from vouch.verifier import verify_receipt

PRIME_SPEC = TaskSpec(
    name="nth_prime", inputs={"n": 10}, declared_postconditions=["output_is_prime"]
)


def _resign(receipt, key):
    receipt = dict(receipt)
    receipt["signature"] = sign(key, signing_payload(receipt))
    return receipt


def test_honest_receipt_passes_reexecution(harness):
    r = harness.execute_and_sign(PRIME_SPEC)
    assert r["witness"]["claimed_output"] == 29  # the 10th prime
    report = verify_receipt(
        r, spec=PRIME_SPEC, now=harness.clock.now(), reexecutor=InProcessReexecutor()
    )
    assert report.by_name("independent_reexecution").passed
    assert report.ok


def test_wrong_but_prime_result_slips_past_witness_but_not_reexecution(harness, key):
    r = dict(harness.execute_and_sign(PRIME_SPEC))
    r["witness"] = {"claimed_output": 7}  # prime, but the 10th prime is 29
    r["output_digest"] = digest(7)
    r = _resign(r, key)
    report = verify_receipt(
        r, spec=PRIME_SPEC, now=harness.clock.now(), reexecutor=InProcessReexecutor()
    )
    assert report.by_name("signature_valid").passed
    assert report.by_name("witness_recheck").passed  # "7 is prime" - fooled
    assert report.by_name("independent_reexecution").passed is False
    assert not report.ok


def test_reexecution_skipped_without_a_reexecutor(harness):
    r = harness.execute_and_sign(PRIME_SPEC)
    report = verify_receipt(r, spec=PRIME_SPEC, now=harness.clock.now())
    assert report.by_name("independent_reexecution").skipped
    assert report.ok


def test_reexecution_skipped_for_nondeterministic_fixture(harness):
    spec = TaskSpec(
        name="slow_task",
        inputs={"sleep_s": 0.0, "n": 5},
        declared_postconditions=["output_equals_closed_form"],
    )
    r = harness.execute_and_sign(spec, deadline_s=2.0)
    report = verify_receipt(r, spec=spec, now=harness.clock.now(), reexecutor=InProcessReexecutor())
    c = report.by_name("independent_reexecution")
    assert c.skipped
    assert "deterministic" in c.detail


def test_subprocess_reexecutor_matches_inprocess():
    got = SubprocessReexecutor()("sum_range", {"n": 100})
    assert got.status == "ok"
    assert got.output_digest == digest(5050)


def test_subprocess_reexecutor_reports_nondeterministic_without_spawning():
    got = SubprocessReexecutor()("slow_task", {"sleep_s": 99, "n": 1})
    assert got.status == "nondeterministic"


def test_subprocess_reexecutor_reports_unknown_fixture():
    got = SubprocessReexecutor()("no_such_task", {})
    assert got.status == "error"
    assert "unknown fixture" in got.detail


def test_reexec_main_entrypoint(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.stdin", io.StringIO(json.dumps({"task_name": "sum_range", "inputs": {"n": 10}}))
    )
    assert reexec._main() == 0
    assert json.loads(capsys.readouterr().out)["output_digest"] == digest(55)

    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    assert reexec._main() == 1


def test_harness_submit_with_reexecutor_blocks_a_lie(ledger, leases, clock, key):
    h = Harness(
        private_key=key,
        ledger=ledger,
        leases=leases,
        clock=clock,
        reexecutor=InProcessReexecutor(),
    )
    spec = TaskSpec(name="nth_prime", inputs={"n": 5}, declared_postconditions=["output_is_prime"])
    r = dict(h.execute_and_sign(spec))
    r["witness"] = {"claimed_output": 3}  # the 5th prime is 11
    r["output_digest"] = digest(3)
    r = _resign(r, key)
    report, entry = h.submit(r, spec)
    assert not report.ok
    assert entry is None
    assert report.by_name("independent_reexecution").passed is False
    assert len(ledger) == 0

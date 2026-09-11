"""Failure mode 3: the receipt is well-formed but its evidence does not hold
up - bad signature, tampered body, fabricated witness, unknown task."""

from vouch.canon import digest
from vouch.identity import sign
from vouch.schema import TaskSpec, signing_payload
from vouch.verifier import verify_receipt


def _resign(receipt, key):
    receipt = dict(receipt)
    receipt["signature"] = sign(key, signing_payload(receipt))
    return receipt


def _verify(receipt, spec, harness):
    return verify_receipt(
        receipt,
        spec=spec,
        ledger=harness.ledger,
        leases=harness.leases,
        now=harness.clock.now(),
        expected_prev_hash=harness.ledger.head_hash(),
    )


def test_broken_signature_rejected(harness, sum_spec):
    r = dict(harness.execute_and_sign(sum_spec))
    r["signature"] = "00" * 64
    report = _verify(r, sum_spec, harness)
    assert not report.ok
    assert report.by_name("signature_valid").passed is False


def test_tampered_body_rejected(harness, sum_spec):
    r = dict(harness.execute_and_sign(sum_spec))
    r["output_digest"] = "sha256:" + "0" * 64  # changed after signing
    report = _verify(r, sum_spec, harness)
    assert not report.ok
    assert report.by_name("signature_valid").passed is False


def test_fabricated_witness_rejected_even_when_resigned(harness, key):
    spec = TaskSpec(
        name="sort_list",
        inputs={"items": [5, 3, 9, 1]},
        declared_postconditions=["is_permutation", "is_ordered"],
    )
    r = dict(harness.execute_and_sign(spec))
    r["witness"] = {"claimed_output": [1, 3, 9, 5]}  # not sorted
    r["output_digest"] = digest([1, 3, 9, 5])
    r = _resign(r, key)
    report = _verify(r, spec, harness)
    assert report.by_name("signature_valid").passed is True  # they did re-sign
    assert report.by_name("witness_recheck").passed is False  # ...math still fails
    assert not report.ok


def test_unknown_fixture_rejected(harness, key):
    spec = TaskSpec(
        name="sum_range", inputs={"n": 5}, declared_postconditions=["output_equals_closed_form"]
    )
    r = dict(harness.execute_and_sign(spec))
    r["task_name"] = "does_not_exist"
    r = _resign(r, key)
    report = _verify(r, spec, harness)
    assert not report.ok
    assert report.by_name("fixture_known").passed is False
    assert report.by_name("task_name_matches_spec").passed is False

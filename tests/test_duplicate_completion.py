"""Failure mode 1: the same task gets completed twice."""


def test_second_completion_is_rejected(harness, ledger, sum_spec):
    r1 = harness.execute_and_sign(sum_spec)
    rep1, entry1 = harness.submit(r1, sum_spec)
    assert rep1.ok and entry1 is not None

    r2 = harness.execute_and_sign(sum_spec)  # fresh receipt_id, fresh nonce
    assert r2["receipt_id"] != r1["receipt_id"]

    rep2, entry2 = harness.submit(r2, sum_spec)
    assert not rep2.ok
    assert entry2 is None
    assert rep2.by_name("no_duplicate_completion").passed is False
    assert len(ledger) == 1  # ledger did not grow


def test_idempotent_resubmit_of_same_receipt_is_not_a_duplicate(harness, ledger, sum_spec):
    r1 = harness.execute_and_sign(sum_spec)
    harness.submit(r1, sum_spec)

    # Exact same receipt again: caught as a replay (nonce), not as a duplicate
    # completion - the dedup check is keyed on receipt_id.
    rep, _ = harness.submit(r1, sum_spec)
    assert not rep.ok
    assert rep.by_name("no_duplicate_completion").passed is True
    assert rep.by_name("nonce_unseen").passed is False

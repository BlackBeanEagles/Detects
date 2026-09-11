"""The path that should work: run a task, get an ACCEPT, land one chained
ledger entry, and have the receipt re-verify later on its own."""

from vouch.verifier import verify_receipt


def test_happy_path_accepts_and_chains(harness, ledger, sum_spec):
    receipt = harness.execute_and_sign(sum_spec)
    assert receipt["outcome"] == "success"
    assert receipt["witness"]["claimed_output"] == 5050
    assert receipt["attempt"] == 1
    assert "succeeded on attempt 1" in receipt["detail"]

    report, entry = harness.submit(receipt, sum_spec)
    assert report.ok, report.summary()
    assert entry is not None
    assert len(ledger) == 1

    ok, msg = ledger.verify_chain()
    assert ok, msg


def test_receipt_reverifies_standalone(harness, sum_spec, clock):
    receipt = harness.execute_and_sign(sum_spec)
    harness.submit(receipt, sum_spec)

    # Later, elsewhere: no ledger head, no lease state - just the receipt.
    report = verify_receipt(receipt, spec=sum_spec, now=clock.now())
    assert report.ok, report.summary()
    assert report.by_name("signature_valid").passed
    assert report.by_name("witness_recheck").passed
    assert report.by_name("task_id_matches_spec").passed
    assert report.by_name("lease_epoch_current").skipped
    assert report.by_name("nonce_unseen").skipped


def test_tampering_with_a_ledger_entry_is_detected(harness, ledger, sum_spec):
    harness.submit(harness.execute_and_sign(sum_spec), sum_spec)
    ledger._entries[0]["receipt"]["output_digest"] = "sha256:" + "0" * 64
    ok, msg = ledger.verify_chain()
    assert not ok
    assert "tampered" in msg

"""Failure mode 2: a worker reports after its lease expired and the task was
re-assigned to someone else."""

import pytest

from vouch.harness import Harness
from vouch.identity import generate_private_key, worker_id_for
from vouch.lease import LeaseHeld
from vouch.schema import TaskSpec, task_id_for
from vouch.verifier import verify_receipt


def test_expired_owner_receipt_rejected(ledger, leases, clock):
    key_a = generate_private_key()
    key_b = generate_private_key()
    worker_a = Harness(private_key=key_a, ledger=ledger, leases=leases, clock=clock)

    spec = TaskSpec(
        name="sum_range", inputs={"n": 7}, declared_postconditions=["output_equals_closed_form"]
    )
    receipt = worker_a.execute_and_sign(spec, lease_ttl_s=10)
    assert receipt["lease_epoch"] == 1

    assert leases.holder(task_id_for(spec)) == worker_a.worker_id

    clock.advance(20)  # A's 10s lease has expired
    leases.claim(task_id_for(spec), worker_id_for(key_b), ttl_s=10, now=clock.now())
    assert leases.current_epoch(task_id_for(spec)) == 2
    assert leases.holder(task_id_for(spec)) == worker_id_for(key_b)

    report = verify_receipt(
        receipt,
        spec=spec,
        ledger=ledger,
        leases=leases,
        now=clock.now(),
        expected_prev_hash=ledger.head_hash(),
    )
    assert not report.ok
    stale = report.by_name("lease_epoch_current")
    assert stale.passed is False
    assert "current epoch=2" in stale.detail
    # nothing else should be complaining
    assert [c.name for c in report.failed()] == ["lease_epoch_current"]


def test_active_lease_blocks_a_second_worker(leases, clock):
    tid = "sha256:abc"
    assert leases.holder(tid) is None
    assert leases.current_epoch(tid) == 0
    leases.claim(tid, "ed25519:aaaa", ttl_s=10, now=clock.now())
    with pytest.raises(LeaseHeld):
        leases.claim(tid, "ed25519:bbbb", ttl_s=10, now=clock.now())

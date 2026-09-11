"""A narrated end-to-end run. Execute with:  python examples/quickstart.py

It builds a harness, completes a task, submits the receipt, tampers with a
copy, shows the verifier reject it, demonstrates independent re-execution
catching a wrong-but-plausible result, and runs one bundled adversary case.
"""

from __future__ import annotations

from vouch import (
    Harness,
    InProcessReexecutor,
    LeaseManager,
    Ledger,
    ManualClock,
    TaskSpec,
    generate_private_key,
    signing_payload,
    verify_receipt,
)
from vouch.adversary import stale_ownership
from vouch.canon import digest
from vouch.identity import sign


def main() -> None:
    clock = ManualClock()
    ledger = Ledger()
    harness = Harness(
        private_key=generate_private_key(),
        ledger=ledger,
        leases=LeaseManager(),
        clock=clock,
    )

    spec = TaskSpec(
        name="sort_list",
        inputs={"items": [9, 3, 7, 1, 3]},
        declared_postconditions=["is_permutation", "is_ordered"],
    )

    print("1. execute + sign")
    receipt = harness.execute_and_sign(spec)
    print(f"   outcome={receipt['outcome']} witness={receipt['witness']}")

    print("2. submit -> verify -> append")
    report, _entry = harness.submit(receipt, spec)
    print(f"   verdict: {'ACCEPT' if report.ok else 'REJECT'}; ledger size = {len(ledger)}")

    print("3. tamper with a copy: claim a different, unsorted result")
    forged = dict(receipt)
    forged["witness"] = {"claimed_output": [9, 3, 7, 1, 3]}
    forged["signature"] = sign(harness.key, signing_payload(forged))
    bad = verify_receipt(forged, spec=spec, ledger=ledger, leases=harness.leases, now=clock.now())
    print(f"   verdict: {'ACCEPT' if bad.ok else 'REJECT'}")
    for c in bad.failed():
        print(f"   - failed: {c.name} :: {c.detail}")

    print("4. a lie the cheap check misses: wrong nth_prime (still prime)")
    prime_spec = TaskSpec(
        name="nth_prime", inputs={"n": 10}, declared_postconditions=["output_is_prime"]
    )
    pr = dict(harness.execute_and_sign(prime_spec))  # honest answer is 29
    pr["witness"] = {"claimed_output": 7}
    pr["output_digest"] = digest(7)
    pr["signature"] = sign(harness.key, signing_payload(pr))
    without = verify_receipt(pr, spec=prime_spec, now=clock.now())
    withre = verify_receipt(pr, spec=prime_spec, now=clock.now(), reexecutor=InProcessReexecutor())
    print(f"   witness_recheck alone: {'ACCEPT' if without.ok else 'REJECT'}")
    print(f"   + independent_reexecution: {'ACCEPT' if withre.ok else 'REJECT'}")

    print("5. one bundled adversary case")
    res = stale_ownership()
    print(f"   {res.name}: rejected={not res.report.ok} (expected {res.expected_caught})")

    print("\nledger chain:", ledger.verify_chain()[1])


if __name__ == "__main__":
    main()

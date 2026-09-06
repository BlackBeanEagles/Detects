"""A narrated end-to-end run. Execute with:  python examples/quickstart.py

It builds a harness, completes a task, submits the receipt, tampers with a
copy, shows the verifier reject it, and runs one bundled adversary case.
"""

from __future__ import annotations

from vouch import (
    Harness,
    LeaseManager,
    Ledger,
    ManualClock,
    TaskSpec,
    generate_private_key,
    verify_receipt,
)
from vouch.adversary import stale_ownership
from vouch.canon import canon_bytes
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
    forged["signature"] = sign(
        harness.key, canon_bytes({k: v for k, v in forged.items() if k != "signature"})
    )
    bad = verify_receipt(forged, spec=spec, ledger=ledger, leases=harness.leases, now=clock.now())
    print(f"   verdict: {'ACCEPT' if bad.ok else 'REJECT'}")
    for c in bad.failed():
        print(f"   - failed: {c.name} :: {c.detail}")

    print("4. one bundled adversary case")
    res = stale_ownership()
    print(f"   {res.name}: rejected={not res.report.ok} (expected {res.expected_caught})")

    print("\nledger chain:", ledger.verify_chain()[1])


if __name__ == "__main__":
    main()

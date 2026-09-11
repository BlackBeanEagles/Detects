"""The harness: claim a lease, run the task, emit a signed receipt, and
gate submission through the verifier before anything touches the ledger.

``execute_and_sign`` produces a receipt. ``submit`` verifies it and appends
to the ledger only if the verdict is ACCEPT. Keeping those two steps
separate is deliberate: the ledger only ever contains receipts that passed
verification.
"""

from __future__ import annotations

import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canon import digest
from .clock import Clock, SystemClock
from .executor import execute
from .fixtures import get_fixture, registry_hash
from .identity import runtime_fingerprint, sign, worker_id_for
from .lease import LeaseManager
from .ledger import Ledger
from .reexec import Reexecutor
from .schema import (
    SCHEMA_VERSION,
    Receipt,
    Run,
    TaskSpec,
    VerdictReport,
    signing_payload,
    task_id_for,
)
from .verifier import verify_receipt


class Harness:
    def __init__(
        self,
        *,
        private_key: Ed25519PrivateKey,
        ledger: Ledger,
        leases: LeaseManager | None = None,
        clock: Clock | None = None,
        reexecutor: Reexecutor | None = None,
    ) -> None:
        self.key = private_key
        self.worker_id = worker_id_for(private_key)
        self.ledger = ledger
        self.leases = leases or LeaseManager()
        self.clock: Clock = clock or SystemClock()
        self.reexecutor = reexecutor

    def execute_and_sign(
        self,
        spec: TaskSpec,
        *,
        deadline_s: float = 5.0,
        max_attempts: int = 3,
        backoff_base_s: float = 0.01,
        lease_ttl_s: float = 30.0,
    ) -> dict:
        fixture = get_fixture(spec.name)
        if fixture is None:
            raise KeyError(f"unknown fixture: {spec.name!r}")

        task_id = task_id_for(spec)
        epoch = self.leases.claim(task_id, self.worker_id, lease_ttl_s, self.clock.now())

        res = execute(
            fixture,
            spec.inputs,
            deadline_s=deadline_s,
            max_attempts=max_attempts,
            backoff_base_s=backoff_base_s,
            clock=self.clock,
        )

        # The run's identity is its own validated object - constructing it
        # here (rather than inlining its fields into the receipt) is what
        # makes "task/run schema" a real, checked step instead of a shape
        # the receipt merely happens to match.
        run = Run(
            run_id="run:" + uuid.uuid4().hex,
            task_id=task_id,
            worker_id=self.worker_id,
            lease_epoch=epoch,
            attempt=res.attempts,
            started_at=res.started_at,
            deadline_at=res.started_at + deadline_s,
        )

        witness: dict = {}
        output_digest = None
        postconditions: list[dict] = []
        if res.outcome == "success":
            witness = fixture.make_witness(spec.inputs, res.output)
            output_digest = digest(res.output)
            ok, detail = fixture.check_witness(spec.inputs, witness)
            postconditions = [
                {"name": n, "passed": ok, "detail": detail} for n in fixture.postconditions
            ]

        receipt = {
            "schema_version": SCHEMA_VERSION,
            "receipt_id": "rcpt:" + uuid.uuid4().hex,
            "task_id": run.task_id,
            "task_name": spec.name,
            "run_id": run.run_id,
            "attempt": run.attempt,
            "lease_epoch": run.lease_epoch,
            "worker_id": run.worker_id,
            "runtime": runtime_fingerprint(registry_hash()),
            "outcome": res.outcome,
            "detail": res.detail,
            "output_digest": output_digest,
            "postconditions": postconditions,
            "witness": witness,
            "started_at": run.started_at,
            "finished_at": res.finished_at,
            "deadline_at": run.deadline_at,
            "nonce": uuid.uuid4().hex,
            "prev_ledger_hash": self.ledger.head_hash(),
        }
        receipt["signature"] = sign(self.key, signing_payload(receipt))
        # Normalize through the model so every consumer sees canonical types.
        return Receipt.model_validate(receipt).model_dump()

    def submit(self, receipt: dict, spec: TaskSpec) -> tuple[VerdictReport, dict | None]:
        report = verify_receipt(
            receipt,
            spec=spec,
            ledger=self.ledger,
            leases=self.leases,
            now=self.clock.now(),
            expected_prev_hash=self.ledger.head_hash(),
            reexecutor=self.reexecutor,
        )
        entry = self.ledger.append(receipt) if report.ok else None
        return report, entry

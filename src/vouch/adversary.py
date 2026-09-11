"""A bundled cheating agent.

Each function stages one forgery or fault and runs it past the verifier,
returning an :class:`AttackResult`. ``run_all`` executes the whole catalogue;
:mod:`vouch.scoreboard` renders it as a table. The rows marked
``expected_caught=False`` are documented limitations - things vouch does not
reject, by design - and the test-suite asserts they stay that way.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canon import canon_str, digest
from .clock import ManualClock
from .fixtures import registry_hash
from .harness import Harness
from .identity import generate_private_key, sign, worker_id_for
from .lease import LeaseManager
from .ledger import Ledger
from .reexec import InProcessReexecutor
from .schema import TaskSpec, VerdictReport, signing_payload, task_id_for
from .verifier import verify_receipt

_Env = tuple[Ed25519PrivateKey, ManualClock, Ledger, LeaseManager, Harness]
_REEXEC = InProcessReexecutor()


@dataclass
class AttackResult:
    name: str
    description: str
    report: VerdictReport
    expected_caught: bool
    expected_check: str | None


def _env() -> _Env:
    key = generate_private_key()
    clock = ManualClock()
    ledger = Ledger()
    leases = LeaseManager()
    h = Harness(private_key=key, ledger=ledger, leases=leases, clock=clock)
    return key, clock, ledger, leases, h


def _resign(receipt: dict, key: Ed25519PrivateKey) -> dict:
    receipt = dict(receipt)
    receipt["signature"] = sign(key, signing_payload(receipt))
    return receipt


def _verify(
    receipt: object,
    *,
    spec: TaskSpec,
    ledger: Ledger,
    leases: LeaseManager,
    clock: ManualClock,
    prev: str | None = None,
) -> VerdictReport:
    return verify_receipt(
        receipt,
        spec=spec,
        ledger=ledger,
        leases=leases,
        now=clock.now(),
        expected_prev_hash=ledger.head_hash() if prev is None else prev,
        reexecutor=_REEXEC,
    )


def _sum(n: int) -> TaskSpec:
    return TaskSpec(
        name="sum_range", inputs={"n": n}, declared_postconditions=["output_equals_closed_form"]
    )


# --------------------------------------------------------------------------- #
# Attacks that MUST be rejected
# --------------------------------------------------------------------------- #
def replay_receipt() -> AttackResult:
    _, clock, ledger, leases, h = _env()
    spec = _sum(10)
    r = h.execute_and_sign(spec)
    h.submit(r, spec)
    report = _verify(r, spec=spec, ledger=ledger, leases=leases, clock=clock)
    return AttackResult(
        "replay_receipt",
        "Resubmit a byte-identical receipt that is already in the ledger.",
        report,
        True,
        "nonce_unseen",
    )


def duplicate_completion() -> AttackResult:
    _, clock, ledger, leases, h = _env()
    spec = _sum(100)
    h.submit(h.execute_and_sign(spec), spec)
    r2 = h.execute_and_sign(spec)
    report = _verify(r2, spec=spec, ledger=ledger, leases=leases, clock=clock)
    return AttackResult(
        "duplicate_completion",
        "Submit a second, independently valid success for an already-finalized task.",
        report,
        True,
        "no_duplicate_completion",
    )


def stale_ownership() -> AttackResult:
    key_a = generate_private_key()
    key_b = generate_private_key()
    clock = ManualClock()
    ledger = Ledger()
    leases = LeaseManager()
    ha = Harness(private_key=key_a, ledger=ledger, leases=leases, clock=clock)
    spec = _sum(7)
    r = ha.execute_and_sign(spec, lease_ttl_s=10)
    clock.advance(20)  # A's lease expires
    leases.claim(task_id_for(spec), worker_id_for(key_b), ttl_s=10, now=clock.now())
    report = _verify(r, spec=spec, ledger=ledger, leases=leases, clock=clock)
    return AttackResult(
        "stale_ownership",
        "A's lease expired and B re-claimed the task; A then submits its receipt.",
        report,
        True,
        "lease_epoch_current",
    )


def broken_signature() -> AttackResult:
    _, clock, ledger, leases, h = _env()
    spec = _sum(5)
    r = dict(h.execute_and_sign(spec))
    r["signature"] = "00" * 64
    report = _verify(r, spec=spec, ledger=ledger, leases=leases, clock=clock)
    return AttackResult(
        "broken_signature",
        "Present a receipt whose Ed25519 signature does not verify.",
        report,
        True,
        "signature_valid",
    )


def tampered_after_signing() -> AttackResult:
    _, clock, ledger, leases, h = _env()
    spec = _sum(5)
    r = dict(h.execute_and_sign(spec))
    r["output_digest"] = "sha256:" + "0" * 64
    report = _verify(r, spec=spec, ledger=ledger, leases=leases, clock=clock)
    return AttackResult(
        "tampered_after_signing",
        "Change a field after signing; the signature no longer covers the body.",
        report,
        True,
        "signature_valid",
    )


def fabricated_witness() -> AttackResult:
    key, clock, ledger, leases, h = _env()
    spec = TaskSpec(
        name="sort_list",
        inputs={"items": [5, 3, 9, 1]},
        declared_postconditions=["is_permutation", "is_ordered"],
    )
    r = dict(h.execute_and_sign(spec))
    r["witness"] = {"claimed_output": [1, 3, 9, 5]}  # not actually sorted
    r["output_digest"] = digest([1, 3, 9, 5])
    r = _resign(r, key)
    report = _verify(r, spec=spec, ledger=ledger, leases=leases, clock=clock)
    return AttackResult(
        "fabricated_witness",
        "Re-sign a success whose witness fails the verifier's cheap re-check.",
        report,
        True,
        "witness_recheck",
    )


def task_substitution() -> AttackResult:
    _, clock, ledger, leases, h = _env()
    r = h.execute_and_sign(_sum(1))  # did the easy task
    report = _verify(
        r,
        spec=_sum(1_000_000),  # was assigned the hard one
        ledger=ledger,
        leases=leases,
        clock=clock,
    )
    return AttackResult(
        "task_substitution",
        "Do an easier task than the one assigned and submit that receipt.",
        report,
        True,
        "task_id_matches_spec",
    )


def truncated_json() -> AttackResult:
    _, clock, ledger, leases, h = _env()
    spec = _sum(5)
    raw = canon_str(h.execute_and_sign(spec))
    report = verify_receipt(
        raw[: len(raw) // 2],
        spec=spec,
        ledger=ledger,
        leases=leases,
        now=clock.now(),
        reexecutor=_REEXEC,
    )
    return AttackResult(
        "truncated_json",
        "Feed the verifier a receipt cut off mid-transmission.",
        report,
        True,
        "schema_parseable",
    )


def missing_field() -> AttackResult:
    _, clock, ledger, leases, h = _env()
    spec = _sum(5)
    r = dict(h.execute_and_sign(spec))
    r.pop("worker_id")
    report = verify_receipt(
        r, spec=spec, ledger=ledger, leases=leases, now=clock.now(), reexecutor=_REEXEC
    )
    return AttackResult(
        "missing_field",
        "Submit a receipt that is missing a required field.",
        report,
        True,
        "schema_parseable",
    )


def unsupported_schema_version() -> AttackResult:
    key, clock, ledger, leases, h = _env()
    spec = _sum(5)
    r = _resign({**dict(h.execute_and_sign(spec)), "schema_version": "0.0"}, key)
    report = verify_receipt(
        r, spec=spec, ledger=ledger, leases=leases, now=clock.now(), reexecutor=_REEXEC
    )
    return AttackResult(
        "unsupported_schema_version",
        "Downgrade schema_version (re-signed) to dodge a newer check.",
        report,
        True,
        "schema_version_supported",
    )


def proof_bomb() -> AttackResult:
    key, clock, ledger, leases, h = _env()
    spec = _sum(5)
    r = dict(h.execute_and_sign(spec))
    r["witness"] = {"claimed_output": 15, "pad": "A" * 50_000}
    r = _resign(r, key)
    report = verify_receipt(
        r, spec=spec, ledger=ledger, leases=leases, now=clock.now(), reexecutor=_REEXEC
    )
    return AttackResult(
        "proof_bomb",
        "Attach a valid-but-huge witness to exhaust the verifier.",
        report,
        True,
        "witness_size_bounded",
    )


def late_success_after_timeout() -> AttackResult:
    key, clock, ledger, leases, h = _env()
    spec = TaskSpec(
        name="slow_task",
        inputs={"sleep_s": 0.3, "n": 10},
        declared_postconditions=["output_equals_closed_form"],
    )
    r = dict(h.execute_and_sign(spec, deadline_s=0.05, max_attempts=1))
    r["outcome"] = "success"
    r["finished_at"] = r["deadline_at"] + 5.0
    r["witness"] = {"claimed_output": 55}
    r["output_digest"] = digest(55)
    r = _resign(r, key)
    report = _verify(r, spec=spec, ledger=ledger, leases=leases, clock=clock)
    return AttackResult(
        "late_success_after_timeout",
        "Take a run that timed out, flip it to success, and submit it late.",
        report,
        True,
        "within_deadline",
    )


def signed_wrong_prime() -> AttackResult:
    key, clock, ledger, leases, h = _env()
    spec = TaskSpec(name="nth_prime", inputs={"n": 10}, declared_postconditions=["output_is_prime"])
    r = dict(h.execute_and_sign(spec))
    # the 10th prime is 29; claim 7 - still prime, so the cheap check is fooled
    r["witness"] = {"claimed_output": 7}
    r["output_digest"] = digest(7)
    r = _resign(r, key)
    report = _verify(r, spec=spec, ledger=ledger, leases=leases, clock=clock)
    return AttackResult(
        "signed_wrong_prime",
        "Sign a wrong (but still prime) nth_prime result. witness_recheck only "
        "tests primality; independent re-execution recomputes 29 and catches it.",
        report,
        True,
        "independent_reexecution",
    )


# --------------------------------------------------------------------------- #
# Documented limitations - NOT rejected, by design
# --------------------------------------------------------------------------- #
def honest_but_unsound_process() -> AttackResult:
    _, clock, ledger, leases, h = _env()
    spec = _sum(100)
    r = h.execute_and_sign(spec)
    report = _verify(r, spec=spec, ledger=ledger, leases=leases, clock=clock)
    return AttackResult(
        "honest_but_unsound_process",
        "Correct result reached by unsound or wasteful reasoning. Even "
        "independent re-execution only confirms the result, not the path to "
        "it - accepted, by design.",
        report,
        False,
        None,
    )


def forged_runtime_fingerprint() -> AttackResult:
    key, clock, ledger, leases, h = _env()
    spec = _sum(100)
    r = dict(h.execute_and_sign(spec))
    r["runtime"] = {
        "code_version": "git:deadbeef",
        "python": "9.9.9",
        "platform": "trusted-enclave",
        "fixture_registry_hash": registry_hash(),
    }
    r = _resign(r, key)
    report = _verify(r, spec=spec, ledger=ledger, leases=leases, clock=clock)
    return AttackResult(
        "forged_runtime_fingerprint",
        "Lie about code_version / platform in the runtime block. The signature "
        "is valid and vouch has no attestation to contradict it - accepted.",
        report,
        False,
        None,
    )


ATTACKS: list[Callable[[], AttackResult]] = [
    replay_receipt,
    duplicate_completion,
    stale_ownership,
    broken_signature,
    tampered_after_signing,
    fabricated_witness,
    task_substitution,
    truncated_json,
    missing_field,
    unsupported_schema_version,
    proof_bomb,
    late_success_after_timeout,
    signed_wrong_prime,
    honest_but_unsound_process,
    forged_runtime_fingerprint,
]


def run_all() -> list[AttackResult]:
    return [fn() for fn in ATTACKS]

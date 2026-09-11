"""The verifier: a pure function over a receipt and some optional context.

``verify_receipt`` never mutates anything and never raises on bad input - it
returns a :class:`~vouch.schema.VerdictReport` of named checks. You can point
it at receipts it did not create; every piece of context is optional and the
corresponding checks are marked *skipped* when it is absent.

Checks, in order:

  schema_parseable              input is UTF-8 JSON matching the Receipt schema
  schema_version_supported      schema_version is one this verifier understands
  witness_size_bounded          witness fits the size cap (proof-bomb guard)
  signature_valid               Ed25519 signature verifies against worker_id
  task_id_matches_spec          receipt binds to sha256(spec)            [needs spec]
  task_name_matches_spec        receipt task_name equals spec.name        [needs spec]
  fixture_known                 task_name is a registered fixture
  witness_recheck               cheap re-derivation from inputs believes  [needs spec]
                                the claimed output
  output_digest_matches_witness output_digest summarizes the witness
  independent_reexecution       re-running the task reproduces the digest  [needs reexecutor]
  no_duplicate_completion       no earlier success for this task_id       [needs ledger]
  nonce_unseen                  nonce not already in the ledger (replay)  [needs ledger]
  lease_epoch_current           receipt epoch == current lease epoch      [needs leases]
  within_deadline               finished_at <= deadline_at
  timestamps_ordered            started_at <= finished_at
  not_from_the_future           started_at <= now + skew                  [needs now]
  prev_ledger_hash_matches      chains onto the ledger head at submission [needs head]
  success_has_witness           a success carries witness + output_digest
"""

from __future__ import annotations

from typing import Any

from .canon import canon_bytes, digest
from .fixtures import get_fixture
from .identity import verify as verify_sig
from .protocols import LeaseReadView, LedgerReadView
from .reexec import Reexecutor
from .schema import (
    SUPPORTED_SCHEMA_VERSIONS,
    TaskSpec,
    VerdictReport,
    VouchParseError,
    parse_receipt,
    signing_payload,
    task_id_for,
)


def verify_receipt(
    receipt: Any,
    *,
    spec: TaskSpec | None = None,
    ledger: LedgerReadView | None = None,
    leases: LeaseReadView | None = None,
    now: float | None = None,
    expected_prev_hash: str | None = None,
    reexecutor: Reexecutor | None = None,
    max_witness_bytes: int = 8192,
    clock_skew_s: float = 5.0,
) -> VerdictReport:
    report = VerdictReport()

    # 0. parse -------------------------------------------------------------- #
    try:
        r = parse_receipt(receipt)
    except VouchParseError as e:
        report.add("schema_parseable", False, str(e))
        return report
    report.add("schema_parseable", True, "well-formed JSON matching the Receipt schema")

    # 1. schema version ------------------------------------------------- #
    supported = r["schema_version"] in SUPPORTED_SCHEMA_VERSIONS
    report.add(
        "schema_version_supported",
        supported,
        f"schema_version={r['schema_version']!r}, supported={sorted(SUPPORTED_SCHEMA_VERSIONS)}",
    )

    # 2. witness size (proof-bomb guard) ---------------------------------- #
    wbytes = len(canon_bytes(r["witness"]))
    report.add(
        "witness_size_bounded",
        wbytes <= max_witness_bytes,
        f"witness is {wbytes} bytes (cap {max_witness_bytes})",
    )

    # 3. signature ---------------------------------------------------- #
    payload = signing_payload(r)
    sig_ok = bool(r["signature"]) and verify_sig(r["worker_id"], payload, r["signature"])
    report.add(
        "signature_valid",
        sig_ok,
        "Ed25519 signature verifies against worker_id"
        if sig_ok
        else "signature missing or does not verify (forged or tampered after signing)",
    )

    # 4. task binding ------------------------------------------------ #
    if spec is not None:
        expected_tid = task_id_for(spec)
        report.add(
            "task_id_matches_spec",
            r["task_id"] == expected_tid,
            f"receipt task_id {'==' if r['task_id'] == expected_tid else '!='} sha256(spec)",
        )
        report.add(
            "task_name_matches_spec",
            r["task_name"] == spec.name,
            f"receipt task_name={r['task_name']!r}, spec.name={spec.name!r}",
        )
    else:
        report.add("task_id_matches_spec", True, "no spec supplied", skipped=True)
        report.add("task_name_matches_spec", True, "no spec supplied", skipped=True)

    # 5. fixture + cheap proof re-check --------------------------------- #
    fx = get_fixture(r["task_name"])
    if fx is None:
        report.add("fixture_known", False, f"no fixture registered as {r['task_name']!r}")
        report.add("witness_recheck", True, "unknown fixture", skipped=True)
        report.add("output_digest_matches_witness", True, "unknown fixture", skipped=True)
    else:
        report.add("fixture_known", True, f"fixture {r['task_name']!r} is registered")
        if r["outcome"] != "success":
            report.add(
                "witness_recheck",
                True,
                f"outcome={r['outcome']}; no witness expected",
                skipped=True,
            )
            report.add(
                "output_digest_matches_witness", True, f"outcome={r['outcome']}", skipped=True
            )
        else:
            claimed = r["witness"].get("claimed_output")
            dig_ok = r["output_digest"] == digest(claimed)
            if spec is None:
                report.add(
                    "witness_recheck", True, "no spec supplied; cannot recompute", skipped=True
                )
            else:
                ok, detail = fx.check_witness(spec.inputs, r["witness"])
                report.add("witness_recheck", ok, f"independent re-check: {detail}")
            report.add(
                "output_digest_matches_witness",
                dig_ok,
                "output_digest == sha256(witness.claimed_output)"
                if dig_ok
                else "output_digest does not match the witness it summarizes",
            )

    # 5b. independent re-execution (opt-in: only if a reexecutor is given) - #
    if reexecutor is None:
        report.add("independent_reexecution", True, "no reexecutor supplied", skipped=True)
    elif spec is None or fx is None or r["outcome"] != "success":
        report.add(
            "independent_reexecution",
            True,
            "needs a spec, a known fixture, and outcome=success",
            skipped=True,
        )
    else:
        res = reexecutor(r["task_name"], spec.inputs)
        if res.status == "nondeterministic":
            report.add(
                "independent_reexecution", True, f"not re-executable: {res.detail}", skipped=True
            )
        elif res.status == "error":
            report.add(
                "independent_reexecution",
                False,
                f"re-execution failed although the receipt claims success: {res.detail}",
            )
        else:
            match = res.output_digest == r["output_digest"]
            report.add(
                "independent_reexecution",
                match,
                "re-executed output digest matches the receipt"
                if match
                else f"re-executed digest {res.output_digest} != receipt {r['output_digest']}",
            )

    # 6. duplicate completion --------------------------------------- #
    if ledger is not None and r["outcome"] == "success":
        prior = ledger.terminal_receipt_for(r["task_id"])
        dup = prior is not None and prior["receipt_id"] != r["receipt_id"]
        report.add(
            "no_duplicate_completion",
            not dup,
            "no prior success for this task_id"
            if not dup
            else f"task already finalized by {prior['receipt_id']}",  # type: ignore[index]
        )
    else:
        report.add(
            "no_duplicate_completion",
            True,
            "no ledger supplied or non-terminal outcome",
            skipped=True,
        )

    # 7. replay ----------------------------------------------------- #
    if ledger is not None:
        seen = ledger.seen_nonce(r["nonce"])
        report.add(
            "nonce_unseen",
            not seen,
            "nonce not seen before" if not seen else "nonce already in ledger (replay)",
        )
    else:
        report.add("nonce_unseen", True, "no ledger supplied", skipped=True)

    # 8. stale ownership ------------------------------------------ #
    if leases is not None:
        cur = leases.current_epoch(r["task_id"])
        fresh = cur > 0 and r["lease_epoch"] == cur
        report.add(
            "lease_epoch_current",
            fresh,
            f"receipt lease_epoch={r['lease_epoch']}, current epoch={cur}",
        )
    else:
        report.add("lease_epoch_current", True, "no lease manager supplied", skipped=True)

    # 9. deadline / clock --------------------------------------- #
    within = r["finished_at"] <= r["deadline_at"] + 1e-9
    report.add(
        "within_deadline",
        within,
        f"finished_at {'<=' if within else '>'} deadline_at "
        f"({r['finished_at']} vs {r['deadline_at']})",
    )
    report.add(
        "timestamps_ordered",
        r["started_at"] <= r["finished_at"] + 1e-9,
        "started_at <= finished_at",
    )
    if now is not None:
        not_future = r["started_at"] <= now + clock_skew_s
        report.add(
            "not_from_the_future",
            not_future,
            f"started_at <= now + skew ({r['started_at']} vs {now} + {clock_skew_s})",
        )
    else:
        report.add("not_from_the_future", True, "no reference clock supplied", skipped=True)

    # 10. ledger chain position ------------------------------- #
    if expected_prev_hash is not None:
        m = r["prev_ledger_hash"] == expected_prev_hash
        report.add(
            "prev_ledger_hash_matches",
            m,
            "prev_ledger_hash == ledger head at submission"
            if m
            else "prev_ledger_hash does not match the current ledger head",
        )
    else:
        report.add(
            "prev_ledger_hash_matches",
            True,
            "not checked (re-verification / no head supplied)",
            skipped=True,
        )

    # 11. outcome sanity ------------------------------------- #
    if r["outcome"] == "success":
        report.add(
            "success_has_witness",
            bool(r["witness"]) and r["output_digest"] is not None,
            "a successful receipt carries a witness and an output_digest",
        )
    else:
        report.add("success_has_witness", True, f"outcome={r['outcome']}", skipped=True)

    return report

"""``detects`` command line.

    detects keygen       [--out worker.key]
    detects run          --task sum_range --inputs '{"n": 100}' [--deadline 5] [--reexecute]
    detects verify       --receipt R.json [--task T --inputs '{...}'] [--reexecute] [--json]
    detects verify-chain [--ledger ledger.jsonl]
    detects ledger       [--ledger ledger.jsonl] [--json]
    detects scoreboard

Exit code is 0 on success / ACCEPT / intact chain, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .canon import canon_str
from .clock import SystemClock
from .harness import Harness
from .identity import generate_private_key, load_private_key, save_private_key, worker_id_for
from .lease import LeaseManager
from .ledger import Ledger
from .reexec import InProcessReexecutor, SubprocessReexecutor
from .schema import TaskSpec, VerdictReport
from .scoreboard import main as run_scoreboard
from .verifier import verify_receipt


def _spec(a: argparse.Namespace) -> TaskSpec | None:
    if not getattr(a, "task", ""):
        return None
    inputs = json.loads(a.inputs) if a.inputs else {}
    pcs = [s for s in a.postconditions.split(",") if s]
    return TaskSpec(name=a.task, inputs=inputs, declared_postconditions=pcs)


def _verdict_json(report: VerdictReport) -> str:
    return json.dumps(
        {
            "ok": report.ok,
            "checks": [
                {"name": c.name, "passed": c.passed, "skipped": c.skipped, "detail": c.detail}
                for c in report.checks
            ],
        },
        indent=2,
    )


def cmd_keygen(a: argparse.Namespace) -> int:
    key = generate_private_key()
    save_private_key(key, a.out)
    print(f"wrote {a.out}")
    print(f"worker_id: {worker_id_for(key)}")
    return 0


def cmd_run(a: argparse.Namespace) -> int:
    if Path(a.key).exists():
        key = load_private_key(a.key)
    else:
        key = generate_private_key()
        save_private_key(key, a.key)
        print(f"(generated new key at {a.key})", file=sys.stderr)

    ledger = Ledger(a.ledger)
    harness = Harness(
        private_key=key,
        ledger=ledger,
        leases=LeaseManager(),
        clock=SystemClock(),
        reexecutor=InProcessReexecutor() if a.reexecute else None,
    )
    spec = _spec(a)
    assert spec is not None  # --task is required on this subcommand
    receipt = harness.execute_and_sign(spec, deadline_s=a.deadline, max_attempts=a.max_attempts)
    report, entry = harness.submit(receipt, spec)

    out = Path(f"{receipt['receipt_id'].replace(':', '_')}.json")
    out.write_text(canon_str(receipt), encoding="utf-8")

    print(canon_str(receipt))
    print("\n" + report.summary(), file=sys.stderr)
    print(f"\nreceipt -> {out}", file=sys.stderr)
    verb = "appended" if entry else "NOT appended (verdict REJECT)"
    print(f"ledger  -> {a.ledger} ({len(ledger)}); {verb}", file=sys.stderr)
    return 0 if report.ok else 1


def cmd_verify(a: argparse.Namespace) -> int:
    raw = Path(a.receipt).read_text(encoding="utf-8")
    report = verify_receipt(
        raw,
        spec=_spec(a),
        ledger=None,
        leases=None,
        now=SystemClock().now(),
        expected_prev_hash=None,
        reexecutor=SubprocessReexecutor() if a.reexecute else None,
    )
    print(_verdict_json(report) if a.json else report.summary())

    if a.ledger and Path(a.ledger).exists():
        led = Ledger(a.ledger)
        chain_ok, _ = led.verify_chain()
        try:
            rid = json.loads(raw).get("receipt_id")
        except (json.JSONDecodeError, AttributeError):
            rid = None
        recorded = bool(rid) and led.get(rid) is not None
        print(
            f"\nledger {a.ledger}: chain {'intact' if chain_ok else 'BROKEN'}; "
            f"this receipt is {'recorded' if recorded else 'NOT recorded'}",
            file=sys.stderr,
        )

    if not a.json:
        print(
            "\nnote: this re-verifies a stored receipt in isolation - replay, "
            "duplicate, lease and chain-head checks only run at submission time "
            "inside the harness.",
            file=sys.stderr,
        )
    return 0 if report.ok else 1


def cmd_verify_chain(a: argparse.Namespace) -> int:
    ok, msg = Ledger(a.ledger).verify_chain()
    print(("OK   " if ok else "FAIL ") + msg)
    return 0 if ok else 1


def cmd_ledger(a: argparse.Namespace) -> int:
    rows = Ledger(a.ledger).rows()
    if a.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print(f"{a.ledger}: empty")
        return 0
    for row in rows:
        print(
            f"#{row['seq']:<3} {row['outcome']:<8} {row['task_name']:<12} "
            f"attempt={row['attempt']} {row['receipt_id']}  {row['worker']}"
        )
    return 0


def cmd_scoreboard(a: argparse.Namespace) -> int:
    return run_scoreboard()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="detects", description="agent-execution verification harness")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen", help="create an Ed25519 worker key")
    g.add_argument("--out", default="worker.key")
    g.set_defaults(fn=cmd_keygen)

    r = sub.add_parser("run", help="execute a fixture task and record a signed receipt")
    r.add_argument("--task", required=True)
    r.add_argument("--inputs", default="{}", help="JSON object, e.g. '{\"n\": 100}'")
    r.add_argument("--postconditions", default="")
    r.add_argument("--key", default="worker.key")
    r.add_argument("--ledger", default="ledger.jsonl")
    r.add_argument("--deadline", type=float, default=5.0)
    r.add_argument("--max-attempts", type=int, default=3, dest="max_attempts")
    r.add_argument(
        "--reexecute", action="store_true", help="re-run the task in-process at submit time"
    )
    r.set_defaults(fn=cmd_run)

    v = sub.add_parser("verify", help="re-verify a stored receipt")
    v.add_argument("--receipt", required=True)
    v.add_argument("--ledger", default="ledger.jsonl")
    v.add_argument("--task", default="")
    v.add_argument("--inputs", default="{}")
    v.add_argument("--postconditions", default="")
    v.add_argument("--json", action="store_true", help="machine-readable VerdictReport")
    v.add_argument(
        "--reexecute",
        action="store_true",
        help="re-run the task in a clean subprocess and compare digests",
    )
    v.set_defaults(fn=cmd_verify)

    c = sub.add_parser("verify-chain", help="check ledger hash-chain integrity")
    c.add_argument("--ledger", default="ledger.jsonl")
    c.set_defaults(fn=cmd_verify_chain)

    ls = sub.add_parser("ledger", help="list ledger entries")
    ls.add_argument("--ledger", default="ledger.jsonl")
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(fn=cmd_ledger)

    s = sub.add_parser("scoreboard", help="run the bundled adversary and print the table")
    s.set_defaults(fn=cmd_scoreboard)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    fn: Any = args.fn
    return int(fn(args))


if __name__ == "__main__":
    raise SystemExit(main())

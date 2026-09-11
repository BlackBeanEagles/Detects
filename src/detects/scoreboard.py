"""Render the bundled adversary as a table.

Every row states whether the attempt was rejected, whether that matches the
documentation, and which check did the rejecting. The "not rejected" rows at
the bottom are the honest limitations section of the README, executable.
"""

from __future__ import annotations

from .adversary import AttackResult, run_all


def _row_ok(res: AttackResult) -> bool:
    caught = not res.report.ok
    if caught != res.expected_caught:
        return False
    if res.expected_caught and res.expected_check:
        chk = res.report.by_name(res.expected_check)
        return chk is not None and not chk.passed and not chk.skipped
    return True


def format_table(rows: list[AttackResult]) -> str:
    w = max(len(r.name) for r in rows)
    head = f"{'attack'.ljust(w)}  rejected  expected  {'reason'.ljust(28)}  row"
    out = [head, "-" * len(head)]
    for r in rows:
        caught = not r.report.ok
        failed = r.report.failed()
        reason = failed[0].name if (caught and failed) else "(accepted - see notes)"
        out.append(
            f"{r.name.ljust(w)}  "
            f"{('yes' if caught else 'no').ljust(8)}  "
            f"{('yes' if r.expected_caught else 'no').ljust(8)}  "
            f"{reason.ljust(28)}  "
            f"{'ok' if _row_ok(r) else 'MISMATCH'}"
        )
    rejected = sum(1 for r in rows if not r.report.ok)
    all_ok = all(_row_ok(r) for r in rows)
    out += [
        "",
        f"{rejected}/{len(rows)} attempts rejected; "
        + (
            "all rows match the documentation"
            if all_ok
            else "SOME ROWS DO NOT MATCH - see MISMATCH above"
        ),
    ]
    return "\n".join(out)


def main() -> int:
    rows = run_all()
    print(format_table(rows))
    print()
    for r in rows:
        print(f"# {r.name}\n  {r.description}\n")
    return 0 if all(_row_ok(r) for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())

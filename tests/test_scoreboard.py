"""The bundled adversary must behave exactly as its documentation says:
every forgery rejected (by the named check), every documented limitation
still accepted."""

from vouch.adversary import run_all
from vouch.scoreboard import format_table


def test_every_attack_matches_its_documentation():
    rows = run_all()
    assert len(rows) >= 12

    problems = []
    for res in rows:
        caught = not res.report.ok
        if caught != res.expected_caught:
            problems.append(f"{res.name}: caught={caught} expected={res.expected_caught}")
            continue
        if res.expected_caught and res.expected_check:
            chk = res.report.by_name(res.expected_check)
            if chk is None or chk.passed or chk.skipped:
                problems.append(f"{res.name}: expected check {res.expected_check!r} did not fail")

    assert not problems, "\n".join(problems) + "\n\n" + format_table(rows)


def test_documented_limitations_are_accepted():
    rows = {r.name: r for r in run_all()}
    assert rows["honest_but_unsound_process"].report.ok is True
    assert rows["forged_runtime_fingerprint"].report.ok is True


def test_table_renders():
    assert "attack" in format_table(run_all())

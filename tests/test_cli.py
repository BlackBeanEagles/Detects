"""Exercise the CLI surface end to end in a temp directory."""

import json

import pytest

from vouch.cli import main


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_version(capsys):
    with pytest.raises(SystemExit) as ei:
        main(["--version"])
    assert ei.value.code == 0
    assert "vouch" in capsys.readouterr().out


def test_keygen_run_verify_chain_ledger(workdir, capsys):
    assert main(["keygen", "--out", "w.key"]) == 0
    assert (workdir / "w.key").exists()
    capsys.readouterr()

    rc = main(
        [
            "run",
            "--task",
            "sum_range",
            "--inputs",
            '{"n": 100}',
            "--key",
            "w.key",
            "--ledger",
            "l.jsonl",
        ]
    )
    assert rc == 0
    receipt_line = capsys.readouterr().out.strip().splitlines()[0]
    receipt = json.loads(receipt_line)
    assert receipt["outcome"] == "success"
    assert receipt["witness"]["claimed_output"] == 5050

    assert main(["verify-chain", "--ledger", "l.jsonl"]) == 0
    assert "1 entry" in capsys.readouterr().out

    assert main(["ledger", "--ledger", "l.jsonl", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["task_name"] == "sum_range"

    rcpt_files = list(workdir.glob("rcpt_*.json"))
    assert len(rcpt_files) == 1
    rc = main(
        [
            "verify",
            "--receipt",
            str(rcpt_files[0]),
            "--ledger",
            "l.jsonl",
            "--task",
            "sum_range",
            "--inputs",
            '{"n": 100}',
            "--json",
        ]
    )
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True
    assert any(c["name"] == "witness_recheck" and c["passed"] for c in report["checks"])


def test_verify_rejects_tampered_receipt(workdir, capsys):
    main(["keygen", "--out", "w.key"])
    main(
        [
            "run",
            "--task",
            "sum_range",
            "--inputs",
            '{"n": 10}',
            "--key",
            "w.key",
            "--ledger",
            "l.jsonl",
        ]
    )
    capsys.readouterr()
    rcpt = next(workdir.glob("rcpt_*.json"))
    doc = json.loads(rcpt.read_text())
    doc["output_digest"] = "sha256:" + "0" * 64
    rcpt.write_text(json.dumps(doc))

    rc = main(["verify", "--receipt", str(rcpt), "--json"])
    assert rc == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False


def test_run_generates_key_when_missing_and_ledger_lists_text(workdir, capsys):
    rc = main(["run", "--task", "sum_range", "--inputs", '{"n": 5}', "--ledger", "l.jsonl"])
    assert rc == 0
    assert (workdir / "worker.key").exists()  # auto-generated
    capsys.readouterr()

    assert main(["ledger", "--ledger", "l.jsonl"]) == 0
    line = capsys.readouterr().out
    assert "sum_range" in line and "success" in line

    assert main(["ledger", "--ledger", "missing.jsonl"]) == 0
    assert "empty" in capsys.readouterr().out


def test_verify_reports_ledger_membership(workdir, capsys):
    main(
        [
            "run",
            "--task",
            "sum_range",
            "--inputs",
            '{"n": 5}',
            "--key",
            "w.key",
            "--ledger",
            "l.jsonl",
        ]
    )
    capsys.readouterr()
    rcpt = next(workdir.glob("rcpt_*.json"))
    rc = main(
        [
            "verify",
            "--receipt",
            str(rcpt),
            "--ledger",
            "l.jsonl",
            "--task",
            "sum_range",
            "--inputs",
            '{"n": 5}',
        ]
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "recorded" in err and "intact" in err


def test_run_and_verify_with_reexecute_flag(workdir, capsys):
    rc = main(
        [
            "run",
            "--task",
            "nth_prime",
            "--inputs",
            '{"n": 10}',
            "--key",
            "w.key",
            "--ledger",
            "l.jsonl",
            "--reexecute",
        ]
    )
    assert rc == 0
    receipt = json.loads(capsys.readouterr().out.strip().splitlines()[0])
    assert receipt["witness"]["claimed_output"] == 29  # the 10th prime
    rcpt = next(workdir.glob("rcpt_*.json"))

    rc = main(
        [
            "verify",
            "--receipt",
            str(rcpt),
            "--task",
            "nth_prime",
            "--inputs",
            '{"n": 10}',
            "--reexecute",
            "--json",
        ]
    )
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    chk = next(c for c in report["checks"] if c["name"] == "independent_reexecution")
    assert chk["passed"] is True
    assert chk["skipped"] is False


def test_scoreboard_cli(capsys):
    assert main(["scoreboard"]) == 0
    assert "attempts rejected" in capsys.readouterr().out

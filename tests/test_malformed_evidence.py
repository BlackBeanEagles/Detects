"""Failure mode 4: the bytes are not a valid receipt at all. The verifier
must fail cleanly - one check, no traceback leaking out."""

import pytest

from vouch.canon import canon_str
from vouch.identity import sign
from vouch.schema import VouchParseError, parse_receipt, signing_payload
from vouch.verifier import verify_receipt


def test_truncated_json_fails_cleanly(harness, sum_spec):
    raw = canon_str(harness.execute_and_sign(sum_spec))
    report = verify_receipt(raw[: len(raw) // 2], spec=sum_spec)
    assert not report.ok
    assert report.by_name("schema_parseable").passed is False
    assert len(report.checks) == 1  # bailed immediately


def test_missing_required_field_fails_cleanly(harness, sum_spec):
    r = dict(harness.execute_and_sign(sum_spec))
    r.pop("worker_id")
    report = verify_receipt(r, spec=sum_spec)
    assert not report.ok
    assert report.by_name("schema_parseable").passed is False


def test_unsupported_schema_version_rejected(harness, sum_spec, key):
    r = dict(harness.execute_and_sign(sum_spec))
    r["schema_version"] = "0.0"
    r["signature"] = sign(key, signing_payload(r))
    report = verify_receipt(r, spec=sum_spec)
    assert report.by_name("schema_parseable").passed is True
    assert report.by_name("schema_version_supported").passed is False
    assert not report.ok


def test_proof_bomb_rejected(harness, sum_spec, key):
    r = dict(harness.execute_and_sign(sum_spec))
    r["witness"] = {"claimed_output": 5050, "pad": "A" * 50_000}
    r["signature"] = sign(key, signing_payload(r))
    report = verify_receipt(r, spec=sum_spec)
    assert not report.ok
    assert report.by_name("witness_size_bounded").passed is False


def test_non_utf8_input_raises_parse_error():
    with pytest.raises(VouchParseError):
        parse_receipt(b"\x80\x81\x82 not json")


def test_non_object_json_raises_parse_error():
    with pytest.raises(VouchParseError):
        parse_receipt("[1, 2, 3]")

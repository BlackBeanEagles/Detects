"""Property-based tests: the parser must never leak a non-detects exception,
canonical JSON must round-trip, and the witness checks must be sound under
random inputs."""

import json

from hypothesis import given
from hypothesis import strategies as st

from detects.canon import canon_str
from detects.fixtures import get_fixture
from detects.schema import DetectsParseError, parse_receipt
from detects.verifier import verify_receipt

_json = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(),
    lambda c: st.lists(c) | st.dictionaries(st.text(), c),
    max_leaves=25,
)


@given(st.one_of(st.binary(), st.text(), _json))
def test_parse_receipt_only_raises_detects_parse_error(blob):
    try:
        parse_receipt(blob)
    except DetectsParseError:
        pass
    except Exception as exc:
        raise AssertionError(f"parse_receipt leaked {type(exc).__name__}: {exc}") from exc


@given(st.one_of(st.binary(), st.text(max_size=200), _json))
def test_verify_receipt_never_raises(blob):
    report = verify_receipt(blob)
    assert report.ok is False  # arbitrary junk is never accepted


@given(_json)
def test_canon_str_roundtrips(value):
    assert json.loads(canon_str(value)) == value


@given(st.lists(st.integers(min_value=-50, max_value=50), max_size=30))
def test_sort_witness_accepts_truth_rejects_lies(items):
    fx = get_fixture("sort_list")
    assert fx is not None
    honest = {"claimed_output": sorted(items)}
    ok, _ = fx.check_witness({"items": items}, honest)
    assert ok

    if len(items) >= 2 and len(set(items)) >= 2:
        broken = sorted(items)
        broken[0], broken[-1] = broken[-1], broken[0]  # break the order
        ok, _ = fx.check_witness({"items": items}, {"claimed_output": broken})
        assert not ok


@given(st.lists(st.integers(min_value=0, max_value=9), max_size=40))
def test_dedupe_witness_accepts_truth(items):
    fx = get_fixture("dedupe")
    assert fx is not None
    honest = {"claimed_output": list(dict.fromkeys(items))}
    ok, detail = fx.check_witness({"items": items}, honest)
    assert ok, detail

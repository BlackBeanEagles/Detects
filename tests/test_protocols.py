"""Structural typing: Ledger and LeaseManager must satisfy the read-only
views the verifier depends on. If either drifts (a rename, a dropped
method), this fails immediately instead of surfacing as a mysterious
AttributeError deep inside verify_receipt."""

from vouch.lease import LeaseManager
from vouch.ledger import Ledger
from vouch.protocols import LeaseReadView, LedgerReadView


def test_ledger_satisfies_ledger_read_view():
    assert isinstance(Ledger(), LedgerReadView)


def test_lease_manager_satisfies_lease_read_view():
    assert isinstance(LeaseManager(), LeaseReadView)


def test_an_unrelated_object_does_not_satisfy_either():
    assert not isinstance(object(), LedgerReadView)
    assert not isinstance(object(), LeaseReadView)

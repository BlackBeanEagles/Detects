"""Structural interfaces the pure verifier depends on.

The verifier never writes and never needs a concrete class - only these
read-only views. :class:`~detects.ledger.Ledger` and
:class:`~detects.lease.LeaseManager` satisfy them structurally, and a test or
an alternate backend can supply anything else that matches.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class LedgerReadView(Protocol):
    def head_hash(self) -> str: ...

    def terminal_receipt_for(self, task_id: str) -> dict | None: ...

    def seen_nonce(self, nonce: str) -> bool: ...


@runtime_checkable
class LeaseReadView(Protocol):
    def current_epoch(self, task_id: str) -> int: ...

"""Append-only, hash-chained log of accepted receipts.

Entry N records the hash of entry N-1, so tampering with any past entry
breaks every subsequent hash. ``verify_chain`` detects that. The ledger
exposes only reads to the verifier; the harness is the sole writer.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from .canon import digest

GENESIS = "sha256:GENESIS"


class Ledger:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._entries: list[dict] = []
        if self.path and self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    self._entries.append(json.loads(line))

    # ---- reads (used by the pure verifier) -------------------------------- #
    def head_hash(self) -> str:
        return self._entries[-1]["entry_hash"] if self._entries else GENESIS

    def __len__(self) -> int:
        return len(self._entries)

    def entries(self) -> Iterator[dict]:
        return iter(list(self._entries))

    def terminal_receipt_for(self, task_id: str) -> dict | None:
        for e in self._entries:
            r: dict = e["receipt"]
            if r["task_id"] == task_id and r["outcome"] == "success":
                return r
        return None

    def seen_nonce(self, nonce: str) -> bool:
        return any(e["receipt"]["nonce"] == nonce for e in self._entries)

    def get(self, receipt_id: str) -> dict | None:
        for e in self._entries:
            if e["receipt"]["receipt_id"] == receipt_id:
                return e
        return None

    def rows(self) -> list[dict]:
        """Compact one-line-per-entry view for humans and the CLI."""
        out: list[dict] = []
        for e in self._entries:
            r = e["receipt"]
            out.append(
                {
                    "seq": e["seq"],
                    "receipt_id": r["receipt_id"],
                    "task_name": r["task_name"],
                    "outcome": r["outcome"],
                    "attempt": r["attempt"],
                    "worker": r["worker_id"][:24] + "...",
                    "entry_hash": e["entry_hash"],
                }
            )
        return out

    # ---- write ---------------------------------------------------------- #
    def append(self, receipt: dict) -> dict:
        prev = self.head_hash()
        body = {"seq": len(self._entries), "prev_hash": prev, "receipt": receipt}
        entry = {**body, "entry_hash": digest(body)}
        self._entries.append(entry)
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def verify_chain(self) -> tuple[bool, str]:
        prev = GENESIS
        for i, e in enumerate(self._entries):
            body = {"seq": e["seq"], "prev_hash": e["prev_hash"], "receipt": e["receipt"]}
            if e["seq"] != i:
                return False, f"entry {i}: seq is {e['seq']}"
            if e["prev_hash"] != prev:
                return False, f"entry {i}: prev_hash does not match entry {i - 1}"
            if e["entry_hash"] != digest(body):
                return False, f"entry {i}: entry_hash does not match contents (tampered)"
            prev = e["entry_hash"]
        return (
            True,
            f"{len(self._entries)} entr{'y' if len(self._entries) == 1 else 'ies'}, chain intact",
        )

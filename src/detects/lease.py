"""Time-limited task ownership with a monotonic fencing token.

Each time a task changes hands its *epoch* increases by one. A run records
the epoch it was claimed under; a receipt carries that epoch; the verifier
rejects any receipt whose epoch is not the current one. That is how
"stale ownership" - a slow worker reporting after its lease expired and the
task was reassigned - is caught.
"""

from __future__ import annotations

from dataclasses import dataclass

from .schema import DetectsError


class LeaseHeld(DetectsError):
    """Raised when a different worker holds an unexpired lease on the task."""


@dataclass
class _Lease:
    holder: str
    epoch: int
    expires_at: float


class LeaseManager:
    def __init__(self) -> None:
        self._leases: dict[str, _Lease] = {}
        self._max_epoch: dict[str, int] = {}

    def claim(self, task_id: str, worker_id: str, ttl_s: float, now: float) -> int:
        cur = self._leases.get(task_id)
        if cur is not None and now < cur.expires_at:
            if cur.holder != worker_id:
                raise LeaseHeld(
                    f"task {task_id[:20]}... held by {cur.holder[:24]}... "
                    f"for another {cur.expires_at - now:.1f}s"
                )
            cur.expires_at = now + ttl_s  # same holder renews; epoch unchanged
            return cur.epoch
        epoch = self._max_epoch.get(task_id, 0) + 1
        self._max_epoch[task_id] = epoch
        self._leases[task_id] = _Lease(worker_id, epoch, now + ttl_s)
        return epoch

    def current_epoch(self, task_id: str) -> int:
        return self._max_epoch.get(task_id, 0)

    def holder(self, task_id: str) -> str | None:
        lease = self._leases.get(task_id)
        return lease.holder if lease else None

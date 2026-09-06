"""The deterministic task / run / receipt schema.

Three content-addressed objects:

* ``TaskSpec``  - what was asked. ``task_id`` = sha256(canonical(spec)).
* ``Run``       - one attempt by one worker under one lease epoch.
* ``Receipt``   - the immutable, signed evidence that a run happened, binding
  task identity, run identity and source/runtime identity together.

``VerdictReport`` is what the verifier returns: an ordered list of named
checks, each pass / fail / skipped.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .canon import canon_bytes, digest

SCHEMA_VERSION = "1.0"
SUPPORTED_SCHEMA_VERSIONS = {"1.0"}


class VouchError(Exception):
    """Base class for every error vouch raises on purpose."""


class VouchParseError(VouchError, ValueError):
    """Raised when raw input cannot be parsed into a Receipt at all
    (not valid UTF-8 / not JSON / not an object / fails schema validation)."""


class TaskSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    inputs: dict[str, Any] = Field(default_factory=dict)
    declared_postconditions: list[str] = Field(default_factory=list)


def task_id_for(spec: TaskSpec | dict) -> str:
    """Deterministic content address of a task spec."""
    d = spec.model_dump() if isinstance(spec, TaskSpec) else dict(spec)
    return digest(
        {
            "name": d["name"],
            "inputs": d.get("inputs", {}),
            "declared_postconditions": sorted(d.get("declared_postconditions", [])),
        }
    )


class Run(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    task_id: str
    worker_id: str
    lease_epoch: int
    attempt: int
    started_at: float
    deadline_at: float


class Receipt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    receipt_id: str
    task_id: str
    task_name: str
    run_id: str
    attempt: int
    lease_epoch: int
    worker_id: str
    runtime: dict[str, Any]
    outcome: Literal["success", "failure", "timeout"]
    output_digest: str | None
    postconditions: list[dict[str, Any]]
    witness: dict[str, Any]
    started_at: float
    finished_at: float
    deadline_at: float
    nonce: str
    prev_ledger_hash: str
    signature: str | None = None

    def unsigned(self) -> dict:
        d = self.model_dump()
        d.pop("signature", None)
        return d

    def signing_payload(self) -> bytes:
        return canon_bytes(self.unsigned())


def parse_receipt(raw: Any) -> dict:
    """Parse arbitrary input into a normalized receipt dict, or raise
    ``VouchParseError``. This is the single choke point that turns malformed
    evidence into a clean, typed failure instead of a traceback."""
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = bytes(raw).decode("utf-8")
        except UnicodeDecodeError as e:
            raise VouchParseError(f"not valid UTF-8: {e}") from e
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as e:
            raise VouchParseError(f"not valid JSON: {e}") from e
    if not isinstance(raw, dict):
        raise VouchParseError(f"receipt must be a JSON object, got {type(raw).__name__}")
    try:
        return Receipt.model_validate(raw).model_dump()
    except ValidationError as e:
        raise VouchParseError(f"failed schema validation: {e.error_count()} error(s)") from e


# --------------------------------------------------------------------------- #
# Verdict reporting
# --------------------------------------------------------------------------- #
@dataclass
class Check:
    name: str
    passed: bool
    detail: str = ""
    skipped: bool = False


@dataclass
class VerdictReport:
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, passed: bool, detail: str = "", skipped: bool = False) -> None:
        self.checks.append(Check(name, bool(passed), detail, skipped))

    @property
    def ok(self) -> bool:
        return all(c.passed for c in self.checks if not c.skipped)

    def failed(self) -> list[Check]:
        return [c for c in self.checks if not c.passed and not c.skipped]

    def by_name(self, name: str) -> Check | None:
        for c in self.checks:
            if c.name == name:
                return c
        return None

    def summary(self) -> str:
        lines = [f"verdict: {'ACCEPT' if self.ok else 'REJECT'}"]
        for c in self.checks:
            mark = "skip" if c.skipped else ("pass" if c.passed else "FAIL")
            lines.append(f"  [{mark}] {c.name}" + (f" - {c.detail}" if c.detail else ""))
        return "\n".join(lines)

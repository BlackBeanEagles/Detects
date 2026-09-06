"""Canonical serialization and content hashing.

Every identifier and every signature in vouch is computed over *canonical
JSON*: UTF-8, keys sorted, no insignificant whitespace, no NaN/Infinity.
Two structurally equal objects therefore always produce the same bytes, the
same SHA-256 digest, and the same signature. That property is what
"deterministic" means throughout this project.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

__all__ = ["canon_bytes", "canon_str", "digest", "sha256_hex"]


def canon_str(obj: Any) -> str:
    """Return the canonical JSON string for ``obj``."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canon_bytes(obj: Any) -> bytes:
    """Return the canonical JSON encoding of ``obj`` as UTF-8 bytes."""
    return canon_str(obj).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj: Any) -> str:
    """Content address of ``obj`` as ``"sha256:<hex>"``."""
    return "sha256:" + sha256_hex(canon_bytes(obj))

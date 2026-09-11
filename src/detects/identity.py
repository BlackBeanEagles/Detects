"""Source / runtime identity.

A worker is identified by an Ed25519 public key, rendered as
``ed25519:<hex>``. It signs every receipt with the matching private key.
Anyone can verify a signature; nobody can forge one without the private key.

LIMITATION (see README): this is a *self-asserted* identity. The keypair is
generated locally, not rooted in any hardware or certificate authority. A
worker that controls its own private key can still lie about anything the
verifier cannot independently recompute - in particular the free-text
contents of the ``runtime`` block.
"""

from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = [
    "generate_private_key",
    "load_private_key",
    "runtime_fingerprint",
    "save_private_key",
    "sign",
    "verify",
    "worker_id_for",
]


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _private_raw(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _public_raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def save_private_key(key: Ed25519PrivateKey, path: str | Path) -> None:
    Path(path).write_text(_private_raw(key).hex(), encoding="ascii")


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    raw = bytes.fromhex(Path(path).read_text(encoding="ascii").strip())
    return Ed25519PrivateKey.from_private_bytes(raw)


def worker_id_for(key: Ed25519PrivateKey) -> str:
    return "ed25519:" + _public_raw(key.public_key()).hex()


def sign(key: Ed25519PrivateKey, payload: bytes) -> str:
    return key.sign(payload).hex()


def verify(worker_id: str, payload: bytes, signature_hex: str) -> bool:
    """Return True iff ``signature_hex`` is a valid signature of ``payload``
    by the key named in ``worker_id``. Never raises."""
    if not isinstance(worker_id, str) or not worker_id.startswith("ed25519:"):
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(worker_id.split(":", 1)[1]))
        pub.verify(bytes.fromhex(signature_hex), payload)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _git_sha() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )
        return "git:" + out.stdout.strip()
    except Exception:
        return "git:unknown"


def runtime_fingerprint(fixture_registry_hash: str) -> dict:
    """A best-effort description of the code and machine that produced a
    receipt. Its contents are NOT independently verifiable - see module
    docstring."""
    return {
        "code_version": _git_sha(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "fixture_registry_hash": fixture_registry_hash,
    }

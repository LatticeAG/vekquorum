"""Domain-separated hashing and signature-message construction.

D(k,x)  = SHA256(UTF8("VekQuorum/" + k + "/1\n") || J(x))
H(k,x)  = "vq1:" + lowercase_hex(D(k,x))
S(k,x)  = UTF8("VekQuorum/sign/" + k + "/1\n") || D(k,x)   (Ed25519 message)

Allowed kinds: action, policy, authority, enrichment, vote, event,
checkpoint, bundle, output, request.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .canon import J
from .errors import VQError

KINDS = {"action", "policy", "authority", "enrichment", "vote", "event",
         "checkpoint", "bundle", "output", "request"}

HASH_RE = re.compile(r"^vq1:[0-9a-f]{64}$")
PUBKEY_RE = re.compile(r"^[0-9a-f]{64}$")
SIG_RE = re.compile(r"^[0-9a-f]{128}$")


def D(kind: str, value: Any) -> bytes:
    if kind not in KINDS:
        raise VQError("SCHEMA_INVALID", details={"reason": "unknown_hash_kind"})
    return hashlib.sha256(
        ("VekQuorum/" + kind + "/1\n").encode("utf-8") + J(value)).digest()


def H(kind: str, value: Any) -> str:
    return "vq1:" + D(kind, value).hex()


def signing_message(kind: str, value: Any) -> bytes:
    return ("VekQuorum/sign/" + kind + "/1\n").encode("utf-8") + D(kind, value)


def validate_hash(value: object, field: str = "hash") -> str:
    if not isinstance(value, str) or not HASH_RE.match(value):
        raise VQError("SCHEMA_INVALID", details={"field": field})
    return value


def validate_public_key(value: object, field: str = "public_key") -> str:
    if not isinstance(value, str) or not PUBKEY_RE.match(value):
        raise VQError("INVALID_KEY", details={"field": field})
    return value


def validate_signature_encoding(value: object,
                                field: str = "signature") -> str:
    if not isinstance(value, str) or not SIG_RE.match(value):
        raise VQError("INVALID_SIGNATURE_ENCODING", details={"field": field})
    return value

"""Locked vq/1 identifier prefixes and generation.

IDs are opaque identifiers, not secrets or authorization credentials.  Every
boundary validates prefix and the 21-character suffix alphabet.
"""

from __future__ import annotations

import secrets

from .errors import VQError

ALPHABET = "_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
SUFFIX_LEN = 21

PREFIXES = {
    "tenant": "vqt_",
    "executor": "vqx_",
    "policy": "vqp_",
    "proposal": "vqa_",
    "operation": "vqo_",
    "principal": "vqu_",
    "key": "vqk_",
    "nonce": "vqn_",
    "event": "vqr_",
    "stream": "vqs_",
    "dispatch": "vqd_",
    "escalation": "vqe_",
    "trace": "vqc_",
    "request": "vqi_",
}

PREFIX_TO_KIND = {v: k for k, v in PREFIXES.items()}

# Reserved coordinator-autonomous principal: never enrollable, never a caller.
SYSTEM_PRINCIPAL = "vqu_" + "0" * SUFFIX_LEN


# Coordinator allocation kinds -> wire prefix.  Proposal-stream resources and
# admin-stream resources draw from separate counters so a deterministic test
# source can reproduce fixture bytes (receipt_id vqr_<seq> on each stream).
ALLOC_PREFIXES = {
    "proposal_stream": "vqs_",
    "admin_stream": "vqs_",
    "receipt": "vqr_",
    "admin_receipt": "vqr_",
    "dispatch": "vqd_",
    "escalation": "vqe_",
}


def new_id(kind: str) -> str:
    prefix = ALLOC_PREFIXES[kind] if kind in ALLOC_PREFIXES else PREFIXES[kind]
    return prefix + "".join(secrets.choice(ALPHABET) for _ in range(SUFFIX_LEN))


def validate_id(value: object, kind: str) -> str:
    if not isinstance(value, str):
        raise VQError("INVALID_ID", details={"expected": kind})
    prefix = PREFIXES[kind]
    if not value.startswith(prefix):
        raise VQError("INVALID_ID", details={"expected": kind, "got": value[:8]})
    suffix = value[len(prefix):]
    if len(suffix) != SUFFIX_LEN or any(c not in ALPHABET for c in suffix):
        raise VQError("INVALID_ID", details={"expected": kind})
    if kind == "principal" and value == SYSTEM_PRINCIPAL:
        raise VQError("INVALID_ID", details={"reason": "reserved_principal"})
    return value


def validate_system_principal(value: object) -> str:
    """Principal slot that may name the reserved system actor."""
    if value == SYSTEM_PRINCIPAL:
        return SYSTEM_PRINCIPAL
    return validate_id(value, "principal")


def looks_like_id(value: object, kind: str) -> bool:
    try:
        validate_id(value, kind)
        return True
    except VQError:
        return False


class SequentialIds:
    """Deterministic test-only ID source: ident(prefix, n) from the spec's
    fixture block.  Production callers must use the random default."""

    def __init__(self, counters: Optional[dict] = None):
        self.counters: dict[str, int] = dict(counters or {})

    def __call__(self, kind: str) -> str:
        n = self.counters.get(kind, 0) + 1
        self.counters[kind] = n
        prefix = ALLOC_PREFIXES[kind] if kind in ALLOC_PREFIXES else PREFIXES[kind]
        return prefix + str(n).zfill(SUFFIX_LEN)


def ident(prefix: str, n: int) -> str:
    """Mirror of the spec fixture helper."""
    return prefix + str(n).zfill(SUFFIX_LEN)

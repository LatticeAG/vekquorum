"""VekQuorum vq/1 stable error codes and the Failure envelope.

Codes are the machine-stable catalog from the protocol; `Result.code` values
emitted by executor adapters are adapter-namespaced and deliberately share the
string space without belonging to this catalog.
"""

from __future__ import annotations

from typing import Any, Optional


class VQError(Exception):
    """Coordinator/SDK error carrying a stable protocol code."""

    def __init__(self, code: str, retryable: bool = False,
                 details: Optional[dict[str, Any]] = None,
                 request_id: Optional[str] = None):
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.details = details or {}
        self.request_id = request_id

    def to_failure(self) -> dict[str, Any]:
        return {"error": {"code": self.code, "retryable": self.retryable,
                          "request_id": self.request_id, "details": self.details}}


def failure(code: str, retryable: bool = False,
            request_id: Optional[str] = None,
            details: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    return {"error": {"code": code, "retryable": retryable,
                      "request_id": request_id, "details": details or {}}}


# Stable code -> (http_status, retryable).  Codes not listed as retryable are
# never retryable.
CATALOG: dict[str, tuple[int, bool]] = {
    "MALFORMED_JSON": (400, False),
    "DUPLICATE_KEY": (400, False),
    "INVALID_UTF8": (400, False),
    "UNKNOWN_FIELD": (400, False),
    "SCHEMA_INVALID": (400, False),
    "INVALID_ID": (400, False),
    "NUMBER_PROFILE": (400, False),
    "INVALID_KEY": (400, False),
    "INVALID_SIGNATURE_ENCODING": (400, False),
    "UNAUTHENTICATED": (401, False),
    "FORBIDDEN": (403, False),
    "TENANT_MISMATCH": (403, False),
    "UNTRUSTED": (403, False),
    "NOT_FOUND": (404, False),
    "METHOD_NOT_ALLOWED": (405, False),
    "REVISION_CONFLICT": (409, True),
    "EPOCH_CONFLICT": (409, True),
    "IDEMPOTENCY_CONFLICT": (409, False),
    "POLICY_VERSION_CONFLICT": (409, False),
    "VOTE_CONFLICT": (409, False),
    "STATE_CONFLICT": (409, False),
    "OPERATION_CONSUMED": (409, False),
    "NONCE_REUSED": (409, False),
    "ACTIVE_OPERATION": (409, False),
    "EQUIVOCATION": (409, False),
    "EXPIRED": (410, False),
    "PROOF_PRUNED": (410, False),
    "BODY_TOO_LARGE": (413, False),
    "PROOF_TOO_LARGE": (413, False),
    "UNSUPPORTED_MEDIA_TYPE": (415, False),
    "HASH_MISMATCH": (422, False),
    "BAD_SIGNATURE": (422, False),
    "POLICY_INVALID": (422, False),
    "UNKNOWN_TOOL": (422, False),
    "KEY_NOT_ENROLLED": (422, False),
    "KEY_REVOKED": (422, False),
    "ACTION_MUTATED": (422, False),
    "QUORUM_NOT_MET": (422, False),
    "PRECONDITION_CHANGED": (422, False),
    "TRUST_MISMATCH": (422, False),
    "DELIVERY_LIMIT": (422, False),
    "VERSION_UNSUPPORTED": (426, False),
    "RATE_LIMITED": (429, True),
    "STORAGE_UNAVAILABLE": (503, True),
    "GATE_UNAVAILABLE": (503, True),
    "COORDINATOR_BUSY": (503, True),
    "CLOCK_UNSAFE": (503, True),
    "ADAPTER_UNAVAILABLE": (503, True),
    "RESTORE_UNSAFE": (503, False),
    "HOSTED_UNAVAILABLE": (501, False),
}

# Verifier check codes that are not Failure codes.
CHECK_CODES = {"OK", "NOT_RUN", "MISSING_EVIDENCE", "CHAIN_BREAK",
               "CHECKPOINT_MISMATCH", "ILLEGAL_TRANSITION"}


def http_status(code: str) -> int:
    return CATALOG.get(code, (500, False))[0]


def is_retryable(code: str) -> bool:
    return CATALOG.get(code, (500, False))[1]


# Failure code -> CLI exit status (spec exit table).
def exit_code_for(code: str) -> int:
    if code in ("MALFORMED_JSON", "DUPLICATE_KEY", "INVALID_UTF8",
                "UNKNOWN_FIELD", "SCHEMA_INVALID", "INVALID_ID",
                "NUMBER_PROFILE", "USAGE", "CONFIG_INVALID"):
        return 2
    if code in ("HASH_MISMATCH", "BAD_SIGNATURE", "INVALID_SIGNATURE_ENCODING",
                "INVALID_KEY", "UNTRUSTED", "PROOF_PRUNED"):
        return 3
    if code == "QUORUM_NOT_MET":
        return 4
    if code.endswith("_CONFLICT") or code in (
            "OPERATION_CONSUMED", "NONCE_REUSED", "ACTIVE_OPERATION",
            "EQUIVOCATION", "POLICY_VERSION_CONFLICT"):
        return 5
    if code in ("UNAUTHENTICATED", "FORBIDDEN", "TENANT_MISMATCH"):
        return 6
    if code == "RATE_LIMITED" or code.endswith("_UNAVAILABLE") or code in (
            "COORDINATOR_BUSY", "CLOCK_UNSAFE", "RESTORE_UNSAFE",
            "NOT_IMPLEMENTED"):
        return 7
    if code in ("EFFECT_UNKNOWN",):
        return 8
    if code in ("EXECUTION_FAILED",):
        return 9
    return 1

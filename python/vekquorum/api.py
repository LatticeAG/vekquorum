"""Pure vq/1 calls: canonicalize, hashAction, signVote, verifyProof inputs.

These functions are side-effect free: no network, no clock, no storage.
"""

from __future__ import annotations

from typing import Any, Optional

from . import schema
from .canon import canonicalize as _canonicalize
from .ed25519 import public_key_of, sign as ed_sign, verify as ed_verify
from .errors import VQError
from .hashing import H, signing_message


def canonicalize(raw_utf8: bytes | str) -> str:
    """Strict raw JSON -> canonical UTF-8 (RFC 8785 numeric domain)."""
    return _canonicalize(raw_utf8)


def hash_action(action: Any) -> str:
    """Validate an Action under the closed vq/1 schema and return its hash."""
    a = schema.action(action)
    return H("action", a)


def _check_enrichment_binding(action: dict, enrichment: Any) -> None:
    if enrichment is None:
        if action["enrichment_hash"] is not None:
            raise VQError("HASH_MISMATCH",
                          details={"reason": "enrichment_absent"})
    else:
        expected = H("enrichment", enrichment)
        if action["enrichment_hash"] != expected:
            raise VQError("HASH_MISMATCH",
                          details={"reason": "enrichment_hash"})


def sign_vote(*, action: Any, policy: Any, enrichment: Any,
              key_id: Any, decision: Any, confirm_hash: Any,
              private_key: bytes) -> dict:
    """Produce a SignedVote after full binding validation.

    ``private_key`` is the raw 32-byte Ed25519 seed, passed out of band by the
    caller; it never enters the vote or any proof object.
    """
    req = schema.sign_request({
        "action": action, "policy": policy, "enrichment": enrichment,
        "key_id": key_id, "decision": decision,
        "confirm_hash": confirm_hash})
    a, p = req["action"], req["policy"]
    if H("action", a) != req["confirm_hash"]:
        raise VQError("HASH_MISMATCH", details={"reason": "confirm_hash"})
    _check_enrichment_binding(a, req["enrichment"])
    member = next((m for m in p["roster"] if m["key_id"] == req["key_id"]),
                  None)
    if member is None:
        raise VQError("KEY_NOT_ENROLLED", details={"key_id": req["key_id"]})
    if public_key_of(private_key).hex() != member["public_key"]:
        raise VQError("INVALID_KEY", details={"key_id": req["key_id"]})
    body = {"v": 1, "action_hash": H("action", a),
            "policy_hash": H("policy", p), "key_id": req["key_id"],
            "decision": req["decision"]}
    return {"body": body,
            "signature": ed_sign(private_key, signing_message("vote", body)).hex()}


def tally(*, action: Any, policy: Any, votes: list) -> dict:
    """Verify every supplied vote's signature and binding, then count.

    Returns approvals (distinct principals with a valid approve), human
    approvals, and whether the policy is satisfied.  Any invalid vote raises.
    """
    a = schema.action(action)
    p = schema.policy(policy)
    checked = [schema.signed_vote(v) for v in votes]
    action_hash = H("action", a)
    policy_hash = H("policy", p)
    approved_principals: set[str] = set()
    human_principals: set[str] = set()
    seen_keys: set[str] = set()
    for vote in checked:
        body = vote["body"]
        if body["action_hash"] != action_hash or \
                body["policy_hash"] != policy_hash:
            raise VQError("HASH_MISMATCH", details={"vote": body["key_id"]})
        member = next((m for m in p["roster"]
                       if m["key_id"] == body["key_id"]), None)
        if member is None:
            raise VQError("KEY_NOT_ENROLLED",
                          details={"key_id": body["key_id"]})
        if body["key_id"] in seen_keys:
            raise VQError("VOTE_CONFLICT", details={"key_id": body["key_id"]})
        seen_keys.add(body["key_id"])
        ed_verify(bytes.fromhex(member["public_key"]),
                  bytes.fromhex(vote["signature"]),
                  signing_message("vote", body))
        if body["decision"] == "approve":
            approved_principals.add(member["principal_id"])
            if member["kind"] == "human":
                human_principals.add(member["principal_id"])
    satisfied = (len(approved_principals) >= p["threshold"]
                 and (not p["require_human"] or len(human_principals) >= 1))
    return {"approvals": len(approved_principals),
            "human_approvals": len(human_principals),
            "satisfied": satisfied}

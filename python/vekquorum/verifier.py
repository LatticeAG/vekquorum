"""Offline proof verifier for vq.visreceipt/1 bundles.

Implements the ordered algorithm: schema -> binding -> trust -> signatures ->
chain -> replay -> quorum.  A structurally readable proof always returns all
seven checks, with NOT_RUN for checks behind a failed prerequisite.

The verifier performs no network access and no execution; freshness is always
``offline_unchecked`` and consumption can only be ``issuer_attested`` for
intact committed evidence — an offline verifier cannot prove durable
non-reuse across databases.
"""

from __future__ import annotations

from typing import Any, Optional

from . import schema
from .canon import J
from .ed25519 import verify as ed_verify
from .errors import VQError
from .hashing import H, signing_message

CHECK_ORDER = ("schema", "binding", "trust", "signatures", "chain", "replay",
               "quorum")

_LIVE = {"OPEN", "READY"}
_CONSUMED_STATES = {"DISPATCHING", "SUCCEEDED", "FAILED", "UNKNOWN"}


def _result(integrity: str, authorization: str, execution: str,
            freshness: str, consumption: str,
            checks: list[dict], bundle_hash: Optional[str]) -> dict:
    return {"integrity": integrity, "authorization": authorization,
            "execution": execution, "freshness": freshness,
            "consumption": consumption, "checks": checks,
            "bundle_hash": bundle_hash}


def _checks(**kw) -> list[dict]:
    out = []
    for name in CHECK_ORDER:
        state = kw.get(name, ("NOT_RUN",))
        if state == "ok":
            out.append({"id": name, "ok": True, "code": "OK"})
        elif state == "NOT_RUN":
            out.append({"id": name, "ok": False, "code": "NOT_RUN"})
        else:
            out.append({"id": name, "ok": False, "code": state})
    return out


def verify_proof(proof_obj: Any, trust: Any) -> dict:
    """Verify a proof against a caller-supplied Trust (out-of-band input)."""
    # 1. size/parse/profile/schema
    try:
        if isinstance(proof_obj, (bytes, str)):
            raw = proof_obj
            if len(raw if isinstance(raw, bytes)
                   else raw.encode("utf-8")) > schema.MAX_PROOF_BYTES:
                raise VQError("PROOF_TOO_LARGE")
            from .jsonparse import parse_json
            proof_obj = parse_json(raw, profile="wire")
        proof = schema.proof(proof_obj)
    except VQError as e:
        checks = _checks(schema=e.code)
        return _result("invalid", "not_assessed", "not_started",
                       "offline_unchecked", "not_attested", checks, None)
    if len(proof["events"]) > schema.MAX_PROOF_EVENTS:
        return _result("invalid", "not_assessed", "not_started",
                       "offline_unchecked", "not_attested",
                       _checks(schema="SCHEMA_INVALID"), None)

    # 2. binding
    try:
        _binding(proof)
        binding = "ok"
    except VQError as e:
        binding = e.code

    # 3. trust (needs binding to know hashes, but evaluated in order)
    trusted = None
    if binding == "ok":
        try:
            trusted = _trust(proof, trust)
            tr = "ok"
        except VQError as e:
            tr = e.code
    else:
        tr = "NOT_RUN"
    if tr != "ok" or binding != "ok":
        status = "invalid"
        checks = _checks(schema="ok", binding=binding, trust=tr)
        return _result(status, "not_assessed", "not_started",
                       "offline_unchecked", "not_attested", checks,
                       H("bundle", proof))

    # 4. signatures
    try:
        _signatures(proof, trusted)
        sig = "ok"
    except VQError as e:
        sig = e.code
    if sig != "ok":
        integrity = "incomplete" if sig == "MISSING_EVIDENCE" else "invalid"
        return _result(integrity, "not_assessed", "not_started",
                       "offline_unchecked", "not_attested",
                       _checks(schema="ok", binding="ok", trust="ok",
                               signatures=sig), H("bundle", proof))

    # 5. chain
    try:
        _chain(proof)
        ch = "ok"
    except VQError as e:
        ch = e.code
    if ch != "ok":
        integrity = "incomplete" if ch in ("MISSING_EVIDENCE",
                                           "CHECKPOINT_MISMATCH") \
            else "invalid"
        return _result(integrity, "not_assessed", "not_started",
                       "offline_unchecked", "not_attested",
                       _checks(schema="ok", binding="ok", trust="ok",
                               signatures="ok", chain=ch),
                       H("bundle", proof))

    # 6. replay
    try:
        final = _replay(proof)
        rep = "ok"
    except VQError as e:
        rep = e.code
        final = None
    if rep != "ok":
        integrity = "incomplete" if rep == "MISSING_EVIDENCE" else "invalid"
        return _result(integrity, "not_assessed", "not_started",
                       "offline_unchecked", "not_attested",
                       _checks(schema="ok", binding="ok", trust="ok",
                               signatures="ok", chain="ok", replay=rep),
                       H("bundle", proof))

    # 7. quorum
    quorum_ok, satisfied_at_commit = _quorum(proof, final)
    qcheck = "ok" if quorum_ok else "QUORUM_NOT_MET"

    checks = _checks(schema="ok", binding="ok", trust="ok", signatures="ok",
                     chain="ok", replay="ok", quorum=qcheck)
    authorization = "satisfied" if (
        final["state"] in ("READY", "DISPATCHING", "SUCCEEDED", "FAILED",
                           "UNKNOWN") and satisfied_at_commit) \
        else "not_satisfied"
    if final["state"] in ("SUCCEEDED", "FAILED", "UNKNOWN"):
        execution = {"SUCCEEDED": "reported_success",
                     "FAILED": "reported_failure",
                     "UNKNOWN": "unknown"}[final["state"]]
    elif final["state"] == "DISPATCHING":
        execution = "unknown"
    else:
        execution = "not_started"
    consumption = "issuer_attested" if final["state"] in _CONSUMED_STATES \
        else "not_attested"
    return _result("valid", authorization, execution, "offline_unchecked",
                   consumption, checks, H("bundle", proof))


# -- step 2 -----------------------------------------------------------------

def _binding(proof: dict) -> None:
    a, p, auth = proof["action"], proof["policy"], proof["authority"]
    if H("policy", p) != a["policy_hash"]:
        raise VQError("HASH_MISMATCH", details={"what": "policy"})
    if p["tenant"] != a["tenant"] or auth["tenant"] != a["tenant"]:
        raise VQError("HASH_MISMATCH", details={"what": "tenant"})
    if p["executor_id"] != a["executor_id"] or \
            auth["executor_id"] != a["executor_id"]:
        raise VQError("HASH_MISMATCH", details={"what": "executor"})
    if p["environment"] != a["environment"]:
        raise VQError("HASH_MISMATCH", details={"what": "environment"})
    if auth["policy_hash"] != a["policy_hash"]:
        raise VQError("HASH_MISMATCH", details={"what": "authority_policy"})
    if auth["epoch"] != a["authority_epoch"]:
        raise VQError("HASH_MISMATCH", details={"what": "authority_epoch"})
    enr = proof["enrichment"]
    if enr is None:
        if a["enrichment_hash"] is not None:
            raise VQError("HASH_MISMATCH", details={"what": "enrichment"})
    elif a["enrichment_hash"] != H("enrichment", enr):
        raise VQError("HASH_MISMATCH", details={"what": "enrichment"})
    if proof["checkpoint"]["body"]["authority_epoch"] != auth["epoch"]:
        raise VQError("HASH_MISMATCH",
                      details={"what": "checkpoint_epoch"})
    if proof["checkpoint"]["body"]["tenant"] != a["tenant"]:
        raise VQError("HASH_MISMATCH", details={"what": "checkpoint_tenant"})
    if proof["checkpoint"]["body"]["proposal_id"] != a["proposal_id"]:
        raise VQError("HASH_MISMATCH",
                      details={"what": "checkpoint_proposal"})
    action_hash = H("action", a)
    for vote in proof["votes"]:
        if vote["body"]["action_hash"] != action_hash or \
                vote["body"]["policy_hash"] != a["policy_hash"]:
            raise VQError("HASH_MISMATCH", details={"what": "vote"})
    for e in proof["events"]:
        if e["body"]["tenant"] != a["tenant"] or \
                e["body"]["proposal_id"] != a["proposal_id"]:
            raise VQError("HASH_MISMATCH", details={"what": "event_scope"})


# -- step 3 -----------------------------------------------------------------

def _trust(proof: dict, trust_obj: Any) -> dict:
    try:
        t = schema.trust(trust_obj)
    except VQError as e:
        raise VQError("UNTRUSTED", details={"reason": e.code}) from None
    a = proof["action"]
    if (t["tenant"] != a["tenant"] or t["executor_id"] != a["executor_id"]
            or t["environment"] != a["environment"]):
        raise VQError("UNTRUSTED", details={"reason": "scope"})
    if a["policy_hash"] not in t["policy_hashes"]:
        raise VQError("UNTRUSTED", details={"reason": "policy"})
    # the pinned policy must independently satisfy roster invariants
    try:
        schema.policy(proof["policy"])
    except VQError as e:
        raise VQError("UNTRUSTED", details={"reason": "policy_invalid"})
    if not t["audit_keys"]:
        raise VQError("UNTRUSTED", details={"reason": "audit_keys"})
    return t


# -- step 4 -----------------------------------------------------------------

def _signatures(proof: dict, trust: dict) -> None:
    members = {m["key_id"]: m for m in proof["policy"]["roster"]}
    for vote in proof["votes"]:
        member = members.get(vote["body"]["key_id"])
        if member is None:
            raise VQError("KEY_NOT_ENROLLED",
                          details={"key_id": vote["body"]["key_id"]})
        ed_verify(bytes.fromhex(member["public_key"]),
                  bytes.fromhex(vote["signature"]),
                  signing_message("vote", vote["body"]))
    events = proof["events"]
    if not events:
        raise VQError("MISSING_EVIDENCE")
    audit_ids = {e["key_id"] for e in events}
    if len(audit_ids) != 1:
        raise VQError("UNTRUSTED", details={"reason": "audit_key_split"})
    audit_id = audit_ids.pop()
    tk = next((k for k in trust["audit_keys"] if k["key_id"] == audit_id),
              None)
    if tk is None:
        raise VQError("UNTRUSTED", details={"reason": "audit_key"})
    pub = bytes.fromhex(tk["public_key"])
    for e in events:
        seq = e["body"]["seq"]
        if seq < tk["first_seq"] or (
                tk["last_seq"] is not None and seq > tk["last_seq"]):
            raise VQError("UNTRUSTED", details={"reason": "seq_range"})
        ed_verify(pub, bytes.fromhex(e["signature"]),
                  signing_message("event", e["body"]))
    cp = proof["checkpoint"]
    if cp["key_id"] != audit_id:
        raise VQError("UNTRUSTED", details={"reason": "checkpoint_key"})
    ed_verify(pub, bytes.fromhex(cp["signature"]),
              signing_message("checkpoint", cp["body"]))


# -- step 5 -----------------------------------------------------------------

def _chain(proof: dict) -> None:
    events = proof["events"]
    seen_ids: set[str] = set()
    prev_hash: Optional[str] = None
    prev_ms = -1
    for i, e in enumerate(events, start=1):
        b = e["body"]
        if b["seq"] != i:
            raise VQError("MISSING_EVIDENCE",
                          details={"expected_seq": i, "got": b["seq"]})
        if e["hash"] != H("event", b):
            raise VQError("CHAIN_BREAK", details={"seq": i})
        if b["prev_hash"] != prev_hash:
            raise VQError("CHAIN_BREAK", details={"seq": i})
        if b["receipt_id"] in seen_ids:
            raise VQError("CHAIN_BREAK", details={"reason": "dup_receipt"})
        seen_ids.add(b["receipt_id"])
        if b["at_ms"] < prev_ms:
            raise VQError("CHAIN_BREAK", details={"reason": "time_order"})
        prev_ms = b["at_ms"]
        prev_hash = e["hash"]
    cp = proof["checkpoint"]["body"]
    if events:
        if cp["head_seq"] != events[-1]["body"]["seq"] or \
                cp["head_hash"] != events[-1]["hash"]:
            raise VQError("CHECKPOINT_MISMATCH")
    else:
        raise VQError("MISSING_EVIDENCE")


# -- step 6 -----------------------------------------------------------------

def _replay(proof: dict) -> dict:
    """Replay transitions; return the reduced final state.

    Enforces referenced votes, quorum set, authority hash, operation id,
    dispatch deadline, and legal transitions.
    """
    a = proof["action"]
    p = proof["policy"]
    votes = proof["votes"]
    events = proof["events"]
    members = {m["key_id"]: m for m in p["roster"]}

    first = events[0]["body"]["data"]
    if first["type"] != "Proposed" or \
            first["action_hash"] != H("action", a) or \
            first["policy_hash"] != a["policy_hash"] or \
            first["authority_epoch"] != a["authority_epoch"]:
        raise VQError("ILLEGAL_TRANSITION", details={"at": "Proposed"})

    state = "OPEN"
    recorded_keys: set[str] = set()
    approved_keys: set[str] = set()
    rejected = False
    committed = False
    votes_by_key: dict[str, dict] = {v["body"]["key_id"]: v for v in votes}
    vote_keys_sorted = sorted(votes_by_key)
    if [v["body"]["key_id"] for v in votes] != vote_keys_sorted:
        raise VQError("ILLEGAL_TRANSITION", details={"at": "votes_order"})
    seen_votes: set[str] = set()

    for e in events[1:]:
        b = e["body"]
        d = b["data"]
        t = d["type"]
        if t == "VoteRecorded":
            v = votes_by_key.get(d["key_id"])
            if v is None or H("vote", v["body"]) != d["vote_hash"]:
                raise VQError("MISSING_EVIDENCE",
                              details={"at": "VoteRecorded"})
            if d["decision"] != v["body"]["decision"]:
                raise VQError("ILLEGAL_TRANSITION", details={"at": "vote"})
            if state not in ("OPEN", "READY"):
                raise VQError("ILLEGAL_TRANSITION", details={"at": "vote"})
            if d["key_id"] in recorded_keys:
                raise VQError("ILLEGAL_TRANSITION",
                              details={"at": "dup_key"})
            recorded_keys.add(d["key_id"])
            seen_votes.add(d["key_id"])
            if d["decision"] == "approve":
                approved_keys.add(d["key_id"])
            else:
                rejected = True
                state = "_reject_pending"  # next event must be Escalated
        elif t == "QuorumReached":
            if state != "OPEN":
                raise VQError("ILLEGAL_TRANSITION",
                              details={"at": "quorum"})
            keys = sorted(approved_keys)
            principals = [members[k]["principal_id"] for k in keys]
            satisfied = len(set(principals)) >= p["threshold"] and (
                not p["require_human"] or any(
                    members[k]["kind"] == "human" for k in keys))
            if not satisfied:
                raise VQError("ILLEGAL_TRANSITION",
                              details={"at": "quorum_unmet"})
            if d["approved_keys"] != keys or \
                    d["approved_principals"] != principals:
                raise VQError("ILLEGAL_TRANSITION",
                              details={"at": "quorum_set"})
            state = "READY"
        elif t == "CommitStarted":
            if state != "READY":
                raise VQError("ILLEGAL_TRANSITION", details={"at": "commit"})
            if d["authority_hash"] != H("authority", proof["authority"]):
                raise VQError("ILLEGAL_TRANSITION",
                              details={"at": "authority_hash"})
            if d["operation_id"] != a["operation_id"]:
                raise VQError("ILLEGAL_TRANSITION",
                              details={"at": "operation"})
            deadline = min(a["expires_ms"], b["at_ms"] + 5000)
            if d["dispatch_deadline_ms"] != deadline:
                raise VQError("ILLEGAL_TRANSITION",
                              details={"at": "deadline"})
            state = "DISPATCHING"
            committed = True
        elif t == "ExecutionReported":
            if state != "DISPATCHING":
                raise VQError("ILLEGAL_TRANSITION", details={"at": "report"})
            state = {"succeeded": "SUCCEEDED", "failed": "FAILED",
                     "unknown": "UNKNOWN"}[d["result"]["status"]]
        elif t == "ExecutionReconciled":
            if state != "UNKNOWN":
                raise VQError("ILLEGAL_TRANSITION",
                              details={"at": "reconcile"})
            state = {"succeeded": "SUCCEEDED", "failed": "FAILED",
                     "unknown": "UNKNOWN"}[d["result"]["status"]]
        elif t == "Escalated":
            if state == "_reject_pending":
                if d["reason"] != "reject_vote":
                    raise VQError("ILLEGAL_TRANSITION",
                                  details={"at": "reject_reason"})
            elif state == "OPEN" and not recorded_keys:
                if d["reason"] not in ("manual", "missing_quorum",
                                       "enrichment_unavailable"):
                    raise VQError("ILLEGAL_TRANSITION",
                                  details={"at": "esc_reason"})
            elif state in ("OPEN", "READY"):
                if d["reason"] not in ("manual", "missing_quorum",
                                       "reject_vote"):
                    raise VQError("ILLEGAL_TRANSITION",
                                  details={"at": "esc_reason"})
            else:
                raise VQError("ILLEGAL_TRANSITION", details={"at": "esc"})
            state = "ESCALATED"
        elif t in ("EscalationDelivered", "EscalationDeferred"):
            if state != "ESCALATED":
                raise VQError("ILLEGAL_TRANSITION",
                              details={"at": "delivery"})
        elif t == "Expired":
            if state not in ("OPEN", "READY"):
                raise VQError("ILLEGAL_TRANSITION",
                              details={"at": "expired"})
            if d["expires_ms"] != a["expires_ms"]:
                raise VQError("ILLEGAL_TRANSITION",
                              details={"at": "expires"})
            if b["at_ms"] < a["expires_ms"]:
                raise VQError("ILLEGAL_TRANSITION",
                              details={"at": "expires_early"})
            state = "EXPIRED"
        elif t == "Canceled":
            if state not in ("OPEN", "READY") or \
                    d["reason"] != "requester_canceled":
                raise VQError("ILLEGAL_TRANSITION",
                              details={"at": "cancel"})
            state = "CANCELED"
        elif t == "Invalidated":
            if state not in ("OPEN", "READY"):
                raise VQError("ILLEGAL_TRANSITION",
                              details={"at": "invalidate"})
            state = "STALE"
        elif t == "AuthorityChanged":
            raise VQError("ILLEGAL_TRANSITION",
                          details={"at": "authority_in_ceremony"})
        else:
            raise VQError("ILLEGAL_TRANSITION", details={"at": t})

    if state == "_reject_pending":
        raise VQError("ILLEGAL_TRANSITION", details={"at": "reject_tail"})
    # every retained vote must resolve to exactly one VoteRecorded
    if seen_votes != set(votes_by_key):
        raise VQError("MISSING_EVIDENCE", details={"at": "votes"})
    return {"state": state, "committed": committed, "rejected": rejected}


# -- step 7 -----------------------------------------------------------------

def _quorum(proof: dict, final: dict) -> tuple[bool, bool]:
    """(quorum_check_ok, satisfied_at_commit)."""
    p = proof["policy"]
    members = {m["key_id"]: m for m in p["roster"]}
    approved = {v["body"]["key_id"] for v in proof["votes"]
                if v["body"]["decision"] == "approve"
                and v["body"]["key_id"] in members}
    principals = {members[k]["principal_id"] for k in approved}
    satisfied = len(principals) >= p["threshold"]
    if p["require_human"]:
        satisfied = satisfied and any(
            members[k]["kind"] == "human" for k in approved)
    state = final["state"]
    if state == "READY":
        return satisfied, satisfied
    if state in _CONSUMED_STATES:
        return satisfied, satisfied
    if state == "OPEN":
        return False, satisfied
    # ESCALATED / EXPIRED / STALE / CANCELED: not authorized regardless
    return False, satisfied

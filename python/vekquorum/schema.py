"""Closed-schema wire validators for vq/1.

All record types are closed: undeclared fields are errors, including nested
records.  All declared properties are required; nullable values appear as
null, never omitted.  Values arrive as inert maps/lists produced by the
strict parser (or equivalent literals in-process).

Field refinements (ID prefixes, hash/signature encodings, string byte bounds,
safe-integer profile) raise the stable codes defined for them, not a generic
schema error.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from .canon import J
from .ed25519 import validate_enrollment_key
from .errors import VQError
from .hashing import (HASH_RE, PUBKEY_RE, SIG_RE)
from .ids import PREFIXES, SYSTEM_PRINCIPAL, SUFFIX_LEN, ALPHABET

SAFE_INT_MAX = 9007199254740991
TOOL_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$")
PAYMENT_ID_RE = re.compile(r"^pay_[A-Za-z0-9_-]{1,64}$")
PRINTABLE_ASCII_RE = re.compile(r"^[\x20-\x7e]+$")
NONEMPTY_ASCII_RE = re.compile(r"^[\x20-\x7e]+$")

MAX_ACTION_BYTES = 65536
MAX_ARGS_BYTES = 32768
MAX_PROOF_BYTES = 4194304
MAX_PROOF_EVENTS = 256
MAX_ROSTER = 32
MAX_PRECONDITIONS = 16
MAX_EXTERNAL_REFS = 8
MAX_STRING_BYTES = 1024
MAX_GOAL_BYTES = 512
MAX_RESOURCE_BYTES = 256


def _bad(field: str, reason: str) -> VQError:
    return VQError("SCHEMA_INVALID", details={"field": field, "reason": reason})


def v_uint(v: Any, field: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise _bad(field, "type")
    if v < 0 or v > SAFE_INT_MAX:
        raise VQError("NUMBER_PROFILE", details={"field": field})
    return v


def v_bool(v: Any, field: str) -> bool:
    if not isinstance(v, bool):
        raise _bad(field, "type")
    return v


def v_str(max_bytes: int = MAX_STRING_BYTES,
          printable_ascii: bool = False,
          nonempty: bool = False) -> Callable[[Any, str], str]:
    def check(v: Any, field: str) -> str:
        if not isinstance(v, str):
            raise _bad(field, "type")
        if nonempty and not v:
            raise _bad(field, "empty")
        if len(v.encode("utf-8")) > max_bytes:
            raise _bad(field, "too_long")
        if printable_ascii and not PRINTABLE_ASCII_RE.match(v):
            raise _bad(field, "not_printable_ascii")
        for ch in v:
            if 0xD800 <= ord(ch) <= 0xDFFF:
                raise _bad(field, "surrogate")
        return v
    return check


def v_id(kind: str) -> Callable[[Any, str], str]:
    prefix = PREFIXES[kind]

    def check(v: Any, field: str) -> str:
        if not isinstance(v, str) or not v.startswith(prefix):
            raise VQError("INVALID_ID", details={"field": field})
        suffix = v[len(prefix):]
        if len(suffix) != SUFFIX_LEN or any(c not in ALPHABET for c in suffix):
            raise VQError("INVALID_ID", details={"field": field})
        if kind == "principal" and v == SYSTEM_PRINCIPAL:
            raise VQError("INVALID_ID", details={"field": field,
                                               "reason": "reserved"})
        return v
    return check


def v_principal_maybe_system(v: Any, field: str) -> str:
    if v == SYSTEM_PRINCIPAL:
        return SYSTEM_PRINCIPAL
    return v_id("principal")(v, field)


def v_hash(v: Any, field: str) -> str:
    if not isinstance(v, str) or not HASH_RE.match(v):
        raise _bad(field, "hash")
    return v


def v_pubkey(v: Any, field: str) -> str:
    if not isinstance(v, str) or not PUBKEY_RE.match(v):
        raise VQError("INVALID_KEY", details={"field": field})
    return v


def v_sig(v: Any, field: str) -> str:
    if not isinstance(v, str) or not SIG_RE.match(v):
        raise VQError("INVALID_SIGNATURE_ENCODING", details={"field": field})
    return v


def v_enum(*options: str) -> Callable[[Any, str], str]:
    def check(v: Any, field: str) -> str:
        if not isinstance(v, str) or v not in options:
            raise _bad(field, "enum")
        return v
    return check


def v_nullable(inner: Callable[[Any, str], Any]) -> Callable[[Any, str], Any]:
    def check(v: Any, field: str) -> Any:
        if v is None:
            return None
        return inner(v, field)
    return check


def v_list(inner: Callable[[Any, str], Any],
           max_len: int | None = None) -> Callable[[Any, str], list]:
    def check(v: Any, field: str) -> list:
        if not isinstance(v, list):
            raise _bad(field, "type")
        if max_len is not None and len(v) > max_len:
            raise _bad(field, "too_many")
        return [inner(item, field) for item in v]
    return check


def v_json(v: Any, field: str, depth: int = 0) -> Any:
    """Arbitrary JSON value inside declared Json-typed maps."""
    if depth > 32:
        raise _bad(field, "max_depth")
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, int):
        if v < -SAFE_INT_MAX or v > SAFE_INT_MAX:
            raise VQError("NUMBER_PROFILE", details={"field": field})
        return v
    if isinstance(v, float):
        raise VQError("NUMBER_PROFILE", details={"field": field})
    if isinstance(v, str):
        for ch in v:
            if 0xD800 <= ord(ch) <= 0xDFFF:
                raise _bad(field, "surrogate")
        return v
    if isinstance(v, list):
        if len(v) > 1024:
            raise _bad(field, "too_many")
        return [v_json(i, field, depth + 1) for i in v]
    if isinstance(v, dict):
        if len(v) > 1024:
            raise _bad(field, "too_many")
        return {k: v_json(x, field, depth + 1) for k, x in v.items()}
    raise _bad(field, "type")


def v_args(v: Any, field: str) -> dict:
    if not isinstance(v, dict):
        raise _bad(field, "type")
    if len(v) > 1024:
        raise _bad(field, "too_many")
    out = {k: v_json(x, field, 1) for k, x in v.items()}
    if len(J(out)) > MAX_ARGS_BYTES:
        raise _bad(field, "args_too_large")
    return out


def closed(v: Any, spec: dict[str, Callable[[Any, str], Any]],
           name: str) -> dict:
    if not isinstance(v, dict):
        raise _bad(name, "type")
    for key in v:
        if key not in spec:
            raise VQError("UNKNOWN_FIELD", details={"object": name,
                                                  "field": key})
    out: dict[str, Any] = {}
    for field, check in spec.items():
        if field not in v:
            raise _bad(name + "." + field, "missing")
        out[field] = check(v[field], name + "." + field)
    return out


def v_version(v: Any, field: str) -> int:
    if v != 1 or isinstance(v, bool):
        raise VQError("VERSION_UNSUPPORTED", details={"field": field})
    return v


# --- leaf object validators -------------------------------------------------

def member(v: Any, field: str = "member") -> dict:
    m = closed(v, {
        "key_id": v_id("key"),
        "principal_id": v_id("principal"),
        "kind": v_enum("human", "agent"),
        "public_key": v_pubkey,
    }, field)
    validate_enrollment_key(m["public_key"])
    return m


def precondition(v: Any, field: str = "precondition") -> dict:
    return closed(v, {
        "resource": v_str(MAX_RESOURCE_BYTES, printable_ascii=True,
                          nonempty=True),
        "version": v_str(MAX_RESOURCE_BYTES, printable_ascii=True,
                         nonempty=True),
    }, field)


def foreign_ref(v: Any, field: str = "foreign_ref") -> dict:
    return closed(v, {
        "system": v_enum("covenant", "world", "mint", "river"),
        "profile": v_str(MAX_STRING_BYTES, printable_ascii=True,
                         nonempty=True),
        "object_id": v_str(MAX_STRING_BYTES, printable_ascii=True,
                           nonempty=True),
        "hash": v_str(MAX_STRING_BYTES, nonempty=True),
    }, field)


def oversight(v: Any, field: str = "oversight") -> dict:
    return closed(v, {
        "goal": v_str(MAX_GOAL_BYTES),
        "human_initiator": v_nullable(v_id("principal")),
        "trace_id": v_id("trace"),
        "parent_receipt_hash": v_nullable(v_hash),
    }, field)


def result(v: Any, field: str = "result") -> dict:
    r = closed(v, {
        "status": v_enum("succeeded", "failed", "unknown"),
        "code": v_str(MAX_STRING_BYTES, nonempty=True),
        "output_hash": v_nullable(v_hash),
        "provider_ref": v_nullable(v_str(MAX_STRING_BYTES)),
    }, field)
    if r["status"] == "succeeded":
        if r["output_hash"] is None or not r["provider_ref"]:
            raise _bad(field, "succeeded_requires_output")
    return r


def vote_body(v: Any, field: str = "vote_body") -> dict:
    return closed(v, {
        "v": v_version,
        "action_hash": v_hash,
        "policy_hash": v_hash,
        "key_id": v_id("key"),
        "decision": v_enum("approve", "reject"),
    }, field)


def signed_vote(v: Any, field: str = "signed_vote") -> dict:
    return closed(v, {
        "body": vote_body,
        "signature": v_sig,
    }, field)


def policy(v: Any, field: str = "policy") -> dict:
    p = closed(v, {
        "v": v_version,
        "tenant": v_id("tenant"),
        "policy_id": v_id("policy"),
        "version": v_uint,
        "executor_id": v_id("executor"),
        "environment": v_enum("test", "live"),
        "tool": v_str(MAX_STRING_BYTES),
        "threshold": v_uint,
        "roster": v_list(member),
        "require_human": v_bool,
        "max_ttl_ms": v_uint,
        "enrichment_required": v_bool,
    }, field)
    _policy_invariants(p)
    return p


def _policy_invariants(p: dict) -> None:
    if not TOOL_RE.match(p["tool"]):
        raise VQError("POLICY_INVALID", details={"reason": "tool_name"})
    roster = p["roster"]
    if not 1 <= p["threshold"] <= len(roster) <= MAX_ROSTER:
        raise VQError("POLICY_INVALID", details={"reason": "threshold"})
    key_ids = [m["key_id"] for m in roster]
    if key_ids != sorted(key_ids):
        raise VQError("POLICY_INVALID", details={"reason": "roster_order"})
    if len(set(key_ids)) != len(key_ids):
        raise VQError("POLICY_INVALID", details={"reason": "dup_key_id"})
    principals = [m["principal_id"] for m in roster]
    if len(set(principals)) != len(principals):
        raise VQError("POLICY_INVALID", details={"reason": "dup_principal"})
    pubs = [m["public_key"] for m in roster]
    if len(set(pubs)) != len(pubs):
        raise VQError("POLICY_INVALID", details={"reason": "dup_public_key"})
    if p["require_human"] and not any(m["kind"] == "human" for m in roster):
        raise VQError("POLICY_INVALID", details={"reason": "require_human"})
    if not 1000 <= p["max_ttl_ms"] <= 300000:
        raise VQError("POLICY_INVALID", details={"reason": "max_ttl"})
    if p["version"] < 1:
        raise VQError("POLICY_INVALID", details={"reason": "version"})


def authority(v: Any, field: str = "authority") -> dict:
    a = closed(v, {
        "v": v_version,
        "tenant": v_id("tenant"),
        "executor_id": v_id("executor"),
        "epoch": v_uint,
        "policy_hash": v_hash,
        "denied_tools": v_list(v_str(MAX_STRING_BYTES)),
        "revoked_keys": v_list(v_id("key")),
        "installed_ms": v_uint,
    }, field)
    if a["denied_tools"] != sorted(set(a["denied_tools"])):
        raise _bad(field, "denied_tools_not_sorted_unique")
    if a["revoked_keys"] != sorted(set(a["revoked_keys"])):
        raise _bad(field, "revoked_keys_not_sorted_unique")
    return a


def lextier_card(v: Any, field: str = "card") -> dict:
    import hashlib
    c = closed(v, {
        "status": v_enum("known", "partial", "unknown"),
        "target": lambda x, f: closed(x, {
            "resource": v_str(MAX_RESOURCE_BYTES, printable_ascii=True,
                              nonempty=True),
            "version": v_str(MAX_RESOURCE_BYTES, printable_ascii=True,
                             nonempty=True),
            "digest": v_str(MAX_STRING_BYTES, nonempty=True),
        }, f),
        "files": v_nullable(v_uint),
        "rows": v_nullable(v_uint),
        "money": v_nullable(lambda x, f: closed(x, {
            "currency": v_enum("USD"),
            "amount_minor": v_uint,
        }, f)),
        "undo": lambda x, f: closed(x, {
            "kind": v_enum("none", "manual"),
            "instruction": v_str(MAX_STRING_BYTES),
        }, f),
        "observed_ms": v_uint,
        "evidence_hash": v_str(MAX_STRING_BYTES, nonempty=True),
    }, field)
    body = {k: c[k] for k in c if k != "evidence_hash"}
    expect = hashlib.sha256(J(body)).hexdigest()
    if c["evidence_hash"] != expect:
        raise _bad(field, "evidence_hash")
    return c


def enrichment(v: Any, field: str = "enrichment") -> dict:
    return closed(v, {
        "v": v_version,
        "source": v_enum("lextier-stop-card/1"),
        "source_action_hash": v_str(MAX_STRING_BYTES, nonempty=True),
        "card": lextier_card,
    }, field)


def action(v: Any, field: str = "action") -> dict:
    a = closed(v, {
        "v": v_version,
        "tenant": v_id("tenant"),
        "proposal_id": v_id("proposal"),
        "operation_id": v_id("operation"),
        "executor_id": v_id("executor"),
        "proposer_id": v_id("principal"),
        "environment": v_enum("test", "live"),
        "tool": v_str(MAX_STRING_BYTES),
        "args": v_args,
        "policy_hash": v_hash,
        "authority_epoch": v_uint,
        "created_ms": v_uint,
        "expires_ms": v_uint,
        "nonce": v_id("nonce"),
        "preconditions": v_list(precondition, MAX_PRECONDITIONS),
        "enrichment_hash": v_nullable(v_hash),
        "oversight": oversight,
        "external_refs": v_list(foreign_ref, MAX_EXTERNAL_REFS),
    }, field)
    _action_invariants(a, field)
    if len(J(a)) > MAX_ACTION_BYTES:
        raise VQError("BODY_TOO_LARGE", details={"field": field})
    return a


def _action_invariants(a: dict, field: str) -> None:
    if not TOOL_RE.match(a["tool"]):
        raise _bad(field, "tool_name")
    pre = a["preconditions"]
    resources = [p["resource"] for p in pre]
    if resources != sorted(resources) or len(set(resources)) != len(resources):
        raise _bad(field, "preconditions_order")
    refs = a["external_refs"]
    keys = [(r["system"], r["profile"], r["object_id"]) for r in refs]
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        raise _bad(field, "external_refs_order")


# --- audit / proof -----------------------------------------------------------

_EVENT_DATA_FIELDS: dict[str, dict[str, Callable[[Any, str], Any]]] = {
    "Proposed": {
        "action_hash": v_hash, "policy_hash": v_hash,
        "authority_epoch": v_uint},
    "VoteRecorded": {
        "vote_hash": v_hash, "key_id": v_id("key"),
        "decision": v_enum("approve", "reject")},
    "QuorumReached": {
        "approved_keys": v_list(v_id("key")),
        "approved_principals": v_list(v_id("principal"))},
    "CommitStarted": {
        "authority_hash": v_hash, "operation_id": v_id("operation"),
        "dispatch_id": v_id("dispatch"), "dispatch_deadline_ms": v_uint,
        "gate_revision": v_str(MAX_STRING_BYTES, nonempty=True)},
    "ExecutionReported": {"result": result},
    "ExecutionReconciled": {"result": result},
    "Escalated": {
        "reason": v_enum("reject_vote", "manual", "missing_quorum",
                         "enrichment_unavailable"),
        "escalation_id": v_id("escalation")},
    "EscalationDelivered": {
        "escalation_id": v_id("escalation"),
        "inbox_ticket": v_str(MAX_STRING_BYTES, nonempty=True)},
    "EscalationDeferred": {
        "escalation_id": v_id("escalation"), "attempt": v_uint,
        "code": v_enum("UNAVAILABLE", "REJECTED")},
    "Expired": {"expires_ms": v_uint},
    "Canceled": {"reason": v_enum("requester_canceled")},
    "Invalidated": {
        "reason": v_enum("policy_changed", "key_revoked", "scope_denied",
                         "state_drift")},
    "AuthorityChanged": {
        "authority": authority, "previous_authority_hash": v_nullable(v_hash)},
}


def event_data(v: Any, field: str = "data") -> dict:
    if not isinstance(v, dict):
        raise _bad(field, "type")
    if "type" not in v or not isinstance(v["type"], str):
        raise _bad(field, "type_tag")
    tag = v["type"]
    spec = _EVENT_DATA_FIELDS.get(tag)
    if spec is None:
        raise _bad(field, "unknown_event_type")
    full = dict(spec)
    full["type"] = lambda x, f: v_enum(tag)(x, f)
    return closed(v, full, field)


def event_body(v: Any, field: str = "event_body") -> dict:
    return closed(v, {
        "v": v_version,
        "tenant": v_id("tenant"),
        "stream_id": v_id("stream"),
        "receipt_id": v_id("event"),
        "seq": v_uint,
        "prev_hash": v_nullable(v_hash),
        "at_ms": v_uint,
        "proposal_id": v_nullable(v_id("proposal")),
        "actor_id": v_principal_maybe_system,
        "data": event_data,
    }, field)


def audit_entry(v: Any, field: str = "audit_entry") -> dict:
    return closed(v, {
        "body": event_body,
        "hash": v_hash,
        "key_id": v_id("key"),
        "signature": v_sig,
    }, field)


def checkpoint_body(v: Any, field: str = "checkpoint_body") -> dict:
    return closed(v, {
        "v": v_version,
        "tenant": v_id("tenant"),
        "proposal_id": v_id("proposal"),
        "head_seq": v_uint,
        "head_hash": v_hash,
        "observed_ms": v_uint,
        "authority_epoch": v_uint,
    }, field)


def checkpoint(v: Any, field: str = "checkpoint") -> dict:
    return closed(v, {
        "body": checkpoint_body,
        "key_id": v_id("key"),
        "signature": v_sig,
    }, field)


def proof(v: Any, field: str = "proof") -> dict:
    if not isinstance(v, dict):
        raise _bad(field, "type")
    for key in v:
        if key not in ("v", "profile", "action", "policy", "authority",
                       "enrichment", "votes", "events", "checkpoint"):
            raise VQError("UNKNOWN_FIELD", details={"object": field,
                                                  "field": key})
    if v.get("v") != 1 or isinstance(v.get("v"), bool):
        raise VQError("VERSION_UNSUPPORTED", details={"field": field + ".v"})
    if v.get("profile") != "vq.visreceipt/1":
        raise VQError("VERSION_UNSUPPORTED",
                      details={"field": field + ".profile"})
    for required in ("action", "policy", "authority", "enrichment", "votes",
                     "events", "checkpoint"):
        if required not in v:
            raise _bad(field + "." + required, "missing")
    out = {
        "v": 1,
        "profile": "vq.visreceipt/1",
        "action": action(v["action"], field + ".action"),
        "policy": policy(v["policy"], field + ".policy"),
        "authority": authority(v["authority"], field + ".authority"),
        "enrichment": (None if v["enrichment"] is None else
                       enrichment(v["enrichment"], field + ".enrichment")),
        "votes": v_list(signed_vote)(v["votes"], field + ".votes"),
        "events": v_list(audit_entry)(v["events"], field + ".events"),
        "checkpoint": checkpoint(v["checkpoint"], field + ".checkpoint"),
    }
    if len(out["events"]) > MAX_PROOF_EVENTS:
        raise _bad(field, "too_many_events")
    return out


def trust_key(v: Any, field: str = "trust_key") -> dict:
    k = closed(v, {
        "key_id": v_id("key"),
        "public_key": v_pubkey,
        "first_seq": v_uint,
        "last_seq": v_nullable(v_uint),
    }, field)
    validate_enrollment_key(k["public_key"])
    if k["last_seq"] is not None and k["last_seq"] < k["first_seq"]:
        raise _bad(field, "seq_interval")
    return k


def trust(v: Any, field: str = "trust") -> dict:
    t = closed(v, {
        "v": v_version,
        "tenant": v_id("tenant"),
        "executor_id": v_id("executor"),
        "environment": v_enum("test", "live"),
        "policy_hashes": v_list(v_hash),
        "audit_keys": v_list(trust_key),
    }, field)
    if t["policy_hashes"] != sorted(set(t["policy_hashes"])):
        raise _bad(field, "policy_hashes_not_sorted_unique")
    kids = [k["key_id"] for k in t["audit_keys"]]
    if len(set(kids)) != len(kids):
        raise _bad(field, "dup_audit_key")
    return t


def caller(v: Any, field: str = "caller") -> dict:
    return closed(v, {
        "tenant": v_id("tenant"),
        "principal_id": v_id("principal"),
        "capabilities": v_list(v_enum("read", "propose", "submit", "commit",
                                      "escalate", "admin")),
    }, field)


# --- request/response wrappers ------------------------------------------------

def propose_request(v: Any) -> dict:
    return closed(v, {
        "action": action, "policy": policy,
        "enrichment": v_nullable(enrichment)}, "propose_request")


def submit_request(v: Any) -> dict:
    return closed(v, {
        "proposal_id": v_id("proposal"), "expected_revision": v_uint,
        "vote": signed_vote}, "submit_request")


def commit_request(v: Any) -> dict:
    return closed(v, {
        "proposal_id": v_id("proposal"), "expected_revision": v_uint,
        "action_hash": v_hash}, "commit_request")


def escalate_request(v: Any) -> dict:
    return closed(v, {
        "proposal_id": v_id("proposal"), "expected_revision": v_uint,
        "reason": v_enum("manual", "missing_quorum")}, "escalate_request")


def cancel_request(v: Any) -> dict:
    return closed(v, {
        "proposal_id": v_id("proposal"),
        "expected_revision": v_uint}, "cancel_request")


def configure_request(v: Any) -> dict:
    return closed(v, {
        "expected_epoch": v_uint, "policy": policy,
        "denied_tools": v_list(v_str(MAX_STRING_BYTES)),
        "revoked_keys": v_list(v_id("key"))}, "configure_request")


def read_request(v: Any) -> dict:
    return closed(v, {"proposal_id": v_id("proposal")}, "read_request")


def reconcile_request(v: Any) -> dict:
    return closed(v, {"proposal_id": v_id("proposal")}, "reconcile_request")


def deliver_request(v: Any) -> dict:
    return closed(v, {"escalation_id": v_id("escalation")}, "deliver_request")


def dispatch_request(v: Any) -> dict:
    return closed(v, {
        "v": v_version, "action": action, "action_hash": v_hash,
        "dispatch_id": v_id("dispatch"),
        "idempotency_key": v_str(MAX_STRING_BYTES, nonempty=True),
        "not_after_ms": v_uint,
        "preconditions": v_list(precondition, MAX_PRECONDITIONS),
        "gate_revision": v_str(MAX_STRING_BYTES, nonempty=True),
    }, "dispatch_request")


def lookup_request(v: Any) -> dict:
    return closed(v, {
        "v": v_version, "operation_id": v_id("operation"),
        "idempotency_key": v_str(MAX_STRING_BYTES, nonempty=True),
        "dispatch_id": v_id("dispatch")}, "lookup_request")


def lookup_result(v: Any) -> dict:
    r = closed(v, {
        "observed": v_enum("succeeded", "failed", "unresolved"),
        "result": v_nullable(result)}, "lookup_result")
    if r["observed"] == "unresolved":
        if r["result"] is not None:
            raise _bad("lookup_result", "unresolved_requires_null_result")
    elif r["result"] is None or r["result"]["status"] != r["observed"]:
        raise _bad("lookup_result", "result_status_mismatch")
    return r


def gate_response(v: Any) -> dict:
    if not isinstance(v, dict):
        raise _bad("gate_response", "type")
    decision = v.get("decision")
    if decision in ("allow", "deny"):
        return closed(v, {"decision": v_enum("allow", "deny"),
                          "revision": v_str(MAX_STRING_BYTES, nonempty=True)},
                      "gate_response")
    if decision == "unavailable":
        return closed(v, {"decision": v_enum("unavailable"),
                          "revision": lambda x, f: None if x is None else _bad(
                              f, "revision_must_be_null")}, "gate_response")
    raise _bad("gate_response", "decision")


def inspect_response(v: Any) -> dict:
    if not isinstance(v, dict):
        raise _bad("inspect_response", "type")
    if v.get("ready") is True:
        return closed(v, {
            "ready": lambda x, f: True if x is True else _bad(f, "type"),
            "preconditions": v_list(precondition, MAX_PRECONDITIONS)},
            "inspect_response")
    if v.get("ready") is False:
        return closed(v, {
            "ready": lambda x, f: False if x is False else _bad(f, "type"),
            "code": v_enum("ADAPTER_UNAVAILABLE")}, "inspect_response")
    raise _bad("inspect_response", "ready")


def inbox_request(v: Any) -> dict:
    return closed(v, {
        "v": v_version,
        "escalation_id": v_id("escalation"),
        "idempotency_key": v_str(MAX_STRING_BYTES, nonempty=True),
        "tenant": v_id("tenant"),
        "proposal_id": v_id("proposal"),
        "action_hash": v_hash,
        "bundle_hash": v_hash,
        "reason": v_enum("reject_vote", "manual", "missing_quorum",
                         "enrichment_unavailable"),
        "expires_ms": v_uint,
        "summary": v_str(MAX_STRING_BYTES),
        "authority": v_enum("informational_only"),
    }, "inbox_request")


def inbox_response(v: Any) -> dict:
    return closed(v, {
        "escalation_id": v_id("escalation"),
        "inbox_ticket": v_str(MAX_STRING_BYTES, nonempty=True),
        "duplicate": v_bool}, "inbox_response")


def sign_request(v: Any) -> dict:
    return closed(v, {
        "action": action, "policy": policy,
        "enrichment": v_nullable(enrichment),
        "key_id": v_id("key"),
        "decision": v_enum("approve", "reject"),
        "confirm_hash": v_hash}, "sign_request")


def deployment_manifest(v: Any) -> dict:
    return closed(v, {
        "v": v_version,
        "executor_id": v_id("executor"),
        "tool": v_str(MAX_STRING_BYTES),
        "schema_hash": v_hash,
        "build_hash": v_hash,
        "irreversible": v_bool}, "deployment_manifest")


def local_config(v: Any) -> dict:
    c = closed(v, {
        "v": v_version,
        "tenant": v_id("tenant"),
        "executor_id": v_id("executor"),
        "environment": v_enum("test", "live"),
        "database": v_str(MAX_STRING_BYTES, nonempty=True),
        "trust_file": v_str(MAX_STRING_BYTES, nonempty=True),
        "audit_key_file": v_str(MAX_STRING_BYTES, nonempty=True),
        "audit_key_id": v_id("key"),
        "caller_principal": v_id("principal"),
        "adapter": v_enum("refund-simulator/1", "application-registered/1"),
        "inbox": lambda x, f: closed(x, {
            "mode": v_enum("file", "application-registered"),
            "directory": v_nullable(v_str(MAX_STRING_BYTES))}, f),
        "hosted": v_nullable(lambda x, f: closed(x, {
            "base_url": v_str(MAX_STRING_BYTES, nonempty=True),
            "credential_env": v_str(MAX_STRING_BYTES, nonempty=True)}, f)),
        "payload_retention_days": v_uint,
        "metadata_retention_days": v_uint,
    }, "local_config")
    if c["inbox"]["mode"] == "file" and c["inbox"]["directory"] is None:
        raise _bad("local_config.inbox", "directory_required")
    if c["inbox"]["mode"] != "file" and c["inbox"]["directory"] is not None:
        raise _bad("local_config.inbox", "directory_forbidden")
    if not 1 <= c["payload_retention_days"] <= 365:
        raise _bad("local_config", "payload_retention")
    if not 30 <= c["metadata_retention_days"] <= 3650:
        raise _bad("local_config", "metadata_retention")
    return c


def hosted_config(v: Any) -> dict:
    return closed(v, {
        "v": v_version,
        "protocol": v_enum("vq/1"),
        "auth_binding": v_enum("INVITE_AUTH"),
        "registry_binding": v_enum("REGISTRY"),
        "tenant_trust_binding": v_enum("TENANT_TRUST"),
        "encryption_key_binding": v_enum("REGISTRY_ENCRYPTION_KEY"),
        "max_verify_bytes": v_uint,
        "max_registry_bytes_per_tenant": v_uint,
        "verify_per_minute": v_uint,
        "writes_per_minute": v_uint,
        "max_concurrent_verify_per_tenant": v_uint,
    }, "hosted_config")

"""The spec's §7 executable fixture environment, built on the real
implementation.  Every value here is deterministic test-only material;
these public test seeds are forbidden outside environment=test.
"""

import copy
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                              "python"))

from vekquorum.canon import J as _J  # noqa: E402
from vekquorum.hashing import D, H, signing_message  # noqa: E402
from vekquorum.ed25519 import sign as _sign  # noqa: E402
from vekquorum.ids import ident  # noqa: E402


def J(value):
    return _J(value)


SK = {i: bytes([i]) * 32 for i in range(1, 5)}
from vekquorum.ed25519 import public_key_of  # noqa: E402
PK = {i: public_key_of(SK[i]).hex() for i in SK}
T = 1800000000000
TEN, EXE, PID, OP, PROP = (ident("vqt_", 1), ident("vqx_", 1),
                           ident("vqa_", 1), ident("vqo_", 1),
                           ident("vqu_", 9))
K = {i: ident("vqk_", i) for i in SK}
U = {i: ident("vqu_", i) for i in SK}
STREAM, DISPATCH, ESC = (ident("vqs_", 1), ident("vqd_", 1),
                         ident("vqe_", 1))
P = {"v": 1, "tenant": TEN, "policy_id": ident("vqp_", 1), "version": 1,
     "executor_id": EXE, "environment": "test", "tool": "covenant.refund",
     "threshold": 2,
     "roster": [{"key_id": K[i], "principal_id": U[i],
                 "kind": "human" if i < 3 else "agent",
                 "public_key": PK[i]} for i in range(1, 4)],
     "require_human": True, "max_ttl_ms": 300000,
     "enrichment_required": False}
PH = H("policy", P)
AUTH = {"v": 1, "tenant": TEN, "executor_id": EXE, "epoch": 1,
        "policy_hash": PH, "denied_tools": [], "revoked_keys": [],
        "installed_ms": T}
A = {"v": 1, "tenant": TEN, "proposal_id": PID, "operation_id": OP,
     "executor_id": EXE, "proposer_id": PROP, "environment": "test",
     "tool": "covenant.refund",
     "args": {"payment_id": "pay_demo", "amount_minor": 100,
              "currency": "USD"},
     "policy_hash": PH, "authority_epoch": 1, "created_ms": T,
     "expires_ms": T + 60000, "nonce": ident("vqn_", 1),
     "preconditions": [{"resource": "payment:pay_demo", "version": "7"}],
     "enrichment_hash": None,
     "oversight": {"goal": "Refund duplicate charge",
                   "human_initiator": U[1], "trace_id": ident("vqc_", 1),
                   "parent_receipt_hash": None},
     "external_refs": []}
AH = H("action", A)


def vote(i, decision="approve", action=A, policy=P):
    body = {"v": 1, "action_hash": H("action", action),
            "policy_hash": H("policy", policy), "key_id": K[i],
            "decision": decision}
    return {"body": body,
            "signature": _sign(SK[i], signing_message("vote", body)).hex()}


VA, VB, VC, VR = vote(1), vote(2), vote(3), vote(3, "reject")
OUTPUT = {"refund_id": "refund_demo", "amount_minor": 100, "currency": "USD"}
RESULT = {"status": "succeeded", "code": "OK",
          "output_hash": H("output", OUTPUT), "provider_ref": "refund_demo"}
UNKNOWN = {"status": "unknown", "code": "TRANSPORT_UNKNOWN",
           "output_hash": None, "provider_ref": None}


def event(n, data, previous, at_ms, actor=PROP):
    body = {"v": 1, "tenant": TEN, "stream_id": STREAM,
            "receipt_id": ident("vqr_", n), "seq": n, "prev_hash": previous,
            "at_ms": at_ms, "proposal_id": PID, "actor_id": actor,
            "data": data}
    return {"body": body, "hash": H("event", body), "key_id": K[4],
            "signature": _sign(SK[4],
                               signing_message("event", body)).hex()}


E1 = event(1, {"type": "Proposed", "action_hash": AH, "policy_hash": PH,
               "authority_epoch": 1}, None, T)
E2 = event(2, {"type": "VoteRecorded", "vote_hash": H("vote", VA["body"]),
               "key_id": K[1], "decision": "approve"}, E1["hash"], T + 1)
E3 = event(3, {"type": "VoteRecorded", "vote_hash": H("vote", VB["body"]),
               "key_id": K[2], "decision": "approve"}, E2["hash"], T + 2)
E4 = event(4, {"type": "QuorumReached", "approved_keys": [K[1], K[2]],
               "approved_principals": [U[1], U[2]]}, E3["hash"], T + 2)
E5 = event(5, {"type": "CommitStarted",
               "authority_hash": H("authority", AUTH), "operation_id": OP,
               "dispatch_id": DISPATCH, "dispatch_deadline_ms": T + 5003,
               "gate_revision": "local-test-1"}, E4["hash"], T + 3)
E6 = event(6, {"type": "ExecutionReported", "result": RESULT}, E5["hash"],
           T + 4)
EVENTS = [E1, E2, E3, E4, E5, E6]
E_CANCEL = event(2, {"type": "Canceled", "reason": "requester_canceled"},
                 E1["hash"], T + 1)
E_ESC = event(2, {"type": "Escalated", "reason": "manual",
                  "escalation_id": ESC}, E1["hash"], T + 1)
E_UNKNOWN = event(6, {"type": "ExecutionReported", "result": UNKNOWN},
                  E5["hash"], T + 4)
E_RECON = event(7, {"type": "ExecutionReconciled", "result": RESULT},
                E_UNKNOWN["hash"], T + 5)
E_ACK = event(3, {"type": "EscalationDelivered", "escalation_id": ESC,
                  "inbox_ticket": "inbox-test-1"}, E_ESC["hash"], T + 2)


def checkpoint(events):
    last = events[-1]
    body = {"v": 1, "tenant": TEN, "proposal_id": PID,
            "head_seq": last["body"]["seq"], "head_hash": last["hash"],
            "observed_ms": last["body"]["at_ms"], "authority_epoch": 1}
    return {"body": body, "key_id": K[4],
            "signature": _sign(SK[4],
                               signing_message("checkpoint", body)).hex()}


def proof(events, votes):
    return {"v": 1, "profile": "vq.visreceipt/1", "action": copy.deepcopy(A),
            "policy": copy.deepcopy(P), "authority": copy.deepcopy(AUTH),
            "enrichment": None, "votes": copy.deepcopy(votes),
            "events": copy.deepcopy(events),
            "checkpoint": checkpoint(events)}


B_OPEN, B_READY, B_OK = (proof(EVENTS[:1], []), proof(EVENTS[:4], [VA, VB]),
                         proof(EVENTS, [VA, VB]))
B_ESC = proof([E1, E_ESC], [])
TRUST = {"v": 1, "tenant": TEN, "executor_id": EXE, "environment": "test",
         "policy_hashes": [PH],
         "audit_keys": [{"key_id": K[4], "public_key": PK[4],
                         "first_seq": 1, "last_seq": None}]}


def view(state, revision, approvals, result=None, escalation_id=None,
         head=None):
    return {"proposal_id": PID, "action_hash": AH, "state": state,
            "revision": revision, "approvals": approvals, "threshold": 2,
            "expires_ms": T + 60000,
            "consumed": state in ["DISPATCHING", "SUCCEEDED", "FAILED",
                                  "UNKNOWN"],
            "result": result, "escalation_id": escalation_id,
            "head_hash": head or EVENTS[revision - 1]["hash"]}


V_OPEN, V_ONE, V_READY = (view("OPEN", 1, 0), view("OPEN", 2, 1),
                          view("READY", 4, 2))
V_RUN, V_OK = view("DISPATCHING", 5, 2), view("SUCCEEDED", 6, 2, RESULT)
V_ESC = view("ESCALATED", 2, 0, escalation_id=ESC, head=E_ESC["hash"])
CHECKS = [{"id": name, "ok": True, "code": "OK"} for name in
          ["schema", "binding", "trust", "signatures", "chain", "replay",
           "quorum"]]
VERIFIED = {"integrity": "valid", "authorization": "satisfied",
            "execution": "reported_success", "freshness": "offline_unchecked",
            "consumption": "issuer_attested", "checks": CHECKS,
            "bundle_hash": H("bundle", B_OK)}
IDEM = "vq/1/" + TEN + "/" + EXE + "/" + OP
CALLER = {"tenant": TEN, "principal_id": PROP,
          "capabilities": ["read", "propose", "submit", "commit",
                           "escalate", "admin"]}
INBOX = {"v": 1, "escalation_id": ESC,
         "idempotency_key": "vq-inbox/1/" + ESC, "tenant": TEN,
         "proposal_id": PID, "action_hash": AH,
         "bundle_hash": H("bundle", B_ESC), "reason": "manual",
         "expires_ms": T + 60000, "summary": "Refund duplicate charge",
         "authority": "informational_only"}


def changed(value, path, replacement):
    result = copy.deepcopy(value)
    target = result
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    return result

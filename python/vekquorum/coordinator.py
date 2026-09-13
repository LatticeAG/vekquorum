"""The local vq/1 coordinator.

The SQLite journal is authoritative for live ceremony state and operation
consumption.  Mutations are serialized per executor; transactions run under
BEGIN IMMEDIATE and never span network I/O.  The dispatch path is:
prepare -> short compare-and-consume transaction (CommitStarted + consumed
tombstone + dispatch intent + view) -> one bounded adapter call -> result
transaction (ExecutionReported).

Crash discipline: a process that restarts with last_clean_shutdown=false
finalizes every consumed dispatch intent lacking a recorded result with
ExecutionReported(unknown/INTERRUPTED) before becoming ready.
"""

from __future__ import annotations

import copy
import json as _json
import threading
from typing import Any, Callable, Optional

from . import schema
from .adapters import covenant_refund_args
from .canon import J
from .ed25519 import sign as ed_sign, verify as ed_verify
from .errors import VQError
from .hashing import H, signing_message
from .ids import SYSTEM_PRINCIPAL, new_id
from .store import Store

DISPATCH_OBSERVE_MS = 5000
DISPATCH_DEADLINE_BUDGET_MS = 5000
CREATED_WINDOW_MS = 2000
CLOCK_SKEW_FAIL_MS = 2000
MAX_DELIVERY_ATTEMPTS = 8
RATE_PROPOSE_PER_MIN = 30
RATE_SUBMIT_PER_MIN = 120
MAX_ACTIVE_PROPOSALS = 128

_TERMINAL = {"SUCCEEDED", "FAILED", "EXPIRED", "STALE", "CANCELED"}
_LIVE = {"OPEN", "READY"}
_CONSUMED_STATES = {"DISPATCHING", "SUCCEEDED", "FAILED", "UNKNOWN"}

# Adapter arg-schema validators per registered tool profile.
ARG_PROFILES: dict[str, Callable[[dict], dict]] = {
    "covenant.refund": covenant_refund_args,
}


class Coordinator:
    """One coordinator owns one (tenant, executor, environment) identity."""

    def __init__(self, store: Store, *, tenant: str, executor_id: str,
                 environment: str, audit_key_id: str,
                 audit_seed: bytes,
                 executors: Optional[dict[str, Any]] = None,
                 gate: Any = None, inbox: Any = None,
                 manifest: Optional[dict] = None,
                 id_source: Callable[[str], str] = new_id,
                 readiness_frontier: Optional[str] = None,
                 hooks: Optional[dict] = None):
        self.store = store
        self.tenant = tenant
        self.executor_id = executor_id
        self.environment = environment
        self.audit_key_id = audit_key_id
        self.audit_seed = audit_seed
        self.executors = dict(executors or {})
        self.gate = gate
        self.inbox = inbox
        self.manifest = manifest
        self.ids = id_source
        self._hooks = dict(hooks or {})
        self._mu = threading.RLock()
        self._rate_propose: list[int] = []
        self._rate_submit: list[int] = []
        # readiness: clock safety first, then external-frontier comparison
        self._readiness(readiness_frontier)
        if not store.was_clean_shutdown():
            self._recover_interrupted()

    # -- readiness / recovery ------------------------------------------------

    def _readiness(self, frontier: Optional[str]) -> None:
        wall = int(self.store._wall_clock_ms())
        last = int(self.store.meta_get("last_logical_ms") or "0")
        if wall < last - CLOCK_SKEW_FAIL_MS:
            raise VQError("CLOCK_UNSAFE",
                          details={"persisted_last_ms": last})
        if frontier is not None:
            local = self._latest_head_hash()
            if local != frontier:
                raise VQError("RESTORE_UNSAFE",
                              details={"local_head": local})
        if self.manifest is not None:
            m = self.manifest
            if m["executor_id"] != self.executor_id:
                raise VQError("ADAPTER_UNAVAILABLE",
                              details={"reason": "manifest_executor"})
            if self.executors.get(m["tool"]) is None:
                raise VQError("ADAPTER_UNAVAILABLE",
                              details={"reason": "manifest_tool"})
            build = getattr(self.executors[m["tool"]], "build_hash", None)
            if build is not None and build != m["build_hash"]:
                raise VQError("ADAPTER_UNAVAILABLE",
                              details={"reason": "build_hash"})
        if self.environment == "live":
            # A live money-moving adapter is supported only when the provider
            # can enforce idempotency, atomic preconditions, and its own
            # effect deadline (§5.2/§5.4); otherwise readiness fails closed.
            for tool, executor in self.executors.items():
                caps = getattr(executor, "capabilities", None) or {}
                for need in ("provider_idempotency", "atomic_preconditions",
                             "effect_deadline_enforced"):
                    if not caps.get(need):
                        raise VQError(
                            "ADAPTER_UNAVAILABLE",
                            details={"tool": tool, "missing": need})

    def _latest_head_hash(self) -> Optional[str]:
        row = self.store.db.execute(
            "SELECT hash FROM events WHERE tenant=? ORDER BY rowid DESC "
            "LIMIT 1", (self.tenant,)).fetchone()
        return row[0] if row else None

    def _recover_interrupted(self) -> None:
        """Finalize consumed dispatch intents that have no recorded result."""
        rows = self.store.db.execute(
            "SELECT d.dispatch_id, c.proposal FROM dispatches d "
            "JOIN consumed c ON c.dispatch_id = d.dispatch_id "
            "WHERE d.tenant=? AND d.result IS NULL",
            (self.tenant,)).fetchall()
        for dispatch_id, proposal_id in rows:
            with self._mu:
                with self.store.tx() as conn:
                    prop = self._load_proposal(conn, proposal_id)
                    if prop is None or prop["state"] != "DISPATCHING":
                        continue
                    now = self.store.logical_now(conn)
                    self._append_event(conn, prop, {
                        "type": "ExecutionReported",
                        "result": {"status": "unknown",
                                   "code": "INTERRUPTED",
                                   "output_hash": None,
                                   "provider_ref": None}},
                        SYSTEM_PRINCIPAL, now)
                    self._set_state(prop, "UNKNOWN")
                    self._flush(conn, prop)
                    conn.execute(
                        "UPDATE dispatches SET result=? WHERE tenant=? AND "
                        "dispatch_id=?",
                        (J({"status": "unknown", "code": "INTERRUPTED",
                            "output_hash": None, "provider_ref": None}),
                         self.tenant, dispatch_id))

    # -- callers / auth --------------------------------------------------------

    @staticmethod
    def _caller(meta: dict) -> dict:
        if not isinstance(meta, dict) or "caller" not in meta:
            raise VQError("UNAUTHENTICATED")
        return schema.caller(meta["caller"])

    def _authorize(self, caller: dict, capability: str) -> None:
        if caller["tenant"] != self.tenant:
            raise VQError("TENANT_MISMATCH")
        if capability not in caller["capabilities"]:
            raise VQError("FORBIDDEN", details={"need": capability})

    # -- idempotency -----------------------------------------------------------

    def _request_hash(self, method: str, request: dict,
                      principal_id: str) -> str:
        return H("request", {"method": method, "request": request,
                             "principal_id": principal_id})

    def _dedupe(self, conn, method: str, request: dict, meta: dict):
        """Request-key dedupe.  Returns ('replay', stored_response) or
        ('new', None).  Conflicting reuse raises IDEMPOTENCY_CONFLICT."""
        caller = schema.caller(meta["caller"])
        req_id = meta.get("idempotency_key")
        if req_id is None:
            raise VQError("SCHEMA_INVALID",
                          details={"field": "idempotency_key",
                                   "reason": "missing"})
        schema.v_id("request")(req_id, "idempotency_key")
        row = conn.execute(
            "SELECT request_hash, response FROM requests WHERE tenant=? AND "
            "principal=? AND method=? AND request_id=?",
            (self.tenant, caller["principal_id"], method, req_id)).fetchone()
        if row is None:
            return "new", None
        if row[0] != self._request_hash(method, request,
                                        caller["principal_id"]):
            raise VQError("IDEMPOTENCY_CONFLICT",
                          details={"request_id": req_id})
        return "replay", row[1]

    def _record_request(self, conn, method: str, request: dict, meta: dict,
                        response: dict) -> None:
        caller = schema.caller(meta["caller"])
        conn.execute(
            "INSERT OR REPLACE INTO requests(tenant,principal,method,"
            "request_id,request_hash,response) VALUES(?,?,?,?,?,?)",
            (self.tenant, caller["principal_id"], method,
             meta["idempotency_key"],
             self._request_hash(method, request, caller["principal_id"]),
             J(response)))

    # -- row helpers -----------------------------------------------------------

    def _load_proposal(self, conn, proposal_id: str) -> Optional[dict]:
        row = conn.execute(
            "SELECT id, executor, operation_id, nonce, state, revision, "
            "action, view, initial_authority, commit_authority FROM proposals "
            "WHERE tenant=? AND id=?", (self.tenant, proposal_id)).fetchone()
        if row is None:
            return None
        view_db = _json.loads(bytes(row[7]).decode())
        return {"id": row[0], "executor": row[1], "operation_id": row[2],
                "nonce": row[3], "state": row[4], "revision": row[5],
                "action_blob": row[6], "view_db": view_db,
                "stream_id": view_db.get("_stream"),
                "initial_authority": row[8], "commit_authority": row[9]}

    def _action_of(self, prop: dict) -> dict:
        if prop["action_blob"] is None:
            raise VQError("PROOF_PRUNED")
        return schema.action(_json.loads(bytes(prop["action_blob"]).decode()))

    def _authority(self, conn, executor: Optional[str] = None) -> Optional[dict]:
        row = conn.execute(
            "SELECT epoch, body FROM authorities WHERE tenant=? AND "
            "executor=?",
            (self.tenant, executor or self.executor_id)).fetchone()
        if row is None:
            return None
        return _json.loads(bytes(row[1]).decode())

    def _policy_of(self, conn, policy_hash: str) -> Optional[dict]:
        row = conn.execute(
            "SELECT body FROM policies WHERE tenant=? AND hash=?",
            (self.tenant, policy_hash)).fetchone()
        if row is None:
            return None
        return _json.loads(bytes(row[0]).decode())

    # -- event machinery ---------------------------------------------------------

    def _append_event(self, conn, prop: dict, data: dict, actor: str,
                      at_ms: int) -> dict:
        seq = prop["revision"] + 1
        prev = prop["view_db"]["head_hash"] if seq > 1 else None
        body = {"v": 1, "tenant": self.tenant, "stream_id": prop["stream_id"],
                "receipt_id": self.ids("receipt"), "seq": seq,
                "prev_hash": prev, "at_ms": at_ms,
                "proposal_id": prop["id"], "actor_id": actor, "data": data}
        entry = {"body": body, "hash": H("event", body),
                 "key_id": self.audit_key_id,
                 "signature": ed_sign(
                     self.audit_seed,
                     signing_message("event", body)).hex()}
        conn.execute(
            "INSERT INTO events(tenant,stream,seq,receipt_id,hash,body) "
            "VALUES(?,?,?,?,?,?)",
            (self.tenant, prop["stream_id"], seq, body["receipt_id"],
             entry["hash"], J(entry)))
        prop["revision"] = seq
        prop["view_db"]["revision"] = seq
        prop["view_db"]["head_hash"] = entry["hash"]
        return entry

    def _set_state(self, prop: dict, state: str) -> None:
        prop["state"] = state
        prop["view_db"]["state"] = state
        prop["view_db"]["consumed"] = state in _CONSUMED_STATES

    def _flush(self, conn, prop: dict) -> None:
        conn.execute(
            "UPDATE proposals SET state=?, revision=?, view=? WHERE tenant=? "
            "AND id=?",
            (prop["state"], prop["revision"], J(prop["view_db"]),
             self.tenant, prop["id"]))

    # -- view materialization ------------------------------------------------------

    @staticmethod
    def _public_view(prop: dict) -> dict:
        return {k: v for k, v in prop["view_db"].items()
                if not k.startswith("_")}

    def _materialize(self, conn, prop: dict, now: int) -> bool:
        """Lazy expiry/invalidation; returns True iff an event was appended."""
        if prop["state"] not in _LIVE:
            return False
        action = self._action_of(prop)
        if now >= action["expires_ms"]:
            self._append_event(conn, prop,
                               {"type": "Expired",
                                "expires_ms": action["expires_ms"]},
                               SYSTEM_PRINCIPAL, now)
            self._set_state(prop, "EXPIRED")
            self._flush(conn, prop)
            return True
        authority = self._authority(conn, prop["executor"])
        if authority is None:
            return False
        policy = self._policy_of(conn, action["policy_hash"])
        roster_keys = {m["key_id"] for m in (policy or {}).get("roster", [])}
        if action["tool"] in authority["denied_tools"]:
            reason = "scope_denied"
        elif roster_keys & set(authority["revoked_keys"]):
            reason = "key_revoked"
        elif (authority["epoch"] != action["authority_epoch"]
              or authority["policy_hash"] != action["policy_hash"]):
            reason = "policy_changed"
        else:
            return False
        self._append_event(conn, prop,
                           {"type": "Invalidated", "reason": reason},
                           SYSTEM_PRINCIPAL, now)
        self._set_state(prop, "STALE")
        self._flush(conn, prop)
        return True

    # -- escalation ------------------------------------------------------------

    def _make_escalation(self, conn, prop: dict, reason: str, actor: str,
                         now: int) -> None:
        action = self._action_of(prop)
        esc_id = self.ids("escalation")
        self._append_event(conn, prop,
                           {"type": "Escalated", "reason": reason,
                            "escalation_id": esc_id}, actor, now)
        # Freeze the InboxRequest and its bundle hash at this checkpoint.
        bundle_hash = self._interim_bundle_hash(conn, prop, action)
        inbox_req = {"v": 1, "escalation_id": esc_id,
                     "idempotency_key": "vq-inbox/1/" + esc_id,
                     "tenant": self.tenant, "proposal_id": prop["id"],
                     "action_hash": H("action", action),
                     "bundle_hash": bundle_hash, "reason": reason,
                     "expires_ms": action["expires_ms"],
                     "summary": action["oversight"]["goal"],
                     "authority": "informational_only"}
        conn.execute(
            "INSERT INTO deliveries(tenant,escalation_id,proposal,state,"
            "attempts,request,inbox_ticket) VALUES(?,?,?,?,0,?,NULL)",
            (self.tenant, esc_id, prop["id"], "PENDING", J(inbox_req)))
        prop["view_db"]["escalation_id"] = esc_id
        self._set_state(prop, "ESCALATED")
        self._flush(conn, prop)

    def _interim_bundle_hash(self, conn, prop: dict, action: dict) -> str:
        policy = self._policy_of(conn, action["policy_hash"])
        events = self._events_of(conn, prop)
        votes = self._votes_of(conn, prop)
        authority = self._snapshot_authority(prop)
        enr = self._enrichment_of(conn, action)
        interim = {"v": 1, "profile": "vq.visreceipt/1", "action": action,
                   "policy": policy, "authority": authority,
                   "enrichment": enr, "votes": votes, "events": events,
                   "checkpoint": self._checkpoint_for(conn, prop, events,
                                                      authority)}
        return H("bundle", interim)

    def _events_of(self, conn, prop: dict) -> list:
        rows = conn.execute(
            "SELECT body FROM events WHERE tenant=? AND stream=? ORDER BY seq",
            (self.tenant, prop["stream_id"])).fetchall()
        return [_json.loads(bytes(r[0]).decode()) for r in rows]

    def _votes_of(self, conn, prop: dict) -> list:
        rows = conn.execute(
            "SELECT body FROM votes WHERE tenant=? AND proposal=? "
            "ORDER BY key_id", (self.tenant, prop["id"])).fetchall()
        return [_json.loads(bytes(r[0]).decode()) for r in rows]

    def _snapshot_authority(self, prop: dict) -> dict:
        blob = prop["commit_authority"] or prop["initial_authority"]
        return _json.loads(bytes(blob).decode())

    def _enrichment_of(self, conn, action: dict) -> Optional[dict]:
        if action["enrichment_hash"] is None:
            return None
        row = conn.execute(
            "SELECT body FROM evidence WHERE tenant=? AND hash=?",
            (self.tenant, action["enrichment_hash"])).fetchone()
        if row is None:
            return None
        return _json.loads(bytes(row[0]).decode())

    def _checkpoint_for(self, conn, prop: dict, events: list,
                        authority: dict) -> dict:
        head = events[-1]
        row = conn.execute(
            "SELECT body FROM checkpoints WHERE tenant=? AND proposal=? AND "
            "head_seq=?", (self.tenant, prop["id"],
                           head["body"]["seq"])).fetchone()
        if row is not None:
            return _json.loads(bytes(row[0]).decode())
        body = {"v": 1, "tenant": self.tenant, "proposal_id": prop["id"],
                "head_seq": head["body"]["seq"], "head_hash": head["hash"],
                "observed_ms": head["body"]["at_ms"],
                "authority_epoch": authority["epoch"]}
        cp = {"body": body, "key_id": self.audit_key_id,
              "signature": ed_sign(
                  self.audit_seed,
                  signing_message("checkpoint", body)).hex()}
        conn.execute(
            "INSERT INTO checkpoints(tenant,proposal,head_seq,body) "
            "VALUES(?,?,?,?)",
            (self.tenant, prop["id"], head["body"]["seq"], J(cp)))
        return cp

    # -- quorum ----------------------------------------------------------------

    def _approved(self, conn, prop: dict, policy: dict) -> tuple[list, list]:
        """(approved key_ids sorted, matching principal ids) from retained
        approve votes."""
        votes = self._votes_of(conn, prop)
        members = {m["key_id"]: m for m in policy["roster"]}
        keys = sorted({v["body"]["key_id"] for v in votes
                       if v["body"]["decision"] == "approve"
                       and v["body"]["key_id"] in members})
        return keys, [members[k]["principal_id"] for k in keys]

    def _quorum_satisfied(self, conn, prop: dict, policy: dict) -> bool:
        keys, principals = self._approved(conn, prop, policy)
        if len(set(principals)) < policy["threshold"]:
            return False
        if policy["require_human"]:
            members = {m["key_id"]: m for m in policy["roster"]}
            if not any(members[k]["kind"] == "human" for k in keys):
                return False
        return True

    def _evidence_put(self, conn, hash_: str, kind: str, body: bytes) -> None:
        conn.execute(
            "INSERT OR IGNORE INTO evidence(tenant,hash,kind,body) "
            "VALUES(?,?,?,?)", (self.tenant, hash_, kind, body))

    # -- configure ---------------------------------------------------------------

    def configure(self, request: dict, meta: dict) -> dict:
        req = schema.configure_request(request)
        caller = self._caller(meta)
        self._authorize(caller, "admin")
        with self._mu:
            with self.store.tx() as conn:
                now = self.store.logical_now(conn)
                kind, stored = self._dedupe(conn, "configure", req, meta)
                if kind == "replay":
                    return _json.loads(bytes(stored).decode())
                policy = req["policy"]
                if policy["tenant"] != self.tenant:
                    raise VQError("TENANT_MISMATCH")
                if (policy["executor_id"] != self.executor_id
                        or policy["environment"] != self.environment):
                    raise VQError("POLICY_INVALID",
                                  details={"reason": "scope_mismatch"})
                if policy["tool"] not in self.executors:
                    raise VQError("UNKNOWN_TOOL",
                                  details={"tool": policy["tool"]})
                if (self.manifest is not None
                        and self.manifest.get("irreversible")
                        and self.manifest.get("tool") == policy["tool"]
                        and not policy["require_human"]):
                    raise VQError("POLICY_INVALID",
                                  details={"reason": "irreversible_human"})
                denied = req["denied_tools"]
                revoked = req["revoked_keys"]
                if denied != sorted(set(denied)):
                    raise VQError("SCHEMA_INVALID",
                                  details={"field": "denied_tools"})
                if revoked != sorted(set(revoked)):
                    raise VQError("SCHEMA_INVALID",
                                  details={"field": "revoked_keys"})
                roster_keys = {m["key_id"] for m in policy["roster"]}
                if roster_keys & set(revoked):
                    raise VQError("POLICY_INVALID",
                                  details={"reason": "revoked_in_roster"})
                current = self._authority(conn)
                current_epoch = current["epoch"] if current else 0
                if req["expected_epoch"] != current_epoch:
                    raise VQError("EPOCH_CONFLICT",
                                  details={"current_epoch": current_epoch})
                if current is not None:
                    if not set(current["revoked_keys"]) <= set(revoked):
                        raise VQError("POLICY_INVALID",
                                      details={"reason": "revoked_shrink"})
                    # A public key once revoked can never re-enroll under any
                    # new key id within this executor identity.
                    revoked_pubs = self._revoked_public_keys(conn, revoked)
                    roster_pubs = {m["public_key"] for m in policy["roster"]}
                    if revoked_pubs & roster_pubs:
                        raise VQError(
                            "POLICY_INVALID",
                            details={"reason": "revoked_key_reenroll"})
                new_epoch = current_epoch + 1
                ph = H("policy", policy)
                auth = {"v": 1, "tenant": self.tenant,
                        "executor_id": self.executor_id, "epoch": new_epoch,
                        "policy_hash": ph, "denied_tools": denied,
                        "revoked_keys": revoked, "installed_ms": now}
                conn.execute(
                    "INSERT OR REPLACE INTO policies(tenant,hash,policy_id,"
                    "version,body) VALUES(?,?,?,?,?)",
                    (self.tenant, ph, policy["policy_id"],
                     policy["version"], J(policy)))
                self._evidence_put(conn, ph, "policy", J(policy))
                prev_hash = H("authority", current) if current else None
                conn.execute(
                    "INSERT OR REPLACE INTO authorities(tenant,executor,"
                    "epoch,body) VALUES(?,?,?,?)",
                    (self.tenant, self.executor_id, new_epoch, J(auth)))
                stream = self._admin_stream(conn)
                aseq = self._admin_seq(conn, stream)
                body = {"v": 1, "tenant": self.tenant, "stream_id": stream,
                        "receipt_id": self.ids("admin_receipt"), "seq": aseq,
                        "prev_hash": self._admin_prev(conn, stream),
                        "at_ms": now, "proposal_id": None,
                        "actor_id": caller["principal_id"],
                        "data": {"type": "AuthorityChanged",
                                 "authority": auth,
                                 "previous_authority_hash": prev_hash}}
                entry = {"body": body, "hash": H("event", body),
                         "key_id": self.audit_key_id,
                         "signature": ed_sign(
                             self.audit_seed,
                             signing_message("event", body)).hex()}
                conn.execute(
                    "INSERT INTO events(tenant,stream,seq,receipt_id,hash,"
                    "body) VALUES(?,?,?,?,?,?)",
                    (self.tenant, stream, aseq, body["receipt_id"],
                     entry["hash"], J(entry)))
                resp = {"authority": auth, "policy_hash": ph}
                self._record_request(conn, "configure", req, meta, resp)
                return resp

    def _revoked_public_keys(self, conn, revoked: list) -> set:
        pubs = set()
        rows = conn.execute(
            "SELECT body FROM policies WHERE tenant=?", (self.tenant,)
        ).fetchall()
        for r in rows:
            pol = _json.loads(bytes(r[0]).decode())
            for m in pol.get("roster", []):
                if m["key_id"] in revoked:
                    pubs.add(m["public_key"])
        return pubs

    def _admin_stream(self, conn) -> str:
        stream = self.store.meta_get("admin_stream") or ""
        if not stream:
            stream = self.ids("admin_stream")
            self.store.meta_set("admin_stream", stream, conn=conn)
        return stream

    def _admin_seq(self, conn, stream: str) -> int:
        row = conn.execute(
            "SELECT MAX(seq) FROM events WHERE tenant=? AND stream=?",
            (self.tenant, stream)).fetchone()
        return (row[0] or 0) + 1

    def _admin_prev(self, conn, stream: str) -> Optional[str]:
        row = conn.execute(
            "SELECT hash FROM events WHERE tenant=? AND stream=? ORDER BY seq "
            "DESC LIMIT 1", (self.tenant, stream)).fetchone()
        return row[0] if row else None

    def _rate_limit(self, bucket: list, limit: int, now: int) -> None:
        cutoff = now - 60000
        while bucket and bucket[0] < cutoff:
            bucket.pop(0)
        if len(bucket) >= limit:
            raise VQError("RATE_LIMITED", retryable=True,
                          details={"retry_after_ms": 60000})
        bucket.append(now)

    # -- propose ------------------------------------------------------------

    def propose(self, request: dict, meta: dict) -> dict:
        req = schema.propose_request(request)
        caller = self._caller(meta)
        self._authorize(caller, "propose")
        action, policy = req["action"], req["policy"]
        enrichment = req["enrichment"]
        if action["tenant"] != self.tenant:
            raise VQError("TENANT_MISMATCH")
        if caller["principal_id"] != action["proposer_id"]:
            raise VQError("FORBIDDEN", details={"reason": "proposer"})
        if action["executor_id"] != self.executor_id or \
                action["environment"] != self.environment:
            raise VQError("SCHEMA_INVALID", details={"reason": "scope"})
        with self._mu:
            with self.store.tx() as conn:
                now = self.store.logical_now(conn)
                self._rate_limit(self._rate_propose, RATE_PROPOSE_PER_MIN, now)
                # trusted policy resolution + hashes
                if H("policy", policy) != action["policy_hash"]:
                    raise VQError("HASH_MISMATCH",
                                  details={"reason": "policy"})
                if action["tool"] not in self.executors:
                    raise VQError("UNKNOWN_TOOL",
                                  details={"tool": action["tool"]})
                profile = ARG_PROFILES.get(action["tool"])
                if profile is not None:
                    profile(action["args"])
                self._check_enrichment_binding(action, enrichment)
                # idempotent replay / dedup ordering
                kind, stored = self._dedupe(conn, "propose", req, meta)
                if kind == "replay":
                    stored_resp = _json.loads(bytes(stored).decode())
                    old = self._load_proposal(
                        conn, stored_resp["proposal_id"])
                    if old is not None:
                        self._materialize(conn, old, now)
                    return self._public_view(old) if old else stored_resp
                existing = self._load_proposal(conn, action["proposal_id"])
                if existing is not None and \
                        bytes(existing["action_blob"] or b"") == J(action):
                    self._materialize(conn, existing, now)
                    return self._public_view(existing)
                consumed = conn.execute(
                    "SELECT proposal FROM consumed WHERE tenant=? AND "
                    "executor=? AND operation_id=?",
                    (self.tenant, self.executor_id,
                     action["operation_id"])).fetchone()
                if consumed is not None:
                    raise VQError("OPERATION_CONSUMED",
                                  details={"proposal_id": consumed[0]})
                live = conn.execute(
                    "SELECT id FROM proposals WHERE tenant=? AND executor=? "
                    "AND operation_id=? AND state IN ('OPEN','READY')",
                    (self.tenant, self.executor_id,
                     action["operation_id"])).fetchone()
                if live is not None:
                    raise VQError("ACTIVE_OPERATION",
                                  details={"proposal_id": live[0]})
                if existing is not None:
                    raise VQError("NONCE_REUSED",
                                  details={"field": "proposal_id"})
                nonce_hit = conn.execute(
                    "SELECT id FROM proposals WHERE tenant=? AND executor=? "
                    "AND nonce=?",
                    (self.tenant, self.executor_id,
                     action["nonce"])).fetchone()
                if nonce_hit is not None:
                    raise VQError("NONCE_REUSED", details={"field": "nonce"})
                authority = self._authority(conn)
                if authority is None or \
                        authority["policy_hash"] != action["policy_hash"] or \
                        authority["epoch"] != action["authority_epoch"]:
                    raise VQError("EPOCH_CONFLICT", details={
                        "current_epoch": None if authority is None
                        else authority["epoch"]})
                # time admission
                if not (action["created_ms"] <= now <=
                        action["created_ms"] + CREATED_WINDOW_MS):
                    raise VQError("SCHEMA_INVALID",
                                  details={"reason": "created_window"})
                ttl = action["expires_ms"] - action["created_ms"]
                if not 1000 <= ttl <= policy["max_ttl_ms"]:
                    raise VQError("SCHEMA_INVALID",
                                  details={"reason": "ttl"})
                if now >= action["expires_ms"]:
                    raise VQError("EXPIRED")
                n_active = conn.execute(
                    "SELECT COUNT(*) FROM proposals WHERE tenant=? AND "
                    "executor=? AND state IN ('OPEN','READY')",
                    (self.tenant, self.executor_id)).fetchone()[0]
                if n_active >= MAX_ACTIVE_PROPOSALS:
                    raise VQError("RATE_LIMITED", retryable=True)
                # evidence before Proposed, atomically
                stream = self.ids("proposal_stream")
                action_hash = H("action", action)
                view_db = {"proposal_id": action["proposal_id"],
                           "action_hash": action_hash,
                           "state": "OPEN", "revision": 0,
                           "approvals": 0,
                           "threshold": policy["threshold"],
                           "expires_ms": action["expires_ms"],
                           "consumed": False, "result": None,
                           "escalation_id": None, "head_hash": None,
                           "_stream": stream}
                prop = {"id": action["proposal_id"], "stream_id": stream,
                        "revision": 0, "state": "OPEN", "view_db": view_db,
                        "action_blob": J(action),
                        "initial_authority": J(authority),
                        "commit_authority": None,
                        "executor": self.executor_id,
                        "operation_id": action["operation_id"],
                        "nonce": action["nonce"]}
                self._evidence_put(conn, action_hash, "action", J(action))
                self._evidence_put(conn, action["policy_hash"], "policy",
                                   J(policy))
                if enrichment is not None:
                    self._evidence_put(conn, action["enrichment_hash"],
                                       "enrichment", J(enrichment))
                conn.execute(
                    "INSERT INTO proposals(tenant,id,executor,operation_id,"
                    "nonce,state,revision,action,view,initial_authority,"
                    "commit_authority) VALUES(?,?,?,?,?,?,0,?,?,?,NULL)",
                    (self.tenant, prop["id"], self.executor_id,
                     action["operation_id"], action["nonce"], "OPEN",
                     J(action), J(view_db), J(authority)))
                self._append_event(conn, prop, {
                    "type": "Proposed", "action_hash": action_hash,
                    "policy_hash": action["policy_hash"],
                    "authority_epoch": action["authority_epoch"]},
                    caller["principal_id"], now)
                # required-enrichment admission gate
                if policy["enrichment_required"]:
                    ok = (enrichment is not None
                          and enrichment["card"]["status"] == "known"
                          and 0 <= now - enrichment["card"]["observed_ms"]
                          <= 5000)
                    if not ok:
                        self._make_escalation(
                            conn, prop, "enrichment_unavailable",
                            caller["principal_id"], now)
                        self._record_request(conn, "propose", req, meta,
                                             self._public_view(prop))
                        return self._public_view(prop)
                self._flush(conn, prop)
                self._record_request(conn, "propose", req, meta,
                                     self._public_view(prop))
                return self._public_view(prop)

    def _check_enrichment_binding(self, action: dict,
                                  enrichment: Optional[dict]) -> None:
        if enrichment is None:
            if action["enrichment_hash"] is not None:
                raise VQError("HASH_MISMATCH",
                              details={"reason": "enrichment_absent"})
        elif action["enrichment_hash"] != H("enrichment", enrichment):
            raise VQError("HASH_MISMATCH",
                          details={"reason": "enrichment_hash"})

    # -- submit ------------------------------------------------------------

    def submit(self, request: dict, meta: dict) -> dict:
        req = schema.submit_request(request)
        caller = self._caller(meta)
        self._authorize(caller, "submit")
        with self._mu:
            with self.store.tx() as conn:
                now = self.store.logical_now(conn)
                self._rate_limit(self._rate_submit, RATE_SUBMIT_PER_MIN, now)
                prop = self._load_proposal(conn, req["proposal_id"])
                if prop is None:
                    raise VQError("NOT_FOUND",
                                  details={"proposal_id": req["proposal_id"]})
                if self._materialize(conn, prop, now):
                    return self._public_view(prop)
                kind, _ = self._dedupe(conn, "submit", req, meta)
                if kind == "replay":
                    return self._public_view(prop)
                action = self._action_of(prop)
                vote = req["vote"]
                body = vote["body"]
                if body["action_hash"] != H("action", action) or \
                        body["policy_hash"] != action["policy_hash"]:
                    raise VQError("HASH_MISMATCH",
                                  details={"reason": "vote_binding"})
                policy = self._policy_of(conn, action["policy_hash"])
                member = next((m for m in policy["roster"]
                               if m["key_id"] == body["key_id"]), None)
                if member is None:
                    raise VQError("KEY_NOT_ENROLLED",
                                  details={"key_id": body["key_id"]})
                ed_verify(bytes.fromhex(member["public_key"]),
                          bytes.fromhex(vote["signature"]),
                          signing_message("vote", body))
                prior = conn.execute(
                    "SELECT body FROM votes WHERE tenant=? AND proposal=? "
                    "AND key_id=?",
                    (self.tenant, prop["id"], body["key_id"])).fetchone()
                if prior is not None:
                    old = _json.loads(bytes(prior[0]).decode())
                    if H("vote", old["body"]) == H("vote", body):
                        self._flush(conn, prop)
                        return self._public_view(prop)
                    raise VQError("VOTE_CONFLICT",
                                  details={"key_id": body["key_id"]})
                if req["expected_revision"] != prop["revision"]:
                    raise VQError("REVISION_CONFLICT", retryable=True,
                                  details={"current_revision":
                                           prop["revision"]})
                if prop["state"] not in _LIVE:
                    raise VQError("STATE_CONFLICT",
                                  details={"state": prop["state"]})
                if now >= action["expires_ms"]:
                    raise VQError("EXPIRED")
                conn.execute(
                    "INSERT INTO votes(tenant,proposal,key_id,body) "
                    "VALUES(?,?,?,?)",
                    (self.tenant, prop["id"], body["key_id"], J(vote)))
                self._evidence_put(conn, H("vote", body), "vote", J(vote))
                self._append_event(conn, prop, {
                    "type": "VoteRecorded", "vote_hash": H("vote", body),
                    "key_id": body["key_id"], "decision": body["decision"]},
                    caller["principal_id"], now)
                if body["decision"] == "reject":
                    self._make_escalation(conn, prop, "reject_vote",
                                          caller["principal_id"], now)
                else:
                    prop["view_db"]["approvals"] = len(
                        set(self._approved(conn, prop, policy)[1]))
                    if prop["state"] == "OPEN" and self._quorum_satisfied(
                            conn, prop, policy):
                        keys, principals = self._approved(conn, prop, policy)
                        self._append_event(conn, prop, {
                            "type": "QuorumReached",
                            "approved_keys": keys,
                            "approved_principals": principals},
                            caller["principal_id"], now)
                        self._set_state(prop, "READY")
                self._flush(conn, prop)
                self._record_request(conn, "submit", req, meta,
                                     self._public_view(prop))
                return self._public_view(prop)

    # -- commit ------------------------------------------------------------

    def commit(self, request: dict, meta: dict, wait_ms: int = 5000) -> dict:
        req = schema.commit_request(request)
        caller = self._caller(meta)
        self._authorize(caller, "commit")
        if not 0 <= wait_ms <= DISPATCH_OBSERVE_MS:
            raise VQError("SCHEMA_INVALID",
                          details={"field": "wait_ms", "reason": "range"})
        with self._mu:
            # phase 1: state checks inside one transaction
            with self.store.tx() as conn:
                now = self.store.logical_now(conn)
                prop = self._load_proposal(conn, req["proposal_id"])
                if prop is None:
                    raise VQError("NOT_FOUND",
                                  details={"proposal_id": req["proposal_id"]})
                if self._materialize(conn, prop, now):
                    return self._public_view(prop)
                kind, _ = self._dedupe(conn, "commit", req, meta)
                if kind == "replay":
                    return self._public_view(prop)
                action = self._action_of(prop)
                if req["action_hash"] != H("action", action):
                    raise VQError("HASH_MISMATCH",
                                  details={"reason": "action_hash"})
                if prop["state"] in _CONSUMED_STATES:
                    return self._public_view(prop)
                if req["expected_revision"] != prop["revision"]:
                    raise VQError("REVISION_CONFLICT", retryable=True,
                                  details={"current_revision":
                                           prop["revision"]})
                if prop["state"] == "OPEN":
                    raise VQError("QUORUM_NOT_MET")
                if prop["state"] != "READY":
                    raise VQError("STATE_CONFLICT",
                                  details={"state": prop["state"]})
                policy = self._policy_of(conn, action["policy_hash"])
                if not self._quorum_satisfied(conn, prop, policy):
                    raise VQError("QUORUM_NOT_MET")
            # phase 2: host I/O outside any transaction (mutex still held)
            gate = self._gate_check(action)
            if gate["decision"] == "unavailable":
                raise VQError("GATE_UNAVAILABLE", retryable=True)
            if gate["decision"] == "deny":
                with self.store.tx() as conn:
                    now = self.store.logical_now(conn)
                    prop = self._load_proposal(conn, req["proposal_id"])
                    self._append_event(conn, prop, {
                        "type": "Invalidated", "reason": "scope_denied"},
                        SYSTEM_PRINCIPAL, now)
                    self._set_state(prop, "STALE")
                    self._flush(conn, prop)
                    return self._public_view(prop)
            executor = self.executors.get(action["tool"])
            if executor is None:
                raise VQError("UNKNOWN_TOOL",
                              details={"tool": action["tool"]})
            insp = self._inspect(executor, action)
            if not insp["ready"]:
                raise VQError("ADAPTER_UNAVAILABLE", retryable=True)
            if insp["preconditions"] != action["preconditions"]:
                with self.store.tx() as conn:
                    now = self.store.logical_now(conn)
                    prop = self._load_proposal(conn, req["proposal_id"])
                    self._append_event(conn, prop, {
                        "type": "Invalidated", "reason": "state_drift"},
                        SYSTEM_PRINCIPAL, now)
                    self._set_state(prop, "STALE")
                    self._flush(conn, prop)
                    return self._public_view(prop)
            # phase 3: compare-and-consume in a short final transaction
            with self.store.tx() as conn:
                now = self.store.logical_now(conn)
                prop = self._load_proposal(conn, req["proposal_id"])
                authority = self._authority(conn)
                if authority is None:
                    # cannot obtain a current scope decision: fail closed
                    raise VQError("GATE_UNAVAILABLE", retryable=True)
                # re-check authority/scope inside the final transaction
                if self._drifted(conn, prop, action, authority):
                    self._materialize(conn, prop, now)
                    return self._public_view(prop)
                if prop["state"] != "READY":
                    return self._public_view(prop)
                hook = self._hooks.get("in_consume_tx")
                if hook is not None:
                    hook()
                deadline = min(action["expires_ms"],
                               now + DISPATCH_DEADLINE_BUDGET_MS)
                dispatch_id = self.ids("dispatch")
                action_hash = H("action", action)
                dispatch_req = {
                    "v": 1, "action": action, "action_hash": action_hash,
                    "dispatch_id": dispatch_id,
                    "idempotency_key": "vq/1/%s/%s/%s" % (
                        self.tenant, self.executor_id,
                        action["operation_id"]),
                    "not_after_ms": deadline,
                    "preconditions": action["preconditions"],
                    "gate_revision": gate["revision"]}
                self._append_event(conn, prop, {
                    "type": "CommitStarted",
                    "authority_hash": H("authority", authority),
                    "operation_id": action["operation_id"],
                    "dispatch_id": dispatch_id,
                    "dispatch_deadline_ms": deadline,
                    "gate_revision": gate["revision"]},
                    caller["principal_id"], now)
                conn.execute(
                    "INSERT INTO consumed(tenant,executor,operation_id,"
                    "proposal,action_hash,dispatch_id) VALUES(?,?,?,?,?,?)",
                    (self.tenant, self.executor_id, action["operation_id"],
                     prop["id"], action_hash, dispatch_id))
                conn.execute(
                    "INSERT INTO dispatches(tenant,dispatch_id,request,"
                    "result) VALUES(?,?,?,NULL)",
                    (self.tenant, dispatch_id, J(dispatch_req)))
                conn.execute(
                    "UPDATE proposals SET commit_authority=? WHERE tenant=? "
                    "AND id=?", (J(authority), self.tenant, prop["id"]))
                prop["commit_authority"] = J(authority)
                self._set_state(prop, "DISPATCHING")
                self._flush(conn, prop)
            # adapter call outside the SQLite transaction (mutex still held)
            hook = self._hooks.get("before_dispatch")
            if hook is not None:
                hook()
            view = self._dispatch(prop["id"], dispatch_id, dispatch_req,
                                  wait_ms, caller)
            self._record_request_later("commit", req, meta, view)
            return view

    def _drifted(self, conn, prop, action, authority) -> bool:
        if authority is None:
            return False
        policy = self._policy_of(conn, action["policy_hash"])
        roster_keys = {m["key_id"] for m in (policy or {}).get("roster", [])}
        return (action["tool"] in authority["denied_tools"]
                or bool(roster_keys & set(authority["revoked_keys"]))
                or authority["epoch"] != action["authority_epoch"]
                or authority["policy_hash"] != action["policy_hash"])

    def _record_request_later(self, method: str, req: dict, meta: dict,
                              response: dict) -> None:
        with self._mu:
            with self.store.tx() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO requests(tenant,principal,method,"
                    "request_id,request_hash,response) VALUES(?,?,?,?,?,?)",
                    (self.tenant, schema.caller(meta["caller"])["principal_id"],
                     method, meta["idempotency_key"],
                     self._request_hash(
                         method, req,
                         schema.caller(meta["caller"])["principal_id"]),
                     J(response)))

    def _gate_check(self, action: dict) -> dict:
        if self.gate is None:
            return {"decision": "unavailable", "revision": None}
        resp = self.gate.check({"action": action,
                                "action_hash": H("action", action)})
        return schema.gate_response(resp)

    def _inspect(self, executor: Any, action: dict) -> dict:
        try:
            resp = executor.inspect({"action": action,
                                     "action_hash": H("action", action)})
        except VQError:
            raise
        except Exception:
            return {"ready": False, "code": "ADAPTER_UNAVAILABLE"}
        return schema.inspect_response(resp)

    def _dispatch(self, proposal_id: str, dispatch_id: str,
                  dispatch_req: dict, wait_ms: int, caller: dict) -> dict:
        """Bounded adapter call; returns the current View."""
        action = dispatch_req["action"]
        hook = self._hooks.get("mutate_dispatch")
        if hook is not None:
            hook(dispatch_req)
        if H("action", action) != dispatch_req["action_hash"]:
            # pre-call mutation: no provider call at all
            self._finish_dispatch(proposal_id, dispatch_id, {
                "status": "unknown", "code": "ACTION_MUTATED",
                "output_hash": None, "provider_ref": None}, caller)
            return self._current_view(proposal_id)
        handed = copy.deepcopy(action)
        executor = self.executors[action["tool"]]
        outcome: dict[str, Any] = {}
        done = threading.Event()

        def call():
            try:
                outcome["result"] = executor.dispatch(
                    {**dispatch_req, "action": handed})
            except Exception as e:  # adapter faults are UNKNOWN, not failure
                outcome["error"] = e
            finally:
                done.set()

        threading.Thread(target=call, daemon=True).start()
        completed = done.wait(min(wait_ms, DISPATCH_OBSERVE_MS) / 1000.0)
        if not completed:
            if wait_ms >= DISPATCH_OBSERVE_MS:
                result = {"status": "unknown", "code": "TRANSPORT_UNKNOWN",
                          "output_hash": None, "provider_ref": None}
                self._finish_dispatch(proposal_id, dispatch_id, result,
                                      caller)
            else:
                self._watch_dispatch(done, outcome, handed, dispatch_req,
                                     proposal_id, dispatch_id, caller)
            return self._current_view(proposal_id)
        result = self._classify_outcome(outcome, handed, dispatch_req)
        self._finish_dispatch(proposal_id, dispatch_id, result, caller)
        return self._current_view(proposal_id)

    def _classify_outcome(self, outcome, handed, dispatch_req) -> dict:
        if "error" in outcome:
            return {"status": "unknown", "code": "TRANSPORT_UNKNOWN",
                    "output_hash": None, "provider_ref": None}
        # rehash the exact defensive copy handed to the adapter
        if H("action", handed) != dispatch_req["action_hash"]:
            return {"status": "unknown", "code": "ACTION_MUTATED",
                    "output_hash": None, "provider_ref": None}
        try:
            return schema.result(outcome["result"])
        except VQError:
            return {"status": "unknown", "code": "MALFORMED_RESULT",
                    "output_hash": None, "provider_ref": None}

    def _watch_dispatch(self, done, outcome, handed, dispatch_req,
                        proposal_id, dispatch_id, caller) -> None:
        def watch():
            if not done.wait(DISPATCH_OBSERVE_MS / 1000.0):
                result = {"status": "unknown", "code": "TRANSPORT_UNKNOWN",
                          "output_hash": None, "provider_ref": None}
            else:
                result = self._classify_outcome(outcome, handed, dispatch_req)
            self._finish_dispatch(proposal_id, dispatch_id, result, caller)

        threading.Thread(target=watch, daemon=True).start()

    def _finish_dispatch(self, proposal_id: str, dispatch_id: str,
                         result: dict, caller: dict) -> None:
        with self._mu:
            with self.store.tx() as conn:
                now = self.store.logical_now(conn)
                prop = self._load_proposal(conn, proposal_id)
                if prop is None or prop["state"] != "DISPATCHING":
                    return
                self._append_event(conn, prop, {
                    "type": "ExecutionReported", "result": result},
                    caller["principal_id"], now)
                state = {"succeeded": "SUCCEEDED", "failed": "FAILED",
                         "unknown": "UNKNOWN"}[result["status"]]
                prop["view_db"]["result"] = result
                self._set_state(prop, state)
                self._flush(conn, prop)
                conn.execute(
                    "UPDATE dispatches SET result=? WHERE tenant=? AND "
                    "dispatch_id=?",
                    (J(result), self.tenant, dispatch_id))

    def _current_view(self, proposal_id: str) -> dict:
        prop = self._load_proposal(self.store.db, proposal_id)
        return self._public_view(prop)

    # -- get / cancel / escalate ------------------------------------------------

    def get(self, request: dict, meta: dict) -> dict:
        req = schema.read_request(request)
        caller = self._caller(meta)
        self._authorize(caller, "read")
        with self._mu:
            with self.store.tx() as conn:
                now = self.store.logical_now(conn)
                prop = self._load_proposal(conn, req["proposal_id"])
                if prop is None:
                    raise VQError("NOT_FOUND",
                                  details={"proposal_id": req["proposal_id"]})
                self._materialize(conn, prop, now)
                return self._public_view(prop)

    def cancel(self, request: dict, meta: dict) -> dict:
        req = schema.cancel_request(request)
        caller = self._caller(meta)
        with self._mu:
            with self.store.tx() as conn:
                prop = self._load_proposal(conn, req["proposal_id"])
                if prop is None:
                    raise VQError("NOT_FOUND",
                                  details={"proposal_id": req["proposal_id"]})
                action = self._action_of(prop)
                if caller["tenant"] != self.tenant:
                    raise VQError("TENANT_MISMATCH")
                if not (caller["principal_id"] == action["proposer_id"]
                        or "admin" in caller["capabilities"]):
                    raise VQError("FORBIDDEN")
                now = self.store.logical_now(conn)
                if self._materialize(conn, prop, now):
                    return self._public_view(prop)
                kind, _ = self._dedupe(conn, "cancel", req, meta)
                if kind == "replay":
                    return self._public_view(prop)
                if req["expected_revision"] != prop["revision"]:
                    raise VQError("REVISION_CONFLICT", retryable=True,
                                  details={"current_revision":
                                           prop["revision"]})
                if prop["state"] not in _LIVE:
                    raise VQError("STATE_CONFLICT",
                                  details={"state": prop["state"]})
                self._append_event(conn, prop, {
                    "type": "Canceled", "reason": "requester_canceled"},
                    caller["principal_id"], now)
                self._set_state(prop, "CANCELED")
                self._flush(conn, prop)
                self._record_request(conn, "cancel", req, meta,
                                     self._public_view(prop))
                return self._public_view(prop)

    def escalate(self, request: dict, meta: dict) -> dict:
        req = schema.escalate_request(request)
        caller = self._caller(meta)
        self._authorize(caller, "escalate")
        with self._mu:
            with self.store.tx() as conn:
                now = self.store.logical_now(conn)
                prop = self._load_proposal(conn, req["proposal_id"])
                if prop is None:
                    raise VQError("NOT_FOUND",
                                  details={"proposal_id": req["proposal_id"]})
                if self._materialize(conn, prop, now):
                    return self._public_view(prop)
                kind, _ = self._dedupe(conn, "escalate", req, meta)
                if kind == "replay":
                    return self._public_view(prop)
                if req["expected_revision"] != prop["revision"]:
                    raise VQError("REVISION_CONFLICT", retryable=True,
                                  details={"current_revision":
                                           prop["revision"]})
                if prop["state"] not in _LIVE:
                    raise VQError("STATE_CONFLICT",
                                  details={"state": prop["state"]})
                self._make_escalation(conn, prop, req["reason"],
                                      caller["principal_id"], now)
                self._record_request(conn, "escalate", req, meta,
                                     self._public_view(prop))
                return self._public_view(prop)

    # -- deliver --------------------------------------------------------------

    def deliver(self, request: dict, meta: dict) -> dict:
        req = schema.deliver_request(request)
        caller = self._caller(meta)
        self._authorize(caller, "escalate")
        with self._mu:
            with self.store.tx() as conn:
                row = conn.execute(
                    "SELECT proposal,state,attempts,request,inbox_ticket "
                    "FROM deliveries WHERE tenant=? AND escalation_id=?",
                    (self.tenant, req["escalation_id"])).fetchone()
                if row is None:
                    raise VQError("NOT_FOUND",
                                  details={"escalation_id":
                                           req["escalation_id"]})
                proposal_id, dstate, attempts, req_blob, ticket = row
                kind, stored = self._dedupe(conn, "deliver", req, meta)
                if kind == "replay":
                    return _json.loads(bytes(stored).decode())
                prop = self._load_proposal(conn, proposal_id)
                now = self.store.logical_now(conn)
                if dstate == "ACKED":
                    resp = {"delivery": "ACKED", "inbox_ticket": ticket,
                            "view": self._public_view(prop)}
                    self._record_request(conn, "deliver", req, meta, resp)
                    return resp
                if attempts >= MAX_DELIVERY_ATTEMPTS:
                    raise VQError("DELIVERY_LIMIT",
                                  details={"escalation_id":
                                           req["escalation_id"]})
                if self.inbox is None:
                    raise VQError("ADAPTER_UNAVAILABLE", retryable=True)
                inbox_req = _json.loads(bytes(req_blob).decode())
                try:
                    resp = schema.inbox_response(
                        self.inbox.deliver(inbox_req))
                    ok = True
                except VQError as e:
                    resp = e
                    ok = False
                except Exception as e:
                    resp = VQError("UNAVAILABLE",
                                   details={"inbox": type(e).__name__})
                    ok = False
                if ok:
                    self._append_event(conn, prop, {
                        "type": "EscalationDelivered",
                        "escalation_id": req["escalation_id"],
                        "inbox_ticket": resp["inbox_ticket"]},
                        caller["principal_id"], now)
                    conn.execute(
                        "UPDATE deliveries SET state='ACKED', attempts=?, "
                        "inbox_ticket=? WHERE tenant=? AND escalation_id=?",
                        (attempts + 1, resp["inbox_ticket"], self.tenant,
                         req["escalation_id"]))
                    out = {"delivery": "ACKED",
                           "inbox_ticket": resp["inbox_ticket"],
                           "view": self._public_view(prop)}
                else:
                    code = "REJECTED" if getattr(
                        resp, "code", None) == "REJECTED" else "UNAVAILABLE"
                    self._append_event(conn, prop, {
                        "type": "EscalationDeferred",
                        "escalation_id": req["escalation_id"],
                        "attempt": attempts + 1, "code": code},
                        caller["principal_id"], now)
                    conn.execute(
                        "UPDATE deliveries SET attempts=? WHERE tenant=? AND "
                        "escalation_id=?",
                        (attempts + 1, self.tenant, req["escalation_id"]))
                    out = {"delivery": "PENDING", "inbox_ticket": None,
                           "view": self._public_view(prop)}
                self._flush(conn, prop)
                self._record_request(conn, "deliver", req, meta, out)
                return out

    # -- reconcile -------------------------------------------------------------

    def reconcile(self, request: dict, meta: dict) -> dict:
        req = schema.reconcile_request(request)
        caller = self._caller(meta)
        self._authorize(caller, "commit")
        with self._mu:
            with self.store.tx() as conn:
                now = self.store.logical_now(conn)
                prop = self._load_proposal(conn, req["proposal_id"])
                if prop is None:
                    raise VQError("NOT_FOUND",
                                  details={"proposal_id": req["proposal_id"]})
                self._materialize(conn, prop, now)
                kind, _ = self._dedupe(conn, "reconcile", req, meta)
                if kind == "replay":
                    return self._public_view(prop)
                if prop["state"] != "UNKNOWN":
                    raise VQError("STATE_CONFLICT",
                                  details={"state": prop["state"]})
                dispatch_id = self._dispatch_id_of(conn, prop)
                action = self._action_of(prop)
                executor = self.executors.get(action["tool"])
                if executor is None:
                    raise VQError("ADAPTER_UNAVAILABLE", retryable=True)
                lookup_req = {
                    "v": 1, "operation_id": action["operation_id"],
                    "idempotency_key": "vq/1/%s/%s/%s" % (
                        self.tenant, self.executor_id,
                        action["operation_id"]),
                    "dispatch_id": dispatch_id}
            # read-only provider lookup outside any transaction
            try:
                lr = schema.lookup_result(executor.lookup(lookup_req))
            except VQError:
                raise
            except Exception:
                raise VQError("ADAPTER_UNAVAILABLE", retryable=True) from None
            if lr["observed"] == "unresolved":
                return self._current_view(req["proposal_id"])
            with self.store.tx() as conn:
                now = self.store.logical_now(conn)
                prop = self._load_proposal(conn, req["proposal_id"])
                if prop["state"] != "UNKNOWN":
                    return self._public_view(prop)
                self._append_event(conn, prop, {
                    "type": "ExecutionReconciled", "result": lr["result"]},
                    caller["principal_id"], now)
                state = "SUCCEEDED" if lr["observed"] == "succeeded" \
                    else "FAILED"
                prop["view_db"]["result"] = lr["result"]
                self._set_state(prop, state)
                self._flush(conn, prop)
                self._record_request(conn, "reconcile", req, meta,
                                     self._public_view(prop))
                return self._public_view(prop)

    def _dispatch_id_of(self, conn, prop: dict) -> str:
        row = conn.execute(
            "SELECT dispatch_id FROM consumed WHERE tenant=? AND proposal=?",
            (self.tenant, prop["id"])).fetchone()
        return row[0]

    # -- export ----------------------------------------------------------------

    def export_proof(self, request: dict, meta: dict) -> dict:
        req = schema.read_request(request)
        caller = self._caller(meta)
        self._authorize(caller, "read")
        with self._mu:
            with self.store.tx() as conn:
                now = self.store.logical_now(conn)
                prop = self._load_proposal(conn, req["proposal_id"])
                if prop is None:
                    raise VQError("NOT_FOUND",
                                  details={"proposal_id": req["proposal_id"]})
                self._materialize(conn, prop, now)
                self._flush(conn, prop)
                if prop["action_blob"] is None:
                    raise VQError("PROOF_PRUNED")
                action = self._action_of(prop)
                policy = self._policy_of(conn, action["policy_hash"])
                if policy is None:
                    raise VQError("PROOF_PRUNED")
                enrichment = self._enrichment_of(conn, action)
                if action["enrichment_hash"] is not None and \
                        enrichment is None:
                    raise VQError("PROOF_PRUNED")
                events = self._events_of(conn, prop)
                votes = self._votes_of(conn, prop)
                authority = self._snapshot_authority(prop)
                cp = self._checkpoint_for(conn, prop, events, authority)
                proof = {"v": 1, "profile": "vq.visreceipt/1",
                         "action": action, "policy": policy,
                         "authority": authority, "enrichment": enrichment,
                         "votes": votes, "events": events, "checkpoint": cp}
                return {"bundle_hash": H("bundle", proof), "proof": proof}

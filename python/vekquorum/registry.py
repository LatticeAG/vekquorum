"""Registry semantics — the spec's per-tenant registry logic, runnable locally.

The *hosted* registry (Workers ingress, DO namespaces, AES-GCM chunk storage)
is a documented stub in :mod:`vekquorum.hosted`.  This module implements the
registry's semantic core — policy/bundle registration, head comparison,
equivocation quarantine, tenant isolation, and verify rate limiting — against
the §12.2 logical tables in a local SQLite file, so conformance probes and
operators exercise real rules rather than a mock.

Local bodies are stored unencrypted: the hosted AES-256-GCM chunk encryption
is a deployment binding, not part of registry semantics.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Optional

from . import schema
from .canon import J
from .errors import VQError
from .hashing import H, validate_hash
from .verifier import verify_proof

SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE policies (tenant TEXT NOT NULL, hash TEXT NOT NULL,
  policy_id TEXT NOT NULL, version INTEGER NOT NULL, body BLOB NOT NULL,
  PRIMARY KEY (tenant,hash), UNIQUE (tenant,policy_id,version));
CREATE TABLE bundles (tenant TEXT NOT NULL, hash TEXT NOT NULL,
  proposal TEXT NOT NULL, head_seq INTEGER NOT NULL, head_hash TEXT NOT NULL,
  body BLOB NOT NULL, registered_ms INTEGER NOT NULL,
  PRIMARY KEY (tenant,hash));
CREATE TABLE heads (tenant TEXT NOT NULL, proposal TEXT NOT NULL,
  head_seq INTEGER NOT NULL, head_hash TEXT NOT NULL, bundle_hash TEXT,
  quarantined INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant,proposal));
CREATE TABLE conflicts (tenant TEXT NOT NULL, proposal TEXT NOT NULL,
  left_checkpoint BLOB NOT NULL, right_checkpoint BLOB NOT NULL);
CREATE TABLE requests (tenant TEXT NOT NULL, principal TEXT NOT NULL,
  route TEXT NOT NULL, key TEXT NOT NULL, body_hash TEXT NOT NULL,
  response BLOB NOT NULL,
  PRIMARY KEY (tenant,principal,route,key));
CREATE TABLE buckets (tenant TEXT NOT NULL, route TEXT NOT NULL,
  minute INTEGER NOT NULL, count INTEGER NOT NULL,
  PRIMARY KEY (tenant,route,minute));
"""


class LocalRegistry:
    """Single-tenant-scope registry with hosted-equivalent semantics."""

    def __init__(self, db_path: Optional[str] = None, *,
                 trust: Optional[dict] = None,
                 clock_ms=None, limits: Optional[dict] = None):
        self.path = db_path or ":memory:"
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(SCHEMA)
        self.trust = trust
        self._clock = clock_ms or (lambda: 0)
        # verify_per_minute / writes_per_minute (hosted defaults per spec)
        self.limits = {"verify_per_minute": 60, "writes_per_minute": 30}
        if limits:
            self.limits.update(limits)

    def close(self) -> None:
        self.db.close()

    def _tx(self):
        db = self.db

        class _T:
            def __enter__(self):
                db.execute("BEGIN IMMEDIATE")
                return db

            def __exit__(self, et, e, tb):
                db.execute("ROLLBACK" if et else "COMMIT")
                return False

        return _T()

    def _rate(self, tenant: str, route: str, limit: int, now: int) -> None:
        minute = now // 60000
        with self._tx() as conn:
            row = conn.execute(
                "SELECT count FROM buckets WHERE tenant=? AND route=? AND "
                "minute=?", (tenant, route, minute)).fetchone()
            n = row[0] if row else 0
            if n >= limit:
                raise VQError("RATE_LIMITED", retryable=True,
                              details={"retry_after_ms": 60000})
            conn.execute(
                "INSERT INTO buckets(tenant,route,minute,count) "
                "VALUES(?,?,?,1) ON CONFLICT(tenant,route,minute) "
                "DO UPDATE SET count=count+1", (tenant, route, minute))

    # -- verify (hosted-equivalent; no registry side effect) -------------------

    def verify(self, proof: Any, *, tenant: str, now: Optional[int] = None
               ) -> dict:
        """POST /v1/verify semantics under the server-pinned Trust."""
        now = self._clock() if now is None else now
        self._rate(tenant, "verify", self.limits["verify_per_minute"], now)
        if self.trust is None or self.trust["tenant"] != tenant:
            raise VQError("UNTRUSTED")
        result = verify_proof(proof, self.trust)
        result["freshness"] = "offline_unchecked"
        return result

    # -- policies --------------------------------------------------------------

    def put_policy(self, policy: Any, *, tenant: str, principal: str,
                   key: Optional[str] = None) -> dict:
        p = schema.policy(policy)
        if p["tenant"] != tenant:
            raise VQError("TENANT_MISMATCH")
        ph = H("policy", p)
        with self._tx() as conn:
            if key is not None:
                row = conn.execute(
                    "SELECT body_hash,response FROM requests WHERE tenant=? "
                    "AND principal=? AND route='put_policy' AND key=?",
                    (tenant, principal, key)).fetchone()
                if row is not None:
                    if row[0] != H("request", p):
                        raise VQError("IDEMPOTENCY_CONFLICT")
                    return json.loads(bytes(row[1]).decode())
            clash = conn.execute(
                "SELECT hash FROM policies WHERE tenant=? AND policy_id=? "
                "AND version=?",
                (tenant, p["policy_id"], p["version"])).fetchone()
            if clash is not None and clash[0] != ph:
                raise VQError("POLICY_VERSION_CONFLICT")
            if self.trust is not None and \
                    ph not in self.trust["policy_hashes"]:
                raise VQError("UNTRUSTED",
                              details={"reason": "policy_not_allowlisted"})
            existed = conn.execute(
                "SELECT 1 FROM policies WHERE tenant=? AND hash=?",
                (tenant, ph)).fetchone() is not None
            conn.execute(
                "INSERT OR IGNORE INTO policies(tenant,hash,policy_id,"
                "version,body) VALUES(?,?,?,?,?)",
                (tenant, ph, p["policy_id"], p["version"], J(p)))
            resp = {"policy_hash": ph, "registered": not existed}
            if key is not None:
                conn.execute(
                    "INSERT INTO requests(tenant,principal,route,key,"
                    "body_hash,response) VALUES(?,?,?,?,?,?)",
                    (tenant, principal, "put_policy", key,
                     H("request", p), J(resp)))
            return resp

    def get_policy(self, policy_hash: str, *, tenant: str) -> dict:
        validate_hash(policy_hash)
        row = self.db.execute(
            "SELECT body FROM policies WHERE tenant=? AND hash=?",
            (tenant, policy_hash)).fetchone()
        if row is None:
            raise VQError("NOT_FOUND")
        return {"policy_hash": policy_hash,
                "policy": json.loads(bytes(row[0]).decode())}

    # -- bundles / heads ---------------------------------------------------------

    def put_proof(self, proof: Any, *, tenant: str, principal: str,
                  key: Optional[str] = None,
                  now: Optional[int] = None) -> dict:
        """POST /v1/bundles: verify, persist, compare head atomically."""
        now = self._clock() if now is None else now
        self._rate(tenant, "put_proof", self.limits["writes_per_minute"], now)
        if self.trust is None or self.trust["tenant"] != tenant:
            raise VQError("UNTRUSTED")
        try:
            p = schema.proof(proof)
        except VQError as e:
            raise VQError(e.code) from None
        if p["action"]["tenant"] != tenant:
            raise VQError("TENANT_MISMATCH")
        result = verify_proof(p, self.trust)
        if result["integrity"] != "valid":
            first = next((c["code"] for c in result["checks"]
                          if not c["ok"]), "SCHEMA_INVALID")
            raise VQError(first, details={"check": "verify"})
        bh = H("bundle", p)
        body = p["checkpoint"]["body"]
        pid, seq, hh = body["proposal_id"], body["head_seq"], body["head_hash"]
        equiv_error = None
        with self._tx() as conn:
            if key is not None:
                row = conn.execute(
                    "SELECT body_hash,response FROM requests WHERE tenant=? "
                    "AND principal=? AND route='put_proof' AND key=?",
                    (tenant, principal, key)).fetchone()
                if row is not None:
                    if row[0] != bh:
                        raise VQError("IDEMPOTENCY_CONFLICT")
                    return json.loads(bytes(row[1]).decode())
            head = conn.execute(
                "SELECT head_seq,head_hash,bundle_hash,quarantined "
                "FROM heads WHERE tenant=? AND proposal=?",
                (tenant, pid)).fetchone()
            quarantined = bool(head[3]) if head else False
            equivocation = (head is not None and seq == head[0]
                            and hh != head[1])
            # persist the bundle regardless of head outcome; a quarantined
            # proposal still stores later valid bundles without advancing
            conn.execute(
                "INSERT OR IGNORE INTO bundles(tenant,hash,proposal,"
                "head_seq,head_hash,body,registered_ms) "
                "VALUES(?,?,?,?,?,?,?)",
                (tenant, bh, pid, seq, hh, J(p), now))
            if equivocation:
                stored = conn.execute(
                    "SELECT body FROM bundles WHERE tenant=? AND hash=?",
                    (tenant, head[2])).fetchone()
                left_cp = None
                if stored is not None:
                    left_cp = json.loads(
                        bytes(stored[0]).decode())["checkpoint"]
                conn.execute(
                    "INSERT INTO conflicts(tenant,proposal,left_checkpoint,"
                    "right_checkpoint) VALUES(?,?,?,?)",
                    (tenant, pid, J(left_cp), J(p["checkpoint"])))
                conn.execute(
                    "UPDATE heads SET quarantined=1 WHERE tenant=? AND "
                    "proposal=?", (tenant, pid))
                resp = {"error": {"code": "EQUIVOCATION",
                                  "retryable": False,
                                  "request_id": key,
                                  "details": {"proposal_id": pid,
                                              "head_seq": seq}}}
                if key is not None:
                    conn.execute(
                        "INSERT INTO requests(tenant,principal,route,key,"
                        "body_hash,response) VALUES(?,?,?,?,?,?)",
                        (tenant, principal, "put_proof", key, bh, J(resp)))
                equiv_error = _Equivocation(resp)
            else:
                if head is None or (seq > head[0] and not quarantined):
                    conn.execute(
                        "INSERT INTO heads(tenant,proposal,head_seq,"
                        "head_hash,bundle_hash,quarantined) "
                        "VALUES(?,?,?,?,?,0) ON CONFLICT(tenant,proposal) "
                        "DO UPDATE SET head_seq=excluded.head_seq, "
                        "head_hash=excluded.head_hash, "
                        "bundle_hash=excluded.bundle_hash",
                        (tenant, pid, seq, hh, bh))
                cur = conn.execute(
                    "SELECT head_seq,head_hash FROM heads WHERE tenant=? "
                    "AND proposal=?", (tenant, pid)).fetchone()
                resp = {"bundle_hash": bh, "registered": True,
                        "head_seq": cur[0], "head_hash": cur[1]}
                if key is not None:
                    conn.execute(
                        "INSERT INTO requests(tenant,principal,route,key,"
                        "body_hash,response) VALUES(?,?,?,?,?,?)",
                        (tenant, principal, "put_proof", key, bh, J(resp)))
        if equiv_error is not None:
            raise equiv_error
        return resp

    def get_proof(self, bundle_hash: str, *, tenant: str) -> dict:
        validate_hash(bundle_hash)
        row = self.db.execute(
            "SELECT body FROM bundles WHERE tenant=? AND hash=?",
            (tenant, bundle_hash)).fetchone()
        if row is None:
            raise VQError("NOT_FOUND")
        return {"bundle_hash": bundle_hash,
                "proof": json.loads(bytes(row[0]).decode())}

    def head(self, proposal_id: str, *, tenant: str,
             now: Optional[int] = None) -> dict:
        schema.v_id("proposal")(proposal_id, "proposal_id")
        now = self._clock() if now is None else now
        row = self.db.execute(
            "SELECT head_seq,head_hash,bundle_hash,quarantined FROM heads "
            "WHERE tenant=? AND proposal=?", (tenant, proposal_id)).fetchone()
        if row is None:
            raise VQError("NOT_FOUND")
        return {"proposal_id": proposal_id, "head_seq": row[0],
                "head_hash": row[1], "bundle_hash": row[2],
                "freshness": "registry_observed", "observed_ms": now,
                "quarantined": bool(row[3])}

    def conflicts(self, proposal_id: str, *, tenant: str) -> list:
        rows = self.db.execute(
            "SELECT left_checkpoint,right_checkpoint FROM conflicts "
            "WHERE tenant=? AND proposal=?", (tenant, proposal_id)).fetchall()
        return [[json.loads(bytes(l).decode()), json.loads(bytes(r).decode())]
                for l, r in rows]

    def healthz(self) -> dict:
        return {"status": "ready", "protocol": "vq/1"}


class _Equivocation(VQError):
    def __init__(self, response: dict):
        super().__init__("EQUIVOCATION")
        self.response = response


def registry_failure(err: VQError, request_id: Optional[str]) -> dict:
    out = err.to_failure()
    out["error"]["request_id"] = request_id
    return out

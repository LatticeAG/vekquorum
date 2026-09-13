"""Executor / ScopeGate / Inbox adapter contracts and reference adapters.

All adapter surfaces are protocols (structural).  The coordinator never
imports provider SDKs; adapters are registered by trusted application code.

Reference implementations shipped here:

* ``RefundSimulator`` — deterministic ``covenant.refund`` executor enforcing
  payment version CAS, exact minor units/currency, deadline and provider
  idempotency in one storage transaction (a lock-guarded atomic section).
* ``FixtureGate`` — explicitly configured local scope permit/deny/unavailable.
* ``FileInbox`` — local file-mode escalation delivery per the persistence
  spec: exclusive create of ``{escalation_id}.json`` holding exactly
  ``J(InboxRequest)``, mode 0600, fsync(file) then fsync(directory).
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import threading
from typing import Any, Protocol

from . import schema
from .errors import VQError
from .hashing import H

# ---------------------------------------------------------------------------
# Contracts (structural typing — adapters are trusted host code)


class Executor(Protocol):
    def inspect(self, request: dict) -> dict:
        """InspectRequest -> InspectResponse (bounded read-only)."""

    def dispatch(self, request: dict) -> dict:
        """DispatchRequest -> Result.  Called at most once per operation."""

    def lookup(self, request: dict) -> dict:
        """LookupRequest -> LookupResult (read-only reconciliation)."""


class ScopeGate(Protocol):
    def check(self, request: dict) -> dict:
        """{action, action_hash} -> GateResponse allow/deny/unavailable."""


class Inbox(Protocol):
    def deliver(self, request: dict) -> dict:
        """InboxRequest -> InboxResponse."""


# ---------------------------------------------------------------------------
# covenant.refund reference profile


def covenant_refund_args(args: dict) -> dict:
    """The reference profile accepts exactly
    {payment_id:string, amount_minor:UInt>0, currency:"USD"}."""
    if not isinstance(args, dict):
        raise VQError("SCHEMA_INVALID", details={"field": "args"})
    for key in args:
        if key not in ("payment_id", "amount_minor", "currency"):
            raise VQError("UNKNOWN_FIELD", details={"object": "args",
                                                  "field": key})
    for key in ("payment_id", "amount_minor", "currency"):
        if key not in args:
            raise VQError("SCHEMA_INVALID",
                          details={"field": "args." + key, "reason": "missing"})
    if not isinstance(args["payment_id"], str) or \
            not schema.PAYMENT_ID_RE.match(args["payment_id"]):
        raise VQError("SCHEMA_INVALID",
                      details={"field": "args.payment_id"})
    if not isinstance(args["amount_minor"], int) or \
            isinstance(args["amount_minor"], bool) or \
            args["amount_minor"] <= 0 or \
            args["amount_minor"] > schema.SAFE_INT_MAX:
        raise VQError("NUMBER_PROFILE",
                      details={"field": "args.amount_minor"})
    if args["currency"] != "USD":
        raise VQError("SCHEMA_INVALID", details={"field": "args.currency"})
    return args


class RefundSimulator:
    """Deterministic covenant.refund simulator.

    Not a deployable Stripe/Covenant interface: it exists so the reference
    profile exercises real deadline/CAS/idempotency semantics in tests and
    local development.
    """

    tool = "covenant.refund"
    # Provider capability claims used by live-environment readiness checks.
    capabilities = {"provider_idempotency": True,
                    "atomic_preconditions": True,
                    "effect_deadline_enforced": True}
    build_hash = None  # deployment-pinned in production; None in dev/test

    def __init__(self, payments: dict[str, dict] | None = None,
                 clock_ms=None):
        # payments: payment_id -> {"version": str, "amount_minor": int,
        #                          "currency": "USD"}.  The default table holds
        # the spec's canonical demo payment so the reference profile is
        # exercisable end to end from the CLI without a provider account.
        self._payments = payments if payments is not None else {
            "pay_demo": {"version": "7", "amount_minor": 100,
                         "currency": "USD"}}
        self._ledger: dict[str, dict] = {}        # idempotency_key -> Result
        self._intent_by_payment: dict[str, str] = {}  # payment_id -> op key
        self._effects = 0
        self._lock = threading.Lock()
        self._clock_ms = clock_ms
        self.expected_gate_revision: str | None = None

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def _payment_resource(payment_id: str) -> str:
        return "payment:" + payment_id

    def _now_ms(self, request: dict) -> int:
        # Effect linearization time: the simulator's own clock.  Tests may pin
        # it; production wrappers supply real wall time.
        if self._clock_ms is not None:
            return int(self._clock_ms())
        import time
        return int(time.time() * 1000)

    @property
    def effects(self) -> int:
        return self._effects

    # -- executor surface ---------------------------------------------------------

    def inspect(self, request: dict) -> dict:
        action = schema.action(request["action"])
        covenant_refund_args(action["args"])
        pid = action["args"]["payment_id"]
        with self._lock:
            payment = self._payments.get(pid)
            if payment is None:
                return {"ready": True, "preconditions": []}
            return {"ready": True, "preconditions": [{
                "resource": self._payment_resource(pid),
                "version": str(payment["version"])}]}

    def dispatch(self, request: dict) -> dict:
        req = schema.dispatch_request(request)
        action = req["action"]
        covenant_refund_args(action["args"])
        if H("action", action) != req["action_hash"]:
            raise VQError("HASH_MISMATCH", details={"reason": "action"})
        with self._lock:  # single storage transaction for CAS/deadline/idem
            prior = self._ledger.get(req["idempotency_key"])
            if prior is not None:
                return dict(prior)
            result = self._execute_locked(req)
            self._ledger[req["idempotency_key"]] = dict(result)
            return result

    def _execute_locked(self, req: dict) -> dict:
        action = req["action"]
        args = action["args"]
        pid = args["payment_id"]
        effect_ms = self._now_ms(req)
        if effect_ms >= req["not_after_ms"]:
            return {"status": "failed", "code": "DEADLINE_EXCEEDED",
                    "output_hash": None, "provider_ref": None}
        if (self.expected_gate_revision is not None
                and req["gate_revision"] != self.expected_gate_revision):
            return {"status": "failed", "code": "SCOPE_CHANGED",
                    "output_hash": None, "provider_ref": None}
        payment = self._payments.get(pid)
        if payment is None:
            return {"status": "failed", "code": "PAYMENT_NOT_FOUND",
                    "output_hash": None, "provider_ref": None}
        want = {p["resource"]: p["version"] for p in req["preconditions"]}
        current = want.get(self._payment_resource(pid))
        if current is None or current != str(payment["version"]):
            return {"status": "failed", "code": "PRECONDITION_CHANGED",
                    "output_hash": None, "provider_ref": None}
        prior_intent = self._intent_by_payment.get(pid)
        if prior_intent is not None and \
                prior_intent != req["idempotency_key"]:
            return {"status": "failed", "code": "INTENT_CONSUMED",
                    "output_hash": None, "provider_ref": None}
        if payment["amount_minor"] < args["amount_minor"]:
            return {"status": "failed", "code": "AMOUNT_MISMATCH",
                    "output_hash": None, "provider_ref": None}
        if payment.get("currency", "USD") != args["currency"]:
            return {"status": "failed", "code": "CURRENCY_MISMATCH",
                    "output_hash": None, "provider_ref": None}
        # Effect: mark the payment refunded under this intent.
        self._intent_by_payment[pid] = req["idempotency_key"]
        payment["version"] = str(int(payment["version"]) + 1)
        self._effects += 1
        refund_id = "refund_" + req["dispatch_id"][4:]
        output = {"refund_id": refund_id, "amount_minor": args["amount_minor"],
                  "currency": args["currency"]}
        return {"status": "succeeded", "code": "OK",
                "output_hash": H("output", output),
                "provider_ref": refund_id}

    def lookup(self, request: dict) -> dict:
        req = schema.lookup_request(request)
        with self._lock:
            prior = self._ledger.get(req["idempotency_key"])
            if prior is None:
                return {"observed": "unresolved", "result": None}
            observed = prior["status"]
            return {"observed": observed, "result": dict(prior)}


# ---------------------------------------------------------------------------
# Scope gate


class FixtureGate:
    """Explicitly configured local permit — the offline-fixture gateway
    boundary.  It never infers allow from absence of a decision."""

    def __init__(self, decision: str = "allow",
                 revision: str = "local-test-1"):
        self.decision = decision
        self.revision = revision

    def check(self, request: dict) -> dict:
        if self.decision == "unavailable":
            return {"decision": "unavailable", "revision": None}
        return {"decision": self.decision, "revision": self.revision}


# ---------------------------------------------------------------------------
# File inbox


class FileInbox:
    """Local file-mode escalation delivery.

    Each escalation is an exclusive-create file ``{escalation_id}.json``
    containing exactly ``J(InboxRequest)``; the acknowledgment ticket is
    ``file:{escalation_id}``.  A name collision with different bytes is
    REJECTED and never overwritten.
    """

    def __init__(self, directory: str):
        self.directory = directory
        os.makedirs(directory, exist_ok=True)

    def deliver(self, request: dict) -> dict:
        req = schema.inbox_request(request)
        from .canon import J
        payload = J(req)
        path = os.path.join(self.directory,
                            req["escalation_id"] + ".json")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            with open(path, "rb") as existing:
                same = existing.read() == payload
            if same:
                return {"escalation_id": req["escalation_id"],
                        "inbox_ticket": "file:" + req["escalation_id"],
                        "duplicate": True}
            raise VQError("REJECTED",
                          details={"escalation_id": req["escalation_id"]})
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        dirfd = os.open(self.directory, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        return {"escalation_id": req["escalation_id"],
                "inbox_ticket": "file:" + req["escalation_id"],
                "duplicate": False}


class UnavailableInbox:
    """Adapter stub used when delivery must fail: returns nothing, raises a
    transport-level failure the coordinator records as EscalationDeferred."""

    def __init__(self, code: str = "UNAVAILABLE"):
        self.code = code

    def deliver(self, request: dict) -> dict:
        raise VQError(self.code)

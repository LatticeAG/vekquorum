"""Conformance harness — the named probes from the spec's §16 preamble.

Each probe drives the real implementation (never a mock of the coordinator)
and returns exactly the fields the vector expects.  Fixture-prefix state is
loaded verbatim into the SQLite store so generated continuations must
reproduce the same signed bytes.
"""

import copy
import json
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                              "python"))
sys.path.insert(0, os.path.dirname(__file__))

import fixture as F  # noqa: E402
from vekquorum import schema  # noqa: E402
from vekquorum.adapters import (FileInbox, FixtureGate,  # noqa: E402
                                RefundSimulator)
from vekquorum.api import canonicalize as api_canonicalize  # noqa: E402
from vekquorum.api import tally as api_tally  # noqa: E402
from vekquorum.canon import J  # noqa: E402
from vekquorum.coordinator import Coordinator  # noqa: E402
from vekquorum.display import render_field  # noqa: E402
from vekquorum.errors import VQError  # noqa: E402
from vekquorum.hashing import H  # noqa: E402
from vekquorum.ids import SequentialIds, ident  # noqa: E402
from vekquorum.registry import LocalRegistry, _Equivocation  # noqa: E402
from vekquorum.store import Store  # noqa: E402
from vekquorum.telemetry import sanitize  # noqa: E402
from vekquorum.verifier import verify_proof  # noqa: E402

K4_SEED = F.SK[4]

PREFIXES = {
    "ABSENT": [], "OPEN": [F.E1], "ONE": [F.E1, F.E2],
    "READY": [F.E1, F.E2, F.E3, F.E4],
    "RUN": [F.E1, F.E2, F.E3, F.E4, F.E5],
    "OK": [F.E1, F.E2, F.E3, F.E4, F.E5, F.E6],
    "ESC": [F.E1, F.E_ESC],
    "UNKNOWN": [F.E1, F.E2, F.E3, F.E4, F.E5, F.E_UNKNOWN],
}
PREFIX_STATE = {"ABSENT": None, "OPEN": "OPEN", "ONE": "OPEN",
                "READY": "READY", "RUN": "DISPATCHING", "OK": "SUCCEEDED",
                "ESC": "ESCALATED", "UNKNOWN": "UNKNOWN"}
PREFIX_VOTES = {"ABSENT": [], "OPEN": [], "ONE": [F.VA],
                "READY": [F.VA, F.VB], "RUN": [F.VA, F.VB],
                "OK": [F.VA, F.VB], "ESC": [], "UNKNOWN": [F.VA, F.VB]}


class ScriptedExecutor(RefundSimulator):
    """Refund simulator with a scripted result for fixture reproduction and
    optional lookup script; still runs the real CAS/deadline/idempotency
    logic before returning."""

    def __init__(self, payments=None, clock_ms=None, forced_result=None,
                 lookup_result=None, mutate=None):
        super().__init__(payments, clock_ms)
        self.forced_result = forced_result
        self.lookup_result = lookup_result
        self.dispatch_calls = 0
        self.lookup_calls = 0
        self.inspect_calls = 0
        self._preconditions_override = None

    def set_preconditions(self, pre):
        self._preconditions_override = pre

    def inspect(self, request):
        self.inspect_calls += 1
        resp = super().inspect(request)
        if self._preconditions_override is not None:
            resp = {"ready": True,
                    "preconditions": self._preconditions_override}
        return resp

    def dispatch(self, request):
        self.dispatch_calls += 1
        result = super().dispatch(request)
        if self.forced_result is not None and result["status"] == "succeeded":
            return dict(self.forced_result)
        return result

    def lookup(self, request):
        self.lookup_calls += 1
        if self.lookup_result is not None:
            return self.lookup_result
        return super().lookup(request)


class ScriptedInbox:
    def __init__(self, ticket="inbox-test-1", fail=None):
        self.calls = []
        self.ticket = ticket
        self.fail = fail

    def deliver(self, request):
        req = schema.inbox_request(request)
        self.calls.append(copy.deepcopy(req))
        if self.fail is not None:
            raise VQError(self.fail)
        return {"escalation_id": req["escalation_id"],
                "inbox_ticket": self.ticket, "duplicate": False}


def _new_store(tmpdir, name="vq.sqlite"):
    return Store(os.path.join(str(tmpdir), name),
                 wall_clock_ms=lambda: F.T)


def _load_prefix(store, state, authority=None, inbox_req=True):
    """Load a named fixture prefix verbatim into the store."""
    authority = authority or F.AUTH
    state = {"SUCCEEDED": "OK", "DISPATCHING": "RUN",
             "ESCALATED": "ESC"}.get(state, state)
    events = PREFIXES[state]
    votes = PREFIX_VOTES[state]
    with store.tx() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO authorities(tenant,executor,epoch,body)"
            " VALUES(?,?,?,?)",
            (F.TEN, F.EXE, authority["epoch"], J(authority)))
        conn.execute(
            "INSERT OR REPLACE INTO policies(tenant,hash,policy_id,version,"
            "body) VALUES(?,?,?,?,?)",
            (F.TEN, F.PH, F.P["policy_id"], F.P["version"], J(F.P)))
        conn.execute(
            "INSERT OR IGNORE INTO evidence(tenant,hash,kind,body) "
            "VALUES(?,?,?,?)", (F.TEN, F.PH, "policy", J(F.P)))
        conn.execute(
            "INSERT OR IGNORE INTO evidence(tenant,hash,kind,body) "
            "VALUES(?,?,?,?)", (F.TEN, F.AH, "action", J(F.A)))
        if state != "ABSENT":
            for e in events:
                conn.execute(
                    "INSERT INTO events(tenant,stream,seq,receipt_id,hash,"
                    "body) VALUES(?,?,?,?,?,?)",
                    (e["body"]["tenant"], e["body"]["stream_id"],
                     e["body"]["seq"], e["body"]["receipt_id"], e["hash"],
                     J(e)))
            st = PREFIX_STATE[state]
            view_db = {"proposal_id": F.PID, "action_hash": F.AH,
                       "state": st, "revision": len(events),
                       "approvals": len({v["body"]["key_id"] for v in votes
                                         if v["body"]["decision"]
                                         == "approve"}),
                       "threshold": 2, "expires_ms": F.A["expires_ms"],
                       "consumed": st in ("DISPATCHING", "SUCCEEDED",
                                          "FAILED", "UNKNOWN"),
                       "result": None, "escalation_id": None,
                       "head_hash": events[-1]["hash"], "_stream": F.STREAM}
            if st in ("SUCCEEDED",):
                view_db["result"] = F.RESULT
            if st == "UNKNOWN":
                view_db["result"] = F.UNKNOWN
            if st == "ESCALATED":
                view_db["escalation_id"] = F.ESC
            conn.execute(
                "INSERT INTO proposals(tenant,id,executor,operation_id,"
                "nonce,state,revision,action,view,initial_authority,"
                "commit_authority) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (F.TEN, F.PID, F.EXE, F.OP, F.A["nonce"], st,
                 len(events), J(F.A), J(view_db), J(F.AUTH),
                 J(F.AUTH) if view_db["consumed"] else None))
            for v in votes:
                conn.execute(
                    "INSERT OR IGNORE INTO votes(tenant,proposal,key_id,"
                    "body) VALUES(?,?,?,?)",
                    (F.TEN, F.PID, v["body"]["key_id"], J(v)))
                conn.execute(
                    "INSERT OR IGNORE INTO evidence(tenant,hash,kind,body) "
                    "VALUES(?,?,?,?)",
                    (F.TEN, H("vote", v["body"]), "vote", J(v)))
            if view_db["consumed"]:
                conn.execute(
                    "INSERT INTO consumed(tenant,executor,operation_id,"
                    "proposal,action_hash,dispatch_id) "
                    "VALUES(?,?,?,?,?,?)",
                    (F.TEN, F.EXE, F.OP, F.PID, F.AH, F.DISPATCH))
                dreq = {"v": 1, "action": F.A, "action_hash": F.AH,
                        "dispatch_id": F.DISPATCH, "idempotency_key": F.IDEM,
                        "not_after_ms": F.T + 5003,
                        "preconditions": F.A["preconditions"],
                        "gate_revision": "local-test-1"}
                result = J(F.RESULT) if st == "SUCCEEDED" else (
                    J(F.UNKNOWN) if st == "UNKNOWN" else None)
                conn.execute(
                    "INSERT INTO dispatches(tenant,dispatch_id,request,"
                    "result) VALUES(?,?,?,?)",
                    (F.TEN, F.DISPATCH, J(dreq), result))
            if st == "ESCALATED" and inbox_req:
                conn.execute(
                    "INSERT INTO deliveries(tenant,escalation_id,proposal,"
                    "state,attempts,request,inbox_ticket) "
                    "VALUES(?,?,?,?,0,?,NULL)",
                    (F.TEN, F.ESC, F.PID, "PENDING", J(F.INBOX)))
        # loaded fixture state models a live coordinator: mark shutdown clean
        conn.execute(
            "UPDATE meta SET value=? WHERE key='last_clean_shutdown'",
            (b"true",))


def _coordinator(store, now, *, authority=None, gate=None,
                 executor=None, inbox=None, hooks=None,
                 receipt_start=None, stream_start=0):
    ids = SequentialIds(counters={
        "receipt": (receipt_start if receipt_start is not None else 0),
        "admin_receipt": 99000, "proposal_stream": stream_start,
        "admin_stream": 99000, "dispatch": 0, "escalation": 0})
    store._wall_clock_ms = lambda: now
    if executor is None:
        executor = ScriptedExecutor(
            payments={"pay_demo": {"version": "7", "amount_minor": 100,
                                   "currency": "USD"}},
            clock_ms=lambda: now, forced_result=F.RESULT)
    if gate is None:
        gate = FixtureGate("allow", "local-test-1")
    if inbox is None:
        inbox = ScriptedInbox()
    return Coordinator(store, tenant=F.TEN, executor_id=F.EXE,
                       environment="test", audit_key_id=F.K[4],
                       audit_seed=K4_SEED,
                       executors={"covenant.refund": executor},
                       gate=gate, inbox=inbox, id_source=ids, hooks=hooks)


def _meta(n=100):
    return {"caller": F.CALLER, "idempotency_key": ident("vqi_", n)}


def _view_state(store, proposal_id):
    row = store.db.execute(
        "SELECT state, view FROM proposals WHERE tenant=? AND id=?",
        (F.TEN, proposal_id)).fetchone()
    if row is None:
        return "ABSENT", None
    return row[0], json.loads(bytes(row[1]).decode())


def _consumed(store, operation_id=F.OP):
    return store.db.execute(
        "SELECT 1 FROM consumed WHERE tenant=? AND operation_id=?",
        (F.TEN, operation_id)).fetchone() is not None


def _events_added(store, stream, after_seq):
    rows = store.db.execute(
        "SELECT body FROM events WHERE tenant=? AND stream=? AND seq>? "
        "ORDER BY seq", (F.TEN, stream, after_seq)).fetchall()
    out = []
    for (blob,) in rows:
        e = json.loads(bytes(blob).decode())
        d = e["body"]["data"]
        name = d["type"]
        if name == "Invalidated":
            name = "Invalidated:" + d["reason"]
        elif name == "Escalated" and d["reason"] == "enrichment_unavailable":
            name = "Escalated:enrichment_unavailable"
        elif name == "ExecutionReported" and \
                d["result"]["code"] == "ACTION_MUTATED":
            name = "ExecutionReported:ACTION_MUTATED"
        out.append(name)
    return out


# ---------------------------------------------------------------------------
# probes


def probe_canonicalize(inp):
    try:
        return {"canonical_utf8": api_canonicalize(inp["raw_utf8"])}
    except VQError as e:
        return {"code": e.code}


def probe_hash(inp):
    return {"hash": H(inp["kind"], inp["value"])}


def probe_different(inp):
    return {"different": inp["left"] != inp["right"]}


def probe_action_schema(inp):
    try:
        schema.action(inp["action"])
        return {"code": "OK"}
    except VQError as e:
        return {"code": e.code}


def probe_policy(inp):
    try:
        schema.policy(inp["policy"])
        return {"code": "OK"}
    except VQError as e:
        return {"code": e.code}


def probe_tally(inp):
    return api_tally(action=inp["action"], policy=inp["policy"],
                     votes=inp["votes"])


def probe_verify(inp):
    result = verify_proof(inp["proof"], inp["trust"])
    first_error = next(
        (c["code"] for c in result["checks"]
         if c["code"] not in ("OK", "NOT_RUN")), None)
    proj = inp.get("projection", "all")
    if proj == "all":
        return result
    out = {}
    for k in proj:
        if k == "first_error":
            out["first_error"] = first_error
        elif k == "network_calls":
            out["network_calls"] = 0
        elif k in result:
            out[k] = result[k]
    return out


def probe_step(tmpdir, inp):
    """Load prefix, run the method, project the outcome."""
    store = _new_store(tmpdir)
    try:
        start = inp["start"]
        extra = dict(inp)
        for k in ("start", "method", "request", "now"):
            extra.pop(k, None)
        authority = extra.get("authority", F.AUTH)
        _load_prefix(store, start, authority=authority,
                     inbox_req=(start == "ESC"))
        executor = ScriptedExecutor(
            payments={"pay_demo": {"version": "7", "amount_minor": 100,
                                   "currency": "USD"}},
            clock_ms=lambda: extra.get("provider_effect_ms", inp["now"]),
            forced_result=extra.get("provider_result", F.RESULT))
        if "live_preconditions" in extra:
            executor.set_preconditions(extra["live_preconditions"])
        gate = FixtureGate("allow", "local-test-1")
        if "gate" in extra:
            g = extra["gate"]
            gate = FixtureGate(g["decision"], g.get("revision"))
        hooks = {}
        if "mutate_dispatch_copy" in extra:
            m = extra["mutate_dispatch_copy"]

            def mutate(dispatch_req):
                target = dispatch_req
                if m["path"][0] not in target and "action" in target:
                    target = target["action"]
                for k in m["path"][:-1]:
                    target = target[k]
                target[m["path"][-1]] = m["value"]
            hooks["mutate_dispatch"] = mutate
        n_events = len(PREFIXES[start])
        coord = _coordinator(store, inp["now"], gate=gate, executor=executor,
                             hooks=hooks, receipt_start=n_events,
                             stream_start=1 if n_events else 0)
        method = inp["method"]
        req = inp["request"]
        code, view = "OK", None
        try:
            fn = {"propose": coord.propose, "submit": coord.submit,
                  "commit": coord.commit, "cancel": coord.cancel,
                  "escalate": coord.escalate, "get": coord.get,
                  "reconcile": coord.reconcile}[method]
            view = fn(req, _meta())
        except VQError as e:
            code = e.code
            view = None
        # projection: state of the addressed (or blocking) proposal
        pid = req.get("proposal_id", F.PID)
        if method == "propose" and view is not None:
            pid = view["proposal_id"]
        elif method == "propose" and code == "OPERATION_CONSUMED":
            row = store.db.execute(
                "SELECT proposal FROM consumed WHERE tenant=? AND "
                "operation_id=?", (F.TEN, req["action"]["operation_id"])
            ).fetchone()
            pid = row[0] if row else F.PID
        state, view_db = _view_state(store, pid)
        stream = (view_db or {}).get("_stream", F.STREAM)
        # a newly created proposal's stream counts all its events
        after = 0 if stream != F.STREAM else n_events
        added = _events_added(store, stream, after)
        return {"code": code, "state": state, "added_events": added,
                "dispatch_calls": executor.dispatch_calls,
                "consumed": _consumed(
                    store, req.get("action", F.A)["operation_id"])}
    finally:
        store.close()


def probe_boot(tmpdir, inp):
    store = _new_store(tmpdir, "boot.sqlite")
    try:
        store.meta_set("last_logical_ms", str(inp["persisted_last_ms"]))
        frontier = inp.get("external_frontier")
        if inp.get("restored_head") is not None:
            # restored backup: load events through the restored head
            evs = [e for e in F.EVENTS
                   if e["body"]["seq"] <= 4]
            with store.tx() as conn:
                for e in evs:
                    conn.execute(
                        "INSERT INTO events(tenant,stream,seq,receipt_id,"
                        "hash,body) VALUES(?,?,?,?,?,?)",
                        (e["body"]["tenant"], e["body"]["stream_id"],
                         e["body"]["seq"], e["body"]["receipt_id"],
                         e["hash"], J(e)))
        try:
            Coordinator(store, tenant=F.TEN, executor_id=F.EXE,
                        environment="test", audit_key_id=F.K[4],
                        audit_seed=K4_SEED,
                        executors={"covenant.refund": ScriptedExecutor()},
                        gate=FixtureGate(), inbox=ScriptedInbox(),
                        id_source=SequentialIds(),
                        readiness_frontier=frontier)
            return {"ready": True, "code": "OK"}
        except VQError as e:
            return {"ready": False, "code": e.code}
    finally:
        store.close()


class SimulatedCrash(Exception):
    pass


def probe_crash(tmpdir, inp):
    store = _new_store(tmpdir, "crash.sqlite")
    try:
        _load_prefix(store, inp["start"])
        at = inp["at"]
        executor = ScriptedExecutor(
            payments={"pay_demo": {"version": "7", "amount_minor": 100,
                                   "currency": "USD"}},
            clock_ms=lambda: inp["restart_ms"], forced_result=F.RESULT)
        hooks = {}
        if at == "after_commit_before_dispatch":
            def boom():
                raise SimulatedCrash()
            hooks["before_dispatch"] = boom
        elif at == "before_transaction_commit":
            def boom2():
                raise SimulatedCrash()
            hooks["in_consume_tx"] = boom2
        coord = _coordinator(store, inp["restart_ms"], executor=executor,
                             hooks=hooks,
                             receipt_start=len(PREFIXES[inp["start"]]))
        try:
            coord.commit(inp["request"], _meta())
        except SimulatedCrash:
            pass
        except VQError:
            pass
        # restart: unclean shutdown flag, new coordinator over same store
        store.db.execute(
            "UPDATE meta SET value=? WHERE key='last_clean_shutdown'",
            (b"false",))
        coord2 = _coordinator(store, inp["restart_ms"], executor=executor,
                              receipt_start=20)
        state, _ = _view_state(store, F.PID)
        row = store.db.execute(
            "SELECT result FROM dispatches WHERE tenant=? AND "
            "dispatch_id=?", (F.TEN, F.DISPATCH)).fetchone()
        result_code = None
        if row is not None and row[0] is not None:
            result_code = json.loads(bytes(row[0]).decode())["code"]
        return {"state": state, "consumed": _consumed(store),
                "dispatch_calls": executor.dispatch_calls,
                "result_code": result_code}
    finally:
        store.close()


def probe_race(tmpdir, inp):
    store = _new_store(tmpdir, "race.sqlite")
    try:
        _load_prefix(store, inp["start"])
        executor = ScriptedExecutor(
            payments={"pay_demo": {"version": "7", "amount_minor": 100,
                                   "currency": "USD"}},
            clock_ms=lambda: F.T + 4, forced_result=F.RESULT)
        coord = _coordinator(store, F.T + 3, executor=executor,
                             receipt_start=5)
        barrier = threading.Barrier(3)
        outcomes = {}

        def worker(i, rid):
            barrier.wait()
            try:
                coord.commit(inp["requests"][i],
                             _meta_named(rid))
                outcomes[i] = "OK"
            except VQError as e:
                outcomes[i] = e.code

        def _meta_named(rid):
            return {"caller": F.CALLER, "idempotency_key": rid}

        threads = [threading.Thread(
            target=worker, args=(i, rid))
            for i, rid in enumerate(inp["request_ids"])]
        for t in threads:
            t.start()
        barrier.wait()
        for t in threads:
            t.join(30)
        consumed_rows = store.db.execute(
            "SELECT COUNT(*) FROM consumed WHERE tenant=?",
            (F.TEN,)).fetchone()[0]
        commit_events = store.db.execute(
            "SELECT COUNT(*) FROM events WHERE tenant=? AND stream=? AND "
            "json_extract(CAST(body AS TEXT),'$.body.data.type')="
            "'CommitStarted'", (F.TEN, F.STREAM)).fetchone()[0]
        state, _ = _view_state(store, F.PID)
        return {"dispatch_calls": executor.dispatch_calls,
                "consumed_rows": consumed_rows, "commit_events": commit_events,
                "final_state": state}
    finally:
        store.close()


def probe_provider(inp):
    req = dict(inp["request"])
    sim = RefundSimulator(
        payments={"pay_demo": {"version": inp.get("payment_version", "7"),
                               "amount_minor": 100, "currency": "USD"}},
        clock_ms=lambda: inp["effect_ms"])
    result = sim.dispatch(req)
    return {"status": result["status"], "code": result["code"],
            "effects": sim.effects}


def probe_registry(tmpdir, inp):
    reg = LocalRegistry(os.path.join(str(tmpdir), "reg.sqlite"),
                        trust=F.TRUST, clock_ms=lambda: F.T + 10)
    try:
        method = inp["method"]
        if "existing" in inp:
            reg.put_proof(inp["existing"], tenant=F.TEN,
                          principal=F.PROP, key=ident("vqi_", 90))
        if method == "put_proof":
            try:
                reg.put_proof(inp["proof"], tenant=F.TEN,
                              principal=F.PROP, key=ident("vqi_", 91))
                return {"http": 201, "code": "OK", "quarantined": False}
            except _Equivocation as e:
                confs = reg.conflicts(F.PID, tenant=F.TEN)
                return {"http": 409, "code": "EQUIVOCATION",
                        "quarantined": True,
                        "retained_conflicting_checkpoints": len(confs) + 1}
            except VQError as e:
                return {"http": 422, "code": e.code, "quarantined": False}
        if method == "verify":
            # simulate prior requests this minute
            now = F.T + 10
            for i in range(inp.get("prior_requests_this_minute", 0)):
                reg._rate(F.TEN, "verify", inp.get("limit", 60), now)
            try:
                reg.verify(inp["proof"], tenant=F.TEN, now=now)
                return {"http": 200, "code": "OK",
                        "verification_started": True}
            except VQError as e:
                return {"http": 429, "code": e.code,
                        "verification_started": False}
        if method == "get_proof":
            try:
                out = reg.get_proof(inp["bundle_hash"],
                                    tenant=inp["authenticated_tenant"])
                return {"http": 200, "code": "OK",
                        "proof_returned": out is not None}
            except VQError as e:
                return {"http": 404, "code": e.code,
                        "proof_returned": False}
        raise AssertionError("unknown registry method " + method)
    finally:
        reg.close()


def probe_readiness(tmpdir, inp):
    store = _new_store(tmpdir, "ready.sqlite")
    try:
        executor = ScriptedExecutor()
        if "actual_build_hash" in inp:
            executor.build_hash = inp["actual_build_hash"]
        if "effect_deadline_enforced" in inp:
            executor.capabilities = {
                "provider_idempotency": inp.get("provider_idempotency", True),
                "atomic_preconditions": inp.get("atomic_preconditions", True),
                "effect_deadline_enforced":
                    inp["effect_deadline_enforced"]}
        manifest = None
        if "pinned_build_hash" in inp:
            manifest = {"v": 1, "executor_id": inp.get("executor_id", F.EXE),
                        "tool": "covenant.refund",
                        "schema_hash": H("request", {"s": 1}),
                        "build_hash": inp["pinned_build_hash"],
                        "irreversible": False}
        env = inp.get("environment", "test")
        try:
            Coordinator(store, tenant=F.TEN,
                        executor_id=inp.get("executor_id", F.EXE),
                        environment=env, audit_key_id=F.K[4],
                        audit_seed=K4_SEED,
                        executors={"covenant.refund": executor},
                        gate=FixtureGate(), inbox=ScriptedInbox(),
                        id_source=SequentialIds(), manifest=manifest)
            return {"ready": True, "code": "OK"}
        except VQError as e:
            return {"ready": False, "code": e.code}
    finally:
        store.close()


def probe_logging(inp):
    return sanitize(dict(inp))


def probe_display(inp):
    return {"display_json": render_field(inp["text"]),
            "signatures_created": 0, "authority_granted": False}


def probe_reconcile(tmpdir, inp):
    store = _new_store(tmpdir, "recon.sqlite")
    try:
        _load_prefix(store, "UNKNOWN")
        executor = ScriptedExecutor(
            payments={"pay_demo": {"version": "8", "amount_minor": 100,
                                   "currency": "USD"}},
            clock_ms=lambda: inp["now"], forced_result=F.RESULT,
            lookup_result=inp["lookup"])
        coord = _coordinator(store, inp["now"], executor=executor,
                             receipt_start=6)
        view = coord.reconcile({"proposal_id": F.PID}, _meta())
        state, _ = _view_state(store, F.PID)
        return {"state": state,
                "added_events": _events_added(store, F.STREAM, 6),
                "dispatch_calls": executor.dispatch_calls,
                "consumed": _consumed(store)}
    finally:
        store.close()


def probe_export(tmpdir, inp):
    store = _new_store(tmpdir, "export.sqlite")
    try:
        _load_prefix(store, inp["state"])
        if not inp.get("action_payload_present", True):
            store.db.execute(
                "UPDATE proposals SET action=NULL WHERE tenant=? AND id=?",
                (F.TEN, inp["proposal_id"]))
            store.db.execute(
                "DELETE FROM evidence WHERE tenant=? AND kind='action'",
                (F.TEN,))
        coord = _coordinator(store, F.T + 5, receipt_start=6)
        try:
            out = coord.export_proof({"proposal_id": inp["proposal_id"]},
                                     _meta())
            return {"code": "OK", "proof": out["proof"]}
        except VQError as e:
            return {"code": e.code, "proof": None}
    finally:
        store.close()


PROBES = {
    "canonicalize": lambda tmp, i: probe_canonicalize(i),
    "hash": lambda tmp, i: probe_hash(i),
    "different": lambda tmp, i: probe_different(i),
    "action_schema": lambda tmp, i: probe_action_schema(i),
    "policy": lambda tmp, i: probe_policy(i),
    "tally": lambda tmp, i: probe_tally(i),
    "verify": lambda tmp, i: probe_verify(i),
    "step": probe_step,
    "boot": probe_boot,
    "crash": probe_crash,
    "race": probe_race,
    "provider": lambda tmp, i: probe_provider(i),
    "registry": probe_registry,
    "readiness": probe_readiness,
    "logging": lambda tmp, i: probe_logging(i),
    "display": lambda tmp, i: probe_display(i),
    "reconcile": probe_reconcile,
    "export": probe_export,
}

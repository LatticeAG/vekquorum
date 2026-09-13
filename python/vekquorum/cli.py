"""``vq`` command-line interface — a thin binding over the SDK.

The CLI cannot bypass a guard: it opens the same SQLite coordinator the SDK
uses and passes an administrator caller derived from the local config's
``caller_principal``.  One JSON object plus LF goes to stdout on success;
diagnostics go to stderr.  Exit codes follow the spec's table.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from typing import Any, Optional

from . import __version__, schema
from .adapters import FileInbox, FixtureGate, RefundSimulator
from .api import canonicalize as api_canonicalize, hash_action, sign_vote
from .coordinator import Coordinator
from .ed25519 import (generate_keypair, load_pkcs8, private_seed,
                      public_key_of)
from .errors import VQError, exit_code_for
from .hashing import validate_hash
from .hosted import _unavailable
from .ids import PREFIXES, new_id
from .jsonparse import parse_json
from .registry import LocalRegistry
from .store import Store
from .verifier import verify_proof

ALL_CAPS = ["read", "propose", "submit", "commit", "escalate", "admin"]

PRIVACY_BANNER = "vq/1"


# ---------------------------------------------------------------------------
# helpers


def _fail(code: str, **kw) -> VQError:
    return VQError(code, **kw)


def _read_file_bytes(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as e:
        raise VQError("USAGE",
                      details={"file": path, "os": e.strerror}) from None


def _read_json_file(path: str) -> Any:
    return parse_json(_read_file_bytes(path), profile="wire")


def _check_private_key_file(path: str) -> bytes:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise VQError("USAGE", details={"file": path, "reason": "symlink"})
    if st.st_mode & 0o077:
        raise VQError("USAGE",
                      details={"file": path,
                               "reason": "group_or_world_readable"})
    return _read_file_bytes(path)


def _exclusive_out(path: str, mode: int = 0o600):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(path, flags, mode)
    except FileExistsError:
        raise VQError("USAGE",
                      details={"file": path, "reason": "exists"}) from None
    except OSError as e:
        raise VQError("USAGE",
                      details={"file": path, "os": e.strerror}) from None


class _Ctx:
    """Resolved local config + coordinator handle."""

    def __init__(self, config_path: str):
        self.config_path = os.path.abspath(config_path)
        self.dir = os.path.dirname(self.config_path)
        cfg = _read_json_file(self.config_path)
        try:
            self.config = schema.local_config(cfg)
        except VQError as e:
            raise VQError("CONFIG_INVALID", details=e.details) from None
        self._store: Optional[Store] = None
        self._coord: Optional[Coordinator] = None

    def _resolve(self, p: str) -> str:
        return p if os.path.isabs(p) else os.path.join(self.dir, p)

    @property
    def caller(self) -> dict:
        return {"tenant": self.config["tenant"],
                "principal_id": self.config["caller_principal"],
                "capabilities": list(ALL_CAPS)}

    def coordinator(self) -> Coordinator:
        if self._coord is None:
            cfg = self.config
            trust = _read_json_file(self._resolve(cfg["trust_file"]))
            trust = schema.trust(trust)
            if (trust["tenant"] != cfg["tenant"]
                    or trust["executor_id"] != cfg["executor_id"]
                    or trust["environment"] != cfg["environment"]):
                raise VQError("TRUST_MISMATCH",
                              details={"reason": "scope"})
            if not any(k["key_id"] == cfg["audit_key_id"]
                       for k in trust["audit_keys"]):
                raise VQError("TRUST_MISMATCH",
                              details={"reason": "audit_key_id"})
            der = _check_private_key_file(
                self._resolve(cfg["audit_key_file"]))
            seed = private_seed(der)
            if public_key_of(seed).hex() != next(
                    k["public_key"] for k in trust["audit_keys"]
                    if k["key_id"] == cfg["audit_key_id"]):
                raise VQError("TRUST_MISMATCH",
                              details={"reason": "audit_key_public"})
            db_path = self._resolve(cfg["database"])
            st = os.lstat(db_path) if os.path.exists(db_path) else None
            if st is not None and stat.S_ISLNK(st.st_mode):
                raise VQError("USAGE",
                              details={"file": db_path,
                                       "reason": "symlink"})
            self._store = Store(db_path, lambda: _wall_ms())
            if cfg["adapter"] == "refund-simulator/1":
                executors = {"covenant.refund": RefundSimulator()}
            else:
                raise VQError("ADAPTER_UNAVAILABLE",
                              details={"reason":
                                       "application-registered requires an "
                                       "in-process adapter; vq cannot run it"})
            if cfg["environment"] == "test":
                gate = FixtureGate("allow", "local-test-1")
            else:
                gate = None  # live requires a host-integrated scope gate
            inbox = None
            if cfg["inbox"]["mode"] == "file":
                inbox = FileInbox(self._resolve(cfg["inbox"]["directory"]))
            self._coord = Coordinator(
                self._store, tenant=cfg["tenant"],
                executor_id=cfg["executor_id"],
                environment=cfg["environment"],
                audit_key_id=cfg["audit_key_id"], audit_seed=seed,
                executors=executors, gate=gate, inbox=inbox)
            self._trust = trust
        return self._coord

    def meta(self, request_id: Optional[str]) -> dict:
        if request_id is None:
            raise VQError("USAGE",
                          details={"reason": "request_id_required"})
        schema.v_id("request")(request_id, "request_id")
        return {"caller": self.caller, "idempotency_key": request_id}

    def close(self) -> None:
        if self._store is not None:
            self._store.close()
            self._store = None


def _wall_ms() -> int:
    import time
    return int(time.time() * 1000)


# ---------------------------------------------------------------------------
# command implementations


def cmd_canonicalize(args) -> dict:
    raw = _read_file_bytes(args.file)
    return {"canonical_utf8": api_canonicalize(raw)}


def cmd_hash(args) -> dict:
    action = _read_json_file(args.action)
    return {"action_hash": hash_action(action)}


def cmd_keygen(args) -> dict:
    kind = args.kind
    if kind not in ("human", "agent"):
        raise VQError("USAGE", details={"field": "kind"})
    der, pub_raw = generate_keypair()
    fd = _exclusive_out(args.out, 0o600)
    try:
        os.write(fd, der)
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"key_id": new_id("key"), "public_key": pub_raw.hex(),
            "kind": kind}


def _coordinator_cmds(fn):
    def wrapper(ctx: _Ctx, args):
        return fn(ctx.coordinator(), ctx, args)
    return wrapper


def cmd_configure(ctx: _Ctx, args) -> dict:
    policy = _read_json_file(args.policy)
    denied = _read_json_file(args.deny_file) if args.deny_file else []
    revoked = (_read_json_file(args.revoke_file)
               if args.revoke_file else [])
    req = {"expected_epoch": args.expected_epoch, "policy": policy,
           "denied_tools": denied, "revoked_keys": revoked}
    return ctx.coordinator().configure(req, ctx.meta(args.request_id))


def cmd_propose(ctx: _Ctx, args) -> dict:
    req = {"action": _read_json_file(args.action),
           "policy": _read_json_file(args.policy),
           "enrichment": (_read_json_file(args.enrichment)
                          if args.enrichment else None)}
    return ctx.coordinator().propose(req, ctx.meta(args.request_id))


def cmd_sign(ctx: _Ctx, args) -> dict:
    action = _read_json_file(args.action)
    policy = _read_json_file(args.policy)
    enrichment = (_read_json_file(args.enrichment)
                  if args.enrichment else None)
    ah = hash_action(action)
    der = _check_private_key_file(args.key)
    seed = private_seed(der)
    pub_hex = public_key_of(seed).hex()
    pol = schema.policy(policy)
    member = next((m for m in pol["roster"]
                   if m["public_key"] == pub_hex), None)
    if member is None:
        raise VQError("KEY_NOT_ENROLLED",
                      details={"reason": "key_not_in_roster"})
    confirm = args.confirm_hash
    if confirm is None:
        if not sys.stdin.isatty():
            raise VQError("USAGE",
                          details={"reason": "confirm_hash_required_no_tty"})
        from .display import render_text, review_display
        disp = review_display(action=schema.action(action), policy=pol,
                              enrichment=enrichment)
        disp["action_hash"] = ah
        sys.stderr.write("Review exactly:\n" + render_text(disp) + "\n")
        sys.stderr.write(
            "Re-type the action_hash to confirm signing: ")
        confirm = sys.stdin.readline().strip()
    validate_hash(confirm, "confirm_hash")
    if confirm != ah:
        raise VQError("HASH_MISMATCH", details={"reason": "confirm_hash"})
    return sign_vote(action=action, policy=policy, enrichment=enrichment,
                     key_id=member["key_id"], decision=args.decision,
                     confirm_hash=confirm, private_key=seed)


def cmd_submit(ctx: _Ctx, args) -> dict:
    req = {"proposal_id": args.proposal,
           "expected_revision": args.revision,
           "vote": _read_json_file(args.vote)}
    return ctx.coordinator().submit(req, ctx.meta(args.request_id))


def cmd_commit(ctx: _Ctx, args) -> dict:
    req = {"proposal_id": args.proposal,
           "expected_revision": args.revision,
           "action_hash": args.hash}
    return ctx.coordinator().commit(req, ctx.meta(args.request_id),
                                    wait_ms=args.wait_ms)


def cmd_get(ctx: _Ctx, args) -> dict:
    return ctx.coordinator().get({"proposal_id": args.proposal},
                                 {"caller": ctx.caller,
                                  "idempotency_key":
                                      args.request_id or new_id("request")})


def cmd_cancel(ctx: _Ctx, args) -> dict:
    req = {"proposal_id": args.proposal,
           "expected_revision": args.revision}
    return ctx.coordinator().cancel(req, ctx.meta(args.request_id))


def cmd_escalate(ctx: _Ctx, args) -> dict:
    req = {"proposal_id": args.proposal,
           "expected_revision": args.revision, "reason": args.reason}
    return ctx.coordinator().escalate(req, ctx.meta(args.request_id))


def cmd_deliver(ctx: _Ctx, args) -> dict:
    return ctx.coordinator().deliver({"escalation_id": args.escalation},
                                     ctx.meta(args.request_id))


def cmd_reconcile(ctx: _Ctx, args) -> dict:
    return ctx.coordinator().reconcile({"proposal_id": args.proposal},
                                       ctx.meta(args.request_id))


def cmd_export(ctx: _Ctx, args) -> dict:
    out = ctx.coordinator().export_proof({"proposal_id": args.proposal},
                                         ctx.meta(args.request_id))
    path = args.out
    fd = _exclusive_out(path, 0o644)
    try:
        from .canon import J
        os.write(fd, J(out["proof"]))
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"bundle_hash": out["bundle_hash"], "path": path}


def cmd_verify(ctx: _Ctx, args) -> dict:
    if args.hosted:
        raise _unavailable("verifier")
    proof = _read_json_file(args.file)
    trust = schema.trust(_read_json_file(args.trust))
    return verify_proof(proof, trust)


def cmd_registry(ctx: _Ctx, args) -> dict:
    cfg = ctx.config
    if cfg["hosted"] is not None:
        # The hosted registry is an invite-only deployment surface, not
        # implemented in the OSS core.
        raise _unavailable("registry." + args.registry_cmd.replace("-", "_"))
    # Local registry semantics: same logical rules in the operator's store.
    reg_path = ctx._resolve("./state/vq-registry.sqlite")
    trust = schema.trust(_read_json_file(ctx._resolve(cfg["trust_file"])))
    reg = LocalRegistry(reg_path, trust=trust, clock_ms=_wall_ms)
    try:
        sub = args.registry_cmd
        if sub == "put-policy":
            pol = _read_json_file(args.file)
            return reg.put_policy(pol, tenant=cfg["tenant"],
                                  principal=cfg["caller_principal"],
                                  key=args.request_id)
        if sub == "get-policy":
            return reg.get_policy(args.hash, tenant=cfg["tenant"])
        if sub == "put-proof":
            proof = _read_json_file(args.file)
            return reg.put_proof(proof, tenant=cfg["tenant"],
                                 principal=cfg["caller_principal"],
                                 key=args.request_id)
        if sub == "get-proof":
            out = reg.get_proof(args.hash, tenant=cfg["tenant"])
            fd = _exclusive_out(args.out, 0o644)
            try:
                from .canon import J
                os.write(fd, J(out["proof"]))
                os.fsync(fd)
            finally:
                os.close(fd)
            return {"bundle_hash": out["bundle_hash"], "path": args.out}
        if sub == "head":
            return reg.head(args.proposal, tenant=cfg["tenant"])
    finally:
        reg.close()
    raise VQError("USAGE", details={"reason": "registry_cmd"})


def cmd_health(ctx: _Ctx, args) -> dict:
    if ctx.config["hosted"] is not None:
        raise _unavailable("healthz")
    # Local readiness signal: coordinator opens cleanly.
    ctx.coordinator()
    return {"status": "ready", "protocol": "vq/1"}


# ---------------------------------------------------------------------------
# argument parsing / dispatch


def _p() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="vq", description=(
        "VekQuorum vq/1 — M-of-N approval over exact action bytes with "
        "consume-once commit evidence"))
    ap.add_argument("--config", default="./vq.config.json")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--timeout-ms", type=int, default=5000)
    ap.add_argument("--version", action="version",
                    version="vq %s (%s)" % (__version__, PRIVACY_BANNER))
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("canonicalize"); s.add_argument("--file", required=True)
    s = sub.add_parser("hash"); s.add_argument("--action", required=True)
    s = sub.add_parser("keygen"); s.add_argument("--out", required=True)
    s.add_argument("--kind", default="human")
    s = sub.add_parser("configure")
    s.add_argument("--policy", required=True)
    s.add_argument("--expected-epoch", type=int, required=True)
    s.add_argument("--deny-file"); s.add_argument("--revoke-file")
    s.add_argument("--request-id", required=True)
    s = sub.add_parser("propose")
    s.add_argument("--action", required=True)
    s.add_argument("--policy", required=True)
    s.add_argument("--enrichment")
    s.add_argument("--request-id", required=True)
    s = sub.add_parser("sign")
    s.add_argument("--action", required=True)
    s.add_argument("--policy", required=True)
    s.add_argument("--key", required=True)
    s.add_argument("--decision", required=True,
                   choices=("approve", "reject"))
    s.add_argument("--enrichment")
    s.add_argument("--confirm-hash")
    s = sub.add_parser("submit")
    s.add_argument("--proposal", required=True)
    s.add_argument("--revision", type=int, required=True)
    s.add_argument("--vote", required=True)
    s.add_argument("--request-id", required=True)
    s = sub.add_parser("commit")
    s.add_argument("--proposal", required=True)
    s.add_argument("--revision", type=int, required=True)
    s.add_argument("--hash", required=True)
    s.add_argument("--wait-ms", type=int, default=5000)
    s.add_argument("--request-id", required=True)
    s = sub.add_parser("get")
    s.add_argument("--proposal", required=True)
    s.add_argument("--request-id")
    s = sub.add_parser("cancel")
    s.add_argument("--proposal", required=True)
    s.add_argument("--revision", type=int, required=True)
    s.add_argument("--request-id", required=True)
    s = sub.add_parser("escalate")
    s.add_argument("--proposal", required=True)
    s.add_argument("--revision", type=int, required=True)
    s.add_argument("--reason", required=True,
                   choices=("manual", "missing_quorum"))
    s.add_argument("--request-id", required=True)
    s = sub.add_parser("deliver")
    s.add_argument("--escalation", required=True)
    s.add_argument("--request-id", required=True)
    s = sub.add_parser("reconcile")
    s.add_argument("--proposal", required=True)
    s.add_argument("--request-id", required=True)
    s = sub.add_parser("export")
    s.add_argument("--proposal", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--request-id", required=True)
    s = sub.add_parser("verify")
    s.add_argument("--file", required=True)
    s.add_argument("--trust", required=True)
    s.add_argument("--hosted", action="store_true")
    reg = sub.add_parser("registry")
    rsub = reg.add_subparsers(dest="registry_cmd", required=True)
    s = rsub.add_parser("put-policy"); s.add_argument("--file", required=True)
    s.add_argument("--request-id", required=True)
    s = rsub.add_parser("get-policy"); s.add_argument("--hash", required=True)
    s = rsub.add_parser("put-proof"); s.add_argument("--file", required=True)
    s.add_argument("--request-id", required=True)
    s = rsub.add_parser("get-proof"); s.add_argument("--hash", required=True)
    s.add_argument("--out", required=True)
    s = rsub.add_parser("head"); s.add_argument("--proposal", required=True)
    sub.add_parser("health")
    return ap


_CMD_NEEDS_CTX = {"configure", "propose", "sign", "submit", "commit", "get",
                  "cancel", "escalate", "deliver", "reconcile", "export",
                  "registry", "health"}

_DISPATCH = {
    "canonicalize": lambda ctx, a: cmd_canonicalize(a),
    "hash": lambda ctx, a: cmd_hash(a),
    "keygen": lambda ctx, a: cmd_keygen(a),
    "configure": cmd_configure, "propose": cmd_propose, "sign": cmd_sign,
    "submit": cmd_submit, "commit": cmd_commit, "get": cmd_get,
    "cancel": cmd_cancel, "escalate": cmd_escalate, "deliver": cmd_deliver,
    "reconcile": cmd_reconcile, "export": cmd_export, "verify": cmd_verify,
    "registry": cmd_registry, "health": cmd_health,
}

# View-state -> exit code for commit/reconcile.
_VIEW_EXIT = {"SUCCEEDED": 0, "FAILED": 9, "UNKNOWN": 8, "DISPATCHING": 8}


def _view_exit(result: dict) -> int:
    if isinstance(result, dict) and "state" in result and \
            "proposal_id" in result:
        return _VIEW_EXIT.get(result["state"], 4 if result["state"] in
                              ("OPEN", "READY", "EXPIRED", "STALE",
                               "CANCELED", "ESCALATED") else 0)
    return 0


def main(argv: Optional[list] = None) -> int:
    args = _p().parse_args(argv)
    if not 100 <= args.timeout_ms <= 30000:
        sys.stderr.write("error: --timeout-ms must be 100..30000\n")
        return 2
    ctx: Optional[_Ctx] = None
    try:
        ctx = _Ctx(args.config) if args.cmd in _CMD_NEEDS_CTX else None
        result = _DISPATCH[args.cmd](ctx, args)
        if args.cmd == "canonicalize" and not args.json:
            sys.stdout.write(result["canonical_utf8"] + "\n")
        else:
            sys.stdout.write(json.dumps(result, separators=(",", ":"),
                                        ensure_ascii=False) + "\n")
        if args.cmd in ("commit", "reconcile"):
            return _view_exit(result)
        if args.cmd == "verify":
            ok = (result["integrity"] == "valid"
                  and result["authorization"] == "satisfied")
            if not ok:
                return 4 if result["integrity"] == "valid" else 3
        return 0
    except VQError as e:
        body = e.to_failure()
        if e.request_id is None:
            body["error"]["request_id"] = getattr(args, "request_id", None)
        sys.stderr.write(json.dumps(body, separators=(",", ":")) + "\n")
        return exit_code_for(e.code)
    except BrokenPipeError:
        return 0
    except Exception as e:  # unexpected runtime fault: exit 1
        sys.stderr.write(json.dumps(
            {"error": {"code": "INTERNAL", "retryable": False,
                       "request_id": getattr(args, "request_id", None),
                       "details": {"type": type(e).__name__}}},
            separators=(",", ":")) + "\n")
        return 1
    finally:
        if ctx is not None:
            ctx.close()


if __name__ == "__main__":
    raise SystemExit(main())

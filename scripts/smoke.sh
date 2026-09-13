#!/usr/bin/env bash
# VekQuorum CLI happy-path smoke: keygen -> configure -> propose -> sign x2
# -> submit x2 -> commit -> export -> verify.  Every artifact is produced by
# the real CLI; JSON outputs are captured under $SMOKE_DIR (default mktemp).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="$ROOT/python"
VQ=(python3 -m vekquorum.cli)
D="${SMOKE_DIR:-$(mktemp -d)}"
mkdir -p "$D"
cd "$D"
echo "smoke dir: $D" >&2

# --- 1. keypairs (3 roster + 1 audit) ---------------------------------------
"${VQ[@]}" --json keygen --out k1.pk8 --kind human > k1.json
"${VQ[@]}" --json keygen --out k2.pk8 --kind human > k2.json
"${VQ[@]}" --json keygen --out k3.pk8 --kind agent > k3.json
"${VQ[@]}" --json keygen --out audit.pk8 --kind human > audit.json
[ "$(stat -c %a k1.pk8)" = "600" ]

# --- 2. build policy/action/trust/config from generated keys ----------------
ROOT_OVERRIDE="$ROOT" python3 - "$D" <<'PY'
import json, sys, time, os
sys.path.insert(0, os.environ["ROOT_OVERRIDE"] + "/python")
from vekquorum.ids import new_id, ident
from vekquorum.hashing import H
from vekquorum.canon import J

D = sys.argv[1]
k = [json.load(open(f"{D}/k{i}.json")) for i in (1, 2, 3)]
audit = json.load(open(f"{D}/audit.json"))
TEN, EXE, PID, OP, PROP = (new_id("tenant"), new_id("executor"),
                           new_id("proposal"), new_id("operation"),
                           new_id("principal"))
U = {1: new_id("principal"), 2: new_id("principal"), 3: new_id("principal")}
now = int(time.time() * 1000)
policy = {"v": 1, "tenant": TEN, "policy_id": new_id("policy"), "version": 1,
          "executor_id": EXE, "environment": "test", "tool": "covenant.refund",
          "threshold": 2,
          "roster": sorted(
              [{"key_id": k[i]["key_id"], "principal_id": U[i + 1],
                "kind": k[i]["kind"], "public_key": k[i]["public_key"]}
               for i in range(3)], key=lambda m: m["key_id"]),
          "require_human": True, "max_ttl_ms": 300000,
          "enrichment_required": False}
ph = H("policy", policy)
action = {"v": 1, "tenant": TEN, "proposal_id": PID, "operation_id": OP,
          "executor_id": EXE, "proposer_id": PROP, "environment": "test",
          "tool": "covenant.refund",
          "args": {"payment_id": "pay_demo", "amount_minor": 100,
                   "currency": "USD"},
          "policy_hash": ph, "authority_epoch": 1, "created_ms": now,
          "expires_ms": now + 60000, "nonce": new_id("nonce"),
          "preconditions": [{"resource": "payment:pay_demo",
                             "version": "7"}],
          "enrichment_hash": None,
          "oversight": {"goal": "Refund duplicate charge",
                        "human_initiator": U[1], "trace_id": new_id("trace"),
                        "parent_receipt_hash": None},
          "external_refs": []}
trust = {"v": 1, "tenant": TEN, "executor_id": EXE, "environment": "test",
         "policy_hashes": [ph],
         "audit_keys": [{"key_id": audit["key_id"],
                         "public_key": audit["public_key"],
                         "first_seq": 1, "last_seq": None}]}
config = {"v": 1, "tenant": TEN, "executor_id": EXE, "environment": "test",
          "database": "./state/vq.sqlite", "trust_file": "./trust.json",
          "audit_key_file": "./audit.pk8", "audit_key_id": audit["key_id"],
          "caller_principal": PROP, "adapter": "refund-simulator/1",
          "inbox": {"mode": "file", "directory": "./inbox"},
          "hosted": None, "payload_retention_days": 30,
          "metadata_retention_days": 365}
for name, obj in [("policy.json", policy), ("action.json", action),
                  ("trust.json", trust), ("vq.config.json", config)]:
    with open(f"{D}/{name}", "wb") as f:
        f.write(J(obj))
print(json.dumps({"tenant": TEN, "proposal_id": PID}))
PY
mkdir -p state inbox

# --- 3. ceremony -------------------------------------------------------------
rid() { PYTHONPATH="$ROOT/python" python3 -c \
    'from vekquorum.ids import new_id; print(new_id("request"))'; }

"${VQ[@]}" --json --config vq.config.json configure \
    --policy policy.json --expected-epoch 0 --request-id "$(rid)" \
    > out-configure.json
AH=$("${VQ[@]}" --json hash --action action.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["action_hash"])')
"${VQ[@]}" --json --config vq.config.json propose \
    --action action.json --policy policy.json \
    --request-id "$(rid)" \
    > out-propose.json
PID=$(python3 -c 'import json; print(json.load(open("out-propose.json"))["proposal_id"])')

"${VQ[@]}" --json --config vq.config.json sign \
    --action action.json --policy policy.json --key k1.pk8 \
    --decision approve --confirm-hash "$AH" > vote1.json
"${VQ[@]}" --json --config vq.config.json sign \
    --action action.json --policy policy.json --key k2.pk8 \
    --decision approve --confirm-hash "$AH" > vote2.json

"${VQ[@]}" --json --config vq.config.json submit --proposal "$PID" \
    --revision 1 --vote vote1.json \
    --request-id "$(rid)" \
    > out-submit1.json
"${VQ[@]}" --json --config vq.config.json submit --proposal "$PID" \
    --revision 2 --vote vote2.json \
    --request-id "$(rid)" \
    > out-submit2.json
REV=$(python3 -c 'import json; print(json.load(open("out-submit2.json"))["revision"])')
"${VQ[@]}" --json --config vq.config.json commit --proposal "$PID" \
    --revision "$REV" --hash "$AH" \
    --request-id "$(rid)" \
    > out-commit.json
"${VQ[@]}" --json --config vq.config.json export --proposal "$PID" \
    --out proof.json \
    --request-id "$(rid)" \
    > out-export.json
"${VQ[@]}" --json verify --file proof.json --trust trust.json \
    > out-verify.json
"${VQ[@]}" --json --config vq.config.json get --proposal "$PID" \
    > out-get.json

echo "== smoke results ==" >&2
for f in out-configure.json out-propose.json out-submit1.json \
         out-submit2.json out-commit.json out-export.json \
         out-verify.json out-get.json; do
  echo "--- $f"; cat "$f"
done

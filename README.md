# VekQuorum

[![CI](https://github.com/LatticeAG/vekquorum/actions/workflows/ci.yml/badge.svg)](https://github.com/LatticeAG/vekquorum/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-22%2B-blue.svg)](package.json)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](python/pyproject.toml)
[![Protocol](https://img.shields.io/badge/protocol-vq%2F1-blue.svg)](#protocol)
[![Conformance: TV-V--01..60](https://img.shields.io/badge/conformance-TV--V--01..60-green)](tests/conformance/)

Exact-action M-of-N Ed25519 approvals over RFC 8785-bound action bytes, with
consume-once commit evidence and offline-verifiable proof bundles — protocol
`vq/1`, proof profile `vq.visreceipt/1`.

VekQuorum gives an operator a local, durable approval ceremony: an action is
bound to an exact policy and authority epoch by hash, M of N enrolled signers
approve the *same bytes* or nothing, a single compare-and-consume tombstone
guarantees each operation dispatches at most once, and every transition is a
signed, hash-chained audit event. The exported proof verifies offline against
a caller-pinned trust document — no service call, no freshness claim.

- **MIT core** — strict JSON/RFC 8785 canonicalization, domain-separated
  hashing, strict Ed25519, closed wire schemas, the SQLite coordinator
  (propose → votes → commit → result), crash recovery into `UNKNOWN`,
  read-only reconciliation, the `covenant.refund` reference simulator,
  file-mode escalation inbox, hash-chained signed evidence, proof export,
  the offline verifier, the local registry, and the `vq` CLI. TypeScript
  ships the portable crypto core; Python ships the full stack.
- **Hosted surface** — the managed verifier and registry are invite-only
  deployment surfaces. The OSS repo ships the *contract* as stub interfaces
  that raise `HOSTED_UNAVAILABLE` with a pointer; they are not implemented
  here and are not a new trust root.

> A VekQuorum proof means exactly this: **"these keys approved these exact
> bytes under this authority epoch, and the issuer's log attests this
> outcome."** It does not prove the effect happened in the world, does not
> establish current freshness, and does not prove global uniqueness of the
> operation outside the issuing coordinator.

## Install

```bash
pip install -e python/        # Python SDK + `vq` CLI
npm install                   # TypeScript core (canonicalize/hash/Ed25519)
```

TypeScript requires Node.js >= 22.5. Python requires `cryptography >= 41`.

## Quick start

```bash
vq keygen --out signer.pk8 --kind human --json
vq --config vq.config.json configure --policy policy.json --expected-epoch 0 \
    --request-id vqi_<id> --json
vq --config vq.config.json propose --action action.json --policy policy.json \
    --request-id vqi_<id> --json
vq hash --action action.json --json          # -> action_hash
vq --config vq.config.json sign --action action.json --policy policy.json \
    --key signer.pk8 --decision approve --confirm-hash <action_hash>
vq --config vq.config.json submit --proposal <id> --revision <n> \
    --vote vote.json --request-id vqi_<id> --json
vq --config vq.config.json commit --proposal <id> --revision <n> \
    --hash <action_hash> --request-id vqi_<id> --json
vq --config vq.config.json export --proposal <id> --out proof.json \
    --request-id vqi_<id> --json
vq verify --file proof.json --trust trust.json --json
```

`scripts/smoke.sh` runs the whole ceremony live against the reference
`covenant.refund` simulator and the file inbox.

## Protocol

`vq/1` locks: RFC 8785/JCS canonical bytes; domain-separated
`SHA256("VekQuorum/" + kind + "/1\n" || J(value))` hashing with `vq1:` hex
presentation; ordinary deterministic Ed25519 with canonical signature
encodings (`S < L`, valid non-small-order `R`); the integer-only wire
profile; vq-prefixed opaque identifiers; and a fixed state machine
(`OPEN → READY → DISPATCHING → SUCCEEDED|FAILED|UNKNOWN`, plus `EXPIRED`,
`STALE`, `CANCELED`, `ESCALATED`).

Exit codes follow the spec table: `0` success, `2` usage/schema, `3`
crypto/trust, `4` quorum-not-met or unsatisfied intact proof, `5` conflicts
and consumption, `6` authn/tenant, `7` availability/clock/restore, `8`
unknown-or-dispatching outcome, `9` terminal failed execution, `1`
unexpected fault.

## Conformance

```bash
python -m pytest tests/conformance -q   # TV-V--01..60, the full vector suite
npm test                                # TS core: frozen KATs + differential
```

## Layout

- `python/vekquorum/` — reference implementation (crypto, coordinator,
  adapters, verifier, registry, CLI, hosted stubs)
- `src/` — TypeScript core (errors, strict parser, canon, hashing, ids,
  strict Ed25519)
- `tests/conformance/` — the spec's executable fixture + TV-V--01..60
- `tests/ts/conformance/` — TS known-answer + cross-language differential
- `scripts/smoke.sh` — live CLI happy path

## License

MIT — see [LICENSE](LICENSE).

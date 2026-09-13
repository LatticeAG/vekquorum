/**
 * Domain-separated hashing and signature-message construction.
 *
 * D(k,x) = SHA256(UTF8("VekQuorum/" + k + "/1\n") || J(x))
 * H(k,x) = "vq1:" + lowercase_hex(D(k,x))
 * S(k,x) = UTF8("VekQuorum/sign/" + k + "/1\n") || D(k,x)   (Ed25519 message)
 *
 * Allowed kinds: action, policy, authority, enrichment, vote, event,
 * checkpoint, bundle, output, request.
 */

import { createHash } from "node:crypto";

import { J } from "./canon.js";
import { VQError } from "./errors.js";
import type { JsonValue } from "./jsonparse.js";

export const KINDS = new Set([
  "action",
  "policy",
  "authority",
  "enrichment",
  "vote",
  "event",
  "checkpoint",
  "bundle",
  "output",
  "request",
]);

export const HASH_RE = /^vq1:[0-9a-f]{64}$/;
export const PUBKEY_RE = /^[0-9a-f]{64}$/;
export const SIG_RE = /^[0-9a-f]{128}$/;

export function D(kind: string, value: JsonValue): Uint8Array {
  if (!KINDS.has(kind)) {
    throw new VQError("SCHEMA_INVALID", {
      details: { reason: "unknown_hash_kind" },
    });
  }
  const h = createHash("sha256");
  h.update(`VekQuorum/${kind}/1\n`, "utf8");
  h.update(J(value));
  return new Uint8Array(h.digest());
}

export function H(kind: string, value: JsonValue): string {
  return "vq1:" + Buffer.from(D(kind, value)).toString("hex");
}

export function signingMessage(kind: string, value: JsonValue): Uint8Array {
  const prefix = new TextEncoder().encode(`VekQuorum/sign/${kind}/1\n`);
  const digest = D(kind, value);
  const out = new Uint8Array(prefix.length + digest.length);
  out.set(prefix, 0);
  out.set(digest, prefix.length);
  return out;
}

export function validateHash(value: unknown, field = "hash"): string {
  if (typeof value !== "string" || !HASH_RE.test(value)) {
    throw new VQError("SCHEMA_INVALID", { details: { field } });
  }
  return value;
}

export function validatePublicKey(value: unknown, field = "public_key"): string {
  if (typeof value !== "string" || !PUBKEY_RE.test(value)) {
    throw new VQError("INVALID_KEY", { details: { field } });
  }
  return value;
}

export function validateSignatureEncoding(
  value: unknown,
  field = "signature",
): string {
  if (typeof value !== "string" || !SIG_RE.test(value)) {
    throw new VQError("INVALID_SIGNATURE_ENCODING", { details: { field } });
  }
  return value;
}

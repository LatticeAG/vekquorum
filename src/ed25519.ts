/**
 * Strict Ed25519 for vq/1.
 *
 * Ordinary Ed25519 only (not Ed25519ph, not ZIP215-relaxed acceptance):
 *
 * - signature encodings must be canonical: 32-byte R that decodes to a valid
 *   curve point and a scalar S < L — length/alphabet failures and S >= L
 *   raise INVALID_SIGNATURE_ENCODING; invalid R points or a failed equation
 *   raise BAD_SIGNATURE;
 * - enrollment public keys must decode to a valid, non-small-order point —
 *   failures raise INVALID_KEY;
 * - signing uses ordinary deterministic Ed25519 (RFC 8032).
 *
 * Point decompression, subgroup rejection and scalar range are enforced here
 * before the equation itself is evaluated by Node's vetted OpenSSL backend.
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
  type KeyObject,
} from "node:crypto";

import { VQError } from "./errors.js";

const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const D_CONST = (-121665n * modPow(121666n, P - 2n, P)) % P;
const I_SQRT = modPow(2n, (P - 1n) / 4n, P); // sqrt(-1) mod p

const IDENTITY: readonly [bigint, bigint] = [0n, 1n];

function mod(x: bigint, m: bigint): bigint {
  const r = x % m;
  return r >= 0n ? r : r + m;
}

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

export function decodePoint(raw: Uint8Array): [bigint, bigint] | null {
  /** RFC 8032 point decompression.  Returns [x, y] or null. */
  if (raw.length !== 32) return null;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(raw[i]!);
  const sign = Number(raw[31]! >> 7);
  y &= (1n << 255n) - 1n;
  if (y >= P) return null;
  const xx = mod((y * y - 1n) * modPow(mod(D_CONST * y * y + 1n, P), P - 2n, P), P);
  let x = modPow(xx, (P + 3n) / 8n, P);
  if (mod(x * x - xx, P) !== 0n) x = mod(x * I_SQRT, P);
  if (mod(x * x - xx, P) !== 0n) return null;
  if (x === 0n && sign) return null;
  if (Number(x & 1n) !== sign) x = P - x;
  return [x, y];
}

function pointAdd(
  p1: readonly [bigint, bigint],
  p2: readonly [bigint, bigint],
): [bigint, bigint] {
  const [x1, y1] = p1;
  const [x2, y2] = p2;
  const t = mod(D_CONST * x1 * x2 * y1 * y2, P);
  const x3 = mod(
    (x1 * y2 + x2 * y1) * modPow(mod(1n + t, P), P - 2n, P),
    P,
  );
  const y3 = mod(
    (y1 * y2 + x1 * x2) * modPow(mod(1n - t, P), P - 2n, P),
    P,
  );
  return [x3, y3];
}

export function isSmallOrder(p: readonly [bigint, bigint]): boolean {
  /** True iff [8]P is the identity (P lies in the cofactor subgroup). */
  let q = pointAdd(p, p);
  q = pointAdd(q, q);
  q = pointAdd(q, q);
  return q[0] === IDENTITY[0] && q[1] === IDENTITY[1];
}

export function validateEnrollmentKey(publicKeyHex: string): Uint8Array {
  /** Validate a roster/trust public key.  Throws INVALID_KEY. */
  let raw: Uint8Array;
  try {
    raw = new Uint8Array(Buffer.from(publicKeyHex, "hex"));
  } catch {
    throw new VQError("INVALID_KEY", { details: { reason: "hex" } });
  }
  const pt = decodePoint(raw);
  if (pt === null || isSmallOrder(pt)) {
    throw new VQError("INVALID_KEY", { details: { reason: "point" } });
  }
  return raw;
}

const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function publicKeyObject(raw: Uint8Array): KeyObject {
  return createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, Buffer.from(raw)]),
    format: "der",
    type: "spki",
  });
}

function privateKeyObject(seed: Uint8Array): KeyObject {
  return createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]),
    format: "der",
    type: "pkcs8",
  });
}

export function verify(
  publicKey: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
): void {
  /**
   * Strict verification.  Throws INVALID_SIGNATURE_ENCODING or
   * BAD_SIGNATURE; callers validate the key itself separately.
   */
  if (signature.length !== 64) {
    throw new VQError("INVALID_SIGNATURE_ENCODING", {
      details: { reason: "length" },
    });
  }
  let sScalar = 0n;
  for (let i = 63; i >= 32; i--) {
    sScalar = (sScalar << 8n) | BigInt(signature[i]!);
  }
  if (sScalar >= L) {
    throw new VQError("INVALID_SIGNATURE_ENCODING", {
      details: { reason: "scalar_range" },
    });
  }
  const rPoint = decodePoint(signature.subarray(0, 32));
  if (rPoint === null || isSmallOrder(rPoint)) {
    throw new VQError("BAD_SIGNATURE", { details: { reason: "r_point" } });
  }
  try {
    const ok = nodeVerify(
      null,
      Buffer.from(message),
      publicKeyObject(publicKey),
      Buffer.from(signature),
    );
    if (!ok) throw new VQError("BAD_SIGNATURE");
  } catch (e) {
    if (e instanceof VQError) throw e;
    throw new VQError("BAD_SIGNATURE");
  }
}

export function sign(privateSeed: Uint8Array, message: Uint8Array): Uint8Array {
  /** Ordinary deterministic Ed25519 over the message bytes. */
  return new Uint8Array(
    nodeSign(null, Buffer.from(message), privateKeyObject(privateSeed)),
  );
}

export function publicKeyOf(privateSeed: Uint8Array): Uint8Array {
  const der = createPublicKey(privateKeyObject(privateSeed)).export({
    format: "der",
    type: "spki",
  });
  return new Uint8Array(der.subarray(der.length - 32));
}

export function generateKeypair(): [Uint8Array, Uint8Array] {
  /** Return [pkcs8_der_private, raw_public]. */
  const pair = generateKeyPairSync("ed25519");
  const pk8 = pair.privateKey.export({ format: "der", type: "pkcs8" });
  const spki = pair.publicKey.export({ format: "der", type: "spki" });
  return [
    new Uint8Array(pk8),
    new Uint8Array(spki.subarray(spki.length - 32)),
  ];
}

export function privateSeed(pkcs8Der: Uint8Array): Uint8Array {
  let key: KeyObject;
  try {
    key = createPrivateKey({
      key: Buffer.from(pkcs8Der),
      format: "der",
      type: "pkcs8",
    });
  } catch {
    throw new VQError("INVALID_KEY", { details: { reason: "der" } });
  }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new VQError("INVALID_KEY", { details: { reason: "not_ed25519" } });
  }
  const exported = key.export({ format: "der", type: "pkcs8" });
  return new Uint8Array(exported.subarray(exported.length - 32));
}

/**
 * VekQuorum vq/1 — TypeScript core.
 *
 * The portable protocol primitives: strict JSON parsing, RFC 8785
 * canonicalization, domain-separated hashing, identifier validation, and
 * strict Ed25519.  The durable coordinator, `covenant.refund` simulator,
 * proof exporter/verifier, local registry and the `vq` CLI ship in the
 * Python reference package (`python/vekquorum`).
 */

export { VQError, CATALOG, exitCodeFor, failure, httpStatus, isRetryable } from "./errors.js";
export type { Failure } from "./errors.js";
export {
  MAX_ARRAY,
  MAX_DEPTH,
  MAX_MEMBERS,
  parseJson,
  SAFE_INT_MAX,
  SAFE_INT_MIN,
} from "./jsonparse.js";
export type { JsonValue } from "./jsonparse.js";
export { canonicalize, canonicalText, J, serializeNumber } from "./canon.js";
export {
  D,
  H,
  HASH_RE,
  KINDS,
  PUBKEY_RE,
  SIG_RE,
  signingMessage,
  validateHash,
  validatePublicKey,
  validateSignatureEncoding,
} from "./hashing.js";
export {
  ALPHABET,
  looksLikeId,
  newId,
  PREFIXES,
  SUFFIX_LEN,
  SYSTEM_PRINCIPAL,
  validateId,
  validateSystemPrincipal,
} from "./ids.js";
export {
  decodePoint,
  generateKeypair,
  isSmallOrder,
  privateSeed,
  publicKeyOf,
  sign,
  validateEnrollmentKey,
  verify,
} from "./ed25519.js";

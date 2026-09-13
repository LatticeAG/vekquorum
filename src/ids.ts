/**
 * Locked vq/1 identifier prefixes and generation.
 *
 * IDs are opaque identifiers, not secrets or authorization credentials.
 * Every boundary validates prefix and the 21-character suffix alphabet.
 */

import { randomInt } from "node:crypto";

import { VQError } from "./errors.js";

export const ALPHABET =
  "_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
export const SUFFIX_LEN = 21;

export const PREFIXES: Record<string, string> = {
  tenant: "vqt_",
  executor: "vqx_",
  policy: "vqp_",
  proposal: "vqa_",
  operation: "vqo_",
  principal: "vqu_",
  key: "vqk_",
  nonce: "vqn_",
  event: "vqr_",
  stream: "vqs_",
  dispatch: "vqd_",
  escalation: "vqe_",
  trace: "vqc_",
  request: "vqi_",
};

/** Reserved coordinator-autonomous principal: never enrollable. */
export const SYSTEM_PRINCIPAL = "vqu_" + "0".repeat(SUFFIX_LEN);

export function newId(kind: string): string {
  const prefix = PREFIXES[kind];
  if (prefix === undefined) {
    throw new VQError("INVALID_ID", { details: { expected: kind } });
  }
  let suffix = "";
  for (let i = 0; i < SUFFIX_LEN; i++) {
    suffix += ALPHABET[randomInt(ALPHABET.length)];
  }
  return prefix + suffix;
}

export function validateId(value: unknown, kind: string): string {
  if (typeof value !== "string") {
    throw new VQError("INVALID_ID", { details: { expected: kind } });
  }
  const prefix = PREFIXES[kind];
  if (prefix === undefined || !value.startsWith(prefix)) {
    throw new VQError("INVALID_ID", {
      details: { expected: kind, got: value.slice(0, 8) },
    });
  }
  const suffix = value.slice(prefix.length);
  if (
    suffix.length !== SUFFIX_LEN ||
    [...suffix].some((c) => !ALPHABET.includes(c))
  ) {
    throw new VQError("INVALID_ID", { details: { expected: kind } });
  }
  if (kind === "principal" && value === SYSTEM_PRINCIPAL) {
    throw new VQError("INVALID_ID", {
      details: { reason: "reserved_principal" },
    });
  }
  return value;
}

export function validateSystemPrincipal(value: unknown): string {
  if (value === SYSTEM_PRINCIPAL) return SYSTEM_PRINCIPAL;
  return validateId(value, "principal");
}

export function looksLikeId(value: unknown, kind: string): boolean {
  try {
    validateId(value, kind);
    return true;
  } catch (e) {
    if (e instanceof VQError) return false;
    throw e;
  }
}

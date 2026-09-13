/**
 * VekQuorum vq/1 stable error codes and the Failure envelope.
 *
 * Codes are the machine-stable catalog from the protocol; Result.code values
 * emitted by executor adapters are adapter-namespaced and deliberately share
 * the string space without belonging to this catalog.
 */

export interface Failure {
  error: {
    code: string;
    retryable: boolean;
    request_id: string | null;
    details: Record<string, unknown>;
  };
}

export class VQError extends Error {
  readonly code: string;
  readonly retryable: boolean;
  readonly details: Record<string, unknown>;
  readonly requestId: string | null;

  constructor(
    code: string,
    opts: {
      retryable?: boolean;
      details?: Record<string, unknown>;
      requestId?: string | null;
    } = {},
  ) {
    super(code);
    this.name = "VQError";
    this.code = code;
    this.retryable = opts.retryable ?? false;
    this.details = opts.details ?? {};
    this.requestId = opts.requestId ?? null;
  }

  toFailure(): Failure {
    return {
      error: {
        code: this.code,
        retryable: this.retryable,
        request_id: this.requestId,
        details: this.details,
      },
    };
  }
}

export function failure(
  code: string,
  retryable = false,
  requestId: string | null = null,
  details: Record<string, unknown> = {},
): Failure {
  return { error: { code, retryable, request_id: requestId, details } };
}

/** Stable code -> [httpStatus, retryable]. */
export const CATALOG: Record<string, [number, boolean]> = {
  MALFORMED_JSON: [400, false],
  DUPLICATE_KEY: [400, false],
  INVALID_UTF8: [400, false],
  UNKNOWN_FIELD: [400, false],
  SCHEMA_INVALID: [400, false],
  INVALID_ID: [400, false],
  NUMBER_PROFILE: [400, false],
  INVALID_KEY: [400, false],
  INVALID_SIGNATURE_ENCODING: [400, false],
  UNAUTHENTICATED: [401, false],
  FORBIDDEN: [403, false],
  TENANT_MISMATCH: [403, false],
  UNTRUSTED: [403, false],
  NOT_FOUND: [404, false],
  METHOD_NOT_ALLOWED: [405, false],
  REVISION_CONFLICT: [409, true],
  EPOCH_CONFLICT: [409, true],
  IDEMPOTENCY_CONFLICT: [409, false],
  POLICY_VERSION_CONFLICT: [409, false],
  VOTE_CONFLICT: [409, false],
  STATE_CONFLICT: [409, false],
  OPERATION_CONSUMED: [409, false],
  NONCE_REUSED: [409, false],
  ACTIVE_OPERATION: [409, false],
  EQUIVOCATION: [409, false],
  EXPIRED: [410, false],
  PROOF_PRUNED: [410, false],
  BODY_TOO_LARGE: [413, false],
  PROOF_TOO_LARGE: [413, false],
  UNSUPPORTED_MEDIA_TYPE: [415, false],
  HASH_MISMATCH: [422, false],
  BAD_SIGNATURE: [422, false],
  POLICY_INVALID: [422, false],
  UNKNOWN_TOOL: [422, false],
  KEY_NOT_ENROLLED: [422, false],
  KEY_REVOKED: [422, false],
  ACTION_MUTATED: [422, false],
  QUORUM_NOT_MET: [422, false],
  PRECONDITION_CHANGED: [422, false],
  TRUST_MISMATCH: [422, false],
  DELIVERY_LIMIT: [422, false],
  VERSION_UNSUPPORTED: [426, false],
  RATE_LIMITED: [429, true],
  STORAGE_UNAVAILABLE: [503, true],
  GATE_UNAVAILABLE: [503, true],
  COORDINATOR_BUSY: [503, true],
  CLOCK_UNSAFE: [503, true],
  ADAPTER_UNAVAILABLE: [503, true],
  RESTORE_UNSAFE: [503, false],
  HOSTED_UNAVAILABLE: [501, false],
};

export function httpStatus(code: string): number {
  return (CATALOG[code] ?? [500, false])[0];
}

export function isRetryable(code: string): boolean {
  return (CATALOG[code] ?? [500, false])[1];
}

/** Failure code -> CLI exit status (spec exit table). */
export function exitCodeFor(code: string): number {
  if (
    [
      "MALFORMED_JSON",
      "DUPLICATE_KEY",
      "INVALID_UTF8",
      "UNKNOWN_FIELD",
      "SCHEMA_INVALID",
      "INVALID_ID",
      "NUMBER_PROFILE",
      "USAGE",
      "CONFIG_INVALID",
    ].includes(code)
  ) {
    return 2;
  }
  if (
    [
      "HASH_MISMATCH",
      "BAD_SIGNATURE",
      "INVALID_SIGNATURE_ENCODING",
      "INVALID_KEY",
      "UNTRUSTED",
      "PROOF_PRUNED",
    ].includes(code)
  ) {
    return 3;
  }
  if (code === "QUORUM_NOT_MET") return 4;
  if (
    code.endsWith("_CONFLICT") ||
    [
      "OPERATION_CONSUMED",
      "NONCE_REUSED",
      "ACTIVE_OPERATION",
      "EQUIVOCATION",
      "POLICY_VERSION_CONFLICT",
    ].includes(code)
  ) {
    return 5;
  }
  if (["UNAUTHENTICATED", "FORBIDDEN", "TENANT_MISMATCH"].includes(code)) {
    return 6;
  }
  if (
    code === "RATE_LIMITED" ||
    code.endsWith("_UNAVAILABLE") ||
    ["COORDINATOR_BUSY", "CLOCK_UNSAFE", "RESTORE_UNSAFE", "NOT_IMPLEMENTED"].includes(code)
  ) {
    return 7;
  }
  if (code === "EFFECT_UNKNOWN") return 8;
  if (code === "EXECUTION_FAILED") return 9;
  return 1;
}

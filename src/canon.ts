/**
 * RFC 8785 (JCS) canonicalization for vq/1.
 *
 * J(x) is the canonical UTF-8 byte encoding of an already-validated inert
 * JSON value.  Object members are ordered by UTF-16 code units — which is
 * exactly JavaScript's native string order, so a plain sort suffices.
 * Numbers serialize with ECMAScript Number::toString shortest-round-trip
 * rules (String(n)); -0 serializes as "0".
 *
 * canonicalize(raw) accepts the RFC 8785/I-JSON numeric domain and returns
 * canonical text after strict parsing (duplicate members, invalid UTF-8 and
 * unpaired surrogates are rejected).  It is not a vq/1 schema validator.
 */

import { VQError } from "./errors.js";
import { parseJson, type JsonValue } from "./jsonparse.js";

const ESCAPES: Record<string, string> = {
  '"': '\\"',
  "\\": "\\\\",
  "\b": "\\b",
  "\f": "\\f",
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
};

function escapeString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const esc = ESCAPES[ch];
    if (esc !== undefined) {
      out += esc;
    } else if (ch < " ") {
      out += "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0");
    } else {
      out += ch;
    }
  }
  return out + '"';
}

export function serializeNumber(v: number): string {
  if (typeof v === "boolean") {
    throw new VQError("SCHEMA_INVALID", {
      details: { reason: "bool_not_number" },
    });
  }
  if (!Number.isFinite(v)) {
    throw new VQError("NUMBER_PROFILE", { details: { reason: "non_finite" } });
  }
  // String(v) is ECMAScript Number::toString — the RFC 8785 number format —
  // and already renders -0 and +0 as "0".
  return String(v);
}

export function canonicalText(value: JsonValue): string {
  return ser(value);
}

export function J(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(ser(value));
}

function ser(value: JsonValue): string {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") return serializeNumber(value);
  if (typeof value === "string") return escapeString(value);
  if (Array.isArray(value)) {
    return "[" + value.map(ser).join(",") + "]";
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return (
      "{" +
      keys.map((k) => escapeString(k) + ":" + ser(value[k]!)).join(",") +
      "}"
    );
  }
  throw new VQError("SCHEMA_INVALID", {
    details: { reason: "unsupported_type" },
  });
}

export function canonicalize(raw: Uint8Array | string): string {
  const value = parseJson(raw, "rfc8785");
  return ser(value);
}

/**
 * Strict JSON parser for vq/1 wire bodies and the standalone canonicalizer.
 *
 * Two numeric domains are supported:
 *
 * - profile "wire" — the vq/1 integer-only profile: number tokens must be
 *   base-10 integers in [-2**53+1, 2**53-1] with no fraction, no exponent and
 *   no negative zero.  Violations raise NUMBER_PROFILE.
 * - profile "rfc8785" — the I-JSON/RFC 8785 numeric domain used by
 *   canonicalize: number tokens are IEEE-754 doubles.
 *
 * Structural limits: max depth 32, max 1024 object members, max 1024 array
 * elements.  Duplicate object members are rejected (DUPLICATE_KEY) before any
 * later stage can collapse them.  Invalid UTF-8 and unpaired surrogates —
 * including those introduced through \u escapes — raise INVALID_UTF8.
 */

import { VQError } from "./errors.js";

export const MAX_DEPTH = 32;
export const MAX_MEMBERS = 1024;
export const MAX_ARRAY = 1024;
export const SAFE_INT_MAX = 9007199254740991;
export const SAFE_INT_MIN = -9007199254740991;

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

const WS = new Set([" ", "\t", "\n", "\r"]);
const HEX = "0123456789abcdefABCDEF";

function checkStr(s: string): string {
  for (let i = 0; i < s.length; i++) {
    const o = s.charCodeAt(i);
    if (o >= 0xd800 && o <= 0xdbff) {
      const lo = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (lo < 0xdc00 || lo > 0xdfff) {
        throw new VQError("INVALID_UTF8", {
          details: { reason: "unpaired_surrogate" },
        });
      }
      i++; // consume the low surrogate
      continue;
    }
    if (o >= 0xdc00 && o <= 0xdfff) {
      throw new VQError("INVALID_UTF8", {
        details: { reason: "unpaired_surrogate" },
      });
    }
  }
  return s;
}

class Parser {
  private i = 0;
  private readonly n: number;

  constructor(
    private readonly s: string,
    private readonly profile: "wire" | "rfc8785",
  ) {
    this.n = s.length;
  }

  private error(code = "MALFORMED_JSON"): VQError {
    return new VQError(code, { details: { offset: this.i } });
  }

  private skipWs(): void {
    while (this.i < this.n && WS.has(this.s[this.i]!)) this.i++;
  }

  parse(): JsonValue {
    this.skipWs();
    const value = this.value(0);
    this.skipWs();
    if (this.i !== this.n) throw this.error();
    return value;
  }

  private value(depth: number): JsonValue {
    if (this.i >= this.n) throw this.error();
    if (depth > MAX_DEPTH) {
      throw new VQError("SCHEMA_INVALID", {
        details: { reason: "max_depth" },
      });
    }
    const ch = this.s[this.i]!;
    if (ch === "{") return this.object(depth);
    if (ch === "[") return this.array(depth);
    if (ch === '"') return this.string();
    if (ch === "t") return this.literal("true", true);
    if (ch === "f") return this.literal("false", false);
    if (ch === "n") return this.literal("null", null);
    return this.number();
  }

  private literal(word: string, value: JsonValue): JsonValue {
    if (this.s.startsWith(word, this.i)) {
      this.i += word.length;
      return value;
    }
    throw this.error();
  }

  private object(depth: number): JsonValue {
    this.i++;
    const out: { [key: string]: JsonValue } = {};
    this.skipWs();
    if (this.i < this.n && this.s[this.i] === "}") {
      this.i++;
      return out;
    }
    for (;;) {
      this.skipWs();
      if (this.i >= this.n || this.s[this.i] !== '"') throw this.error();
      const key = this.string() as string;
      this.skipWs();
      if (this.i >= this.n || this.s[this.i] !== ":") throw this.error();
      this.i++;
      this.skipWs();
      const val = this.value(depth + 1);
      if (Object.prototype.hasOwnProperty.call(out, key)) {
        throw new VQError("DUPLICATE_KEY", { details: { key } });
      }
      out[key] = val;
      if (Object.keys(out).length > MAX_MEMBERS) {
        throw new VQError("SCHEMA_INVALID", {
          details: { reason: "max_members" },
        });
      }
      this.skipWs();
      if (this.i >= this.n) throw this.error();
      const ch = this.s[this.i]!;
      if (ch === "}") {
        this.i++;
        return out;
      }
      if (ch !== ",") throw this.error();
      this.i++;
    }
  }

  private array(depth: number): JsonValue {
    this.i++;
    const out: JsonValue[] = [];
    this.skipWs();
    if (this.i < this.n && this.s[this.i] === "]") {
      this.i++;
      return out;
    }
    for (;;) {
      this.skipWs();
      out.push(this.value(depth + 1));
      if (out.length > MAX_ARRAY) {
        throw new VQError("SCHEMA_INVALID", {
          details: { reason: "max_array" },
        });
      }
      this.skipWs();
      if (this.i >= this.n) throw this.error();
      const ch = this.s[this.i]!;
      if (ch === "]") {
        this.i++;
        return out;
      }
      if (ch !== ",") throw this.error();
      this.i++;
    }
  }

  private string(): string {
    this.i++;
    let buf = "";
    for (;;) {
      if (this.i >= this.n) throw this.error();
      const ch = this.s[this.i]!;
      const o = ch.charCodeAt(0);
      if (ch === '"') {
        this.i++;
        return checkStr(buf);
      }
      if (ch === "\\") {
        this.i++;
        if (this.i >= this.n) throw this.error();
        const esc = this.s[this.i]!;
        this.i++;
        if (esc === '"') buf += '"';
        else if (esc === "\\") buf += "\\";
        else if (esc === "/") buf += "/";
        else if (esc === "b") buf += "\b";
        else if (esc === "f") buf += "\f";
        else if (esc === "n") buf += "\n";
        else if (esc === "r") buf += "\r";
        else if (esc === "t") buf += "\t";
        else if (esc === "u") buf += this.hex4();
        else throw this.error();
        continue;
      }
      if (o < 0x20) throw this.error();
      if (o >= 0xd800 && o <= 0xdbff) {
        // Raw surrogate pair (valid astral character in a JS string).
        const lo = this.i + 1 < this.n ? this.s.charCodeAt(this.i + 1) : 0;
        if (lo < 0xdc00 || lo > 0xdfff) {
          throw new VQError("INVALID_UTF8", {
            details: { reason: "unpaired_surrogate" },
          });
        }
        buf += ch + this.s[this.i + 1]!;
        this.i += 2;
        continue;
      }
      if (o >= 0xdc00 && o <= 0xdfff) {
        throw new VQError("INVALID_UTF8", {
          details: { reason: "unpaired_surrogate" },
        });
      }
      buf += ch;
      this.i++;
    }
  }

  private hex4(): string {
    if (this.i + 4 > this.n) throw this.error();
    const digits = this.s.slice(this.i, this.i + 4);
    if ([...digits].some((c) => !HEX.includes(c))) throw this.error();
    this.i += 4;
    const cp = parseInt(digits, 16);
    if (cp >= 0xd800 && cp <= 0xdbff) {
      if (this.s.startsWith("\\u", this.i)) {
        this.i += 2;
        if (this.i + 4 > this.n) throw this.error();
        const lo = this.s.slice(this.i, this.i + 4);
        if ([...lo].some((c) => !HEX.includes(c))) throw this.error();
        this.i += 4;
        const lcp = parseInt(lo, 16);
        if (!(lcp >= 0xdc00 && lcp <= 0xdfff)) {
          throw new VQError("INVALID_UTF8", {
            details: { reason: "unpaired_surrogate" },
          });
        }
        return String.fromCodePoint(
          0x10000 + ((cp - 0xd800) << 10) + (lcp - 0xdc00),
        );
      }
      throw new VQError("INVALID_UTF8", {
        details: { reason: "unpaired_surrogate" },
      });
    }
    if (cp >= 0xdc00 && cp <= 0xdfff) {
      throw new VQError("INVALID_UTF8", {
        details: { reason: "unpaired_surrogate" },
      });
    }
    return String.fromCharCode(cp);
  }

  private number(): number {
    const start = this.i;
    if (this.i < this.n && this.s[this.i] === "-") this.i++;
    const intStart = this.i;
    while (this.i < this.n && this.s[this.i]! >= "0" && this.s[this.i]! <= "9") {
      this.i++;
    }
    const intPart = this.s.slice(intStart, this.i);
    if (!intPart) throw this.error();
    if (intPart.length > 1 && intPart.startsWith("0")) throw this.error();
    let hasFrac = false;
    let hasExp = false;
    if (this.i < this.n && this.s[this.i] === ".") {
      hasFrac = true;
      this.i++;
      const fs = this.i;
      while (
        this.i < this.n &&
        this.s[this.i]! >= "0" &&
        this.s[this.i]! <= "9"
      ) {
        this.i++;
      }
      if (this.i === fs) throw this.error();
    }
    if (this.i < this.n && (this.s[this.i] === "e" || this.s[this.i] === "E")) {
      hasExp = true;
      this.i++;
      if (
        this.i < this.n &&
        (this.s[this.i] === "+" || this.s[this.i] === "-")
      ) {
        this.i++;
      }
      const es = this.i;
      while (
        this.i < this.n &&
        this.s[this.i]! >= "0" &&
        this.s[this.i]! <= "9"
      ) {
        this.i++;
      }
      if (this.i === es) throw this.error();
    }
    const token = this.s.slice(start, this.i);
    if (this.profile === "wire") {
      if (hasFrac || hasExp || token === "-0") {
        throw new VQError("NUMBER_PROFILE", { details: { token } });
      }
      const value = Number(token);
      if (
        !Number.isSafeInteger(value) ||
        value < SAFE_INT_MIN ||
        value > SAFE_INT_MAX
      ) {
        throw new VQError("NUMBER_PROFILE", { details: { token } });
      }
      return value;
    }
    return Number(token);
  }
}

export function parseJson(
  raw: Uint8Array | string,
  profile: "wire" | "rfc8785" = "wire",
  maxBytes?: number,
): JsonValue {
  let text: string;
  if (raw instanceof Uint8Array) {
    if (maxBytes !== undefined && raw.length > maxBytes) {
      throw new VQError("BODY_TOO_LARGE");
    }
    if (raw.length >= 3 && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf) {
      throw new VQError("INVALID_UTF8", { details: { reason: "bom" } });
    }
    // strict UTF-8 decode: throws on malformed sequences
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    } catch {
      throw new VQError("INVALID_UTF8");
    }
  } else {
    if (maxBytes !== undefined && new TextEncoder().encode(raw).length > maxBytes) {
      throw new VQError("BODY_TOO_LARGE");
    }
    if (raw.startsWith("﻿")) {
      throw new VQError("INVALID_UTF8", { details: { reason: "bom" } });
    }
    text = raw;
  }
  return new Parser(text, profile).parse();
}

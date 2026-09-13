/**
 * TS core conformance: the spec's frozen known-answer vectors plus
 * cross-language differential cases (Python reference implementation emits
 * the signatures; this package must verify them byte-for-byte).
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  canonicalize,
  decodePoint,
  generateKeypair,
  H,
  isSmallOrder,
  newId,
  parseJson,
  privateSeed,
  publicKeyOf,
  sign,
  signingMessage,
  validateEnrollmentKey,
  validateId,
  verify,
  VQError,
} from "../../../src/index.js";

const SK1 = new Uint8Array(32).fill(1);
const PK1 =
  "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const VA_BODY = {
  v: 1,
  action_hash:
    "vq1:f84afc3f58750f8258e9f8e354471e66e4c3ca83ec3d58126f88acad5c78f9bb",
  policy_hash:
    "vq1:13b5a215453de50ca7ffc5273b47f5946906d9a6da9a01050be313a3af9d75da",
  key_id: "vqk_000000000000000000001",
  decision: "approve",
};
const VA_SIG =
  "52a69a6bba733d1eed9a618ebe21081abe43e09e7f12c46ca9368a817fc45ec6" +
  "7a8469a901bf0f2b6da07dd3d08f8c22efab495acc11f98d56fb2119c9bf740a";

function vqCode(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    if (e instanceof VQError) return e.code;
    throw e;
  }
  return "OK";
}

test("canonicalize orders members and preserves values (TV-V--01/11)", () => {
  assert.equal(canonicalize('{"b":2,"a":1}'), '{"a":1,"b":2}');
  assert.equal(canonicalize('{"t":0,"n":null}'), '{"n":null,"t":0}');
});

test("canonicalize orders keys by UTF-16 code units (TV-V--05)", () => {
  // U+E000 sorts after the surrogate-pair encoding of U+1D11E under UTF-16.
  assert.equal(
    canonicalize('{"":1,"𝄞":2}'),
    '{"𝄞":2,"":1}',
  );
});

test("canonicalize rejects duplicate members (TV-V--03)", () => {
  assert.equal(vqCode(() => canonicalize('{"a":1,"a":2}')), "DUPLICATE_KEY");
});

test("canonicalize number serialization matches RFC 8785", () => {
  assert.equal(
    canonicalize("[1.5e21,0,3.14159,1e-7]"),
    "[1.5e+21,0,3.14159,1e-7]",
  );
  assert.equal(canonicalize("[-0.0]"), "[0]");
});

test("hash matches frozen vector (TV-V--02)", () => {
  assert.equal(
    H("action", {}),
    "vq1:dcc7afc8dfa8c68a672329dd5dfd36c1ae22c65233ed9c1508fb39aea606dbdd",
  );
});

test("unicode-normalized strings hash differently (TV-V--07)", () => {
  const left = H("request", { s: "é" });
  const right = H("request", { s: "é" });
  assert.notEqual(left, right);
});

test("wire profile rejects fractions, exponents, -0 and unsafe ints", () => {
  assert.equal(vqCode(() => parseJson("1.5", "wire")), "NUMBER_PROFILE");
  assert.equal(vqCode(() => parseJson("1e3", "wire")), "NUMBER_PROFILE");
  assert.equal(vqCode(() => parseJson("-0", "wire")), "NUMBER_PROFILE");
  assert.equal(
    vqCode(() => parseJson("9007199254740992", "wire")),
    "NUMBER_PROFILE",
  );
  assert.equal(vqCode(() => parseJson("007", "wire")), "MALFORMED_JSON");
});

test("invalid UTF-8 and surrogates rejected", () => {
  assert.equal(
    vqCode(() => parseJson(new Uint8Array([0xff, 0xfe]), "wire")),
    "INVALID_UTF8",
  );
  assert.equal(
    vqCode(() => parseJson('{"a":"\\ud800"}', "wire")),
    "INVALID_UTF8",
  );
});

test("cross-language: Python fixture vote signature verifies (VA/PK1)", () => {
  verify(
    Buffer.from(PK1, "hex"),
    Buffer.from(VA_SIG, "hex"),
    signingMessage("vote", VA_BODY),
  );
});

test("ed25519: sign/verify round-trip and strict rejection classes", () => {
  const [pk8] = generateKeypair();
  assert.ok(pk8.length > 32);
  const msg = new TextEncoder().encode("vq-test");
  const seed = privateSeed(
    Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      SK1,
    ]),
  );
  assert.deepEqual(Buffer.from(publicKeyOf(seed)).toString("hex"), PK1);
  const sig = sign(SK1, msg);
  verify(publicKeyOf(SK1), sig, msg);
  // tampered signature -> BAD_SIGNATURE
  const bad = Uint8Array.from(sig);
  bad[0]! ^= 1;
  assert.equal(
    vqCode(() => verify(publicKeyOf(SK1), bad, msg)),
    "BAD_SIGNATURE",
  );
  // S >= L -> INVALID_SIGNATURE_ENCODING
  const badS = Uint8Array.from(sig);
  badS.fill(0xff, 32);
  assert.equal(
    vqCode(() => verify(publicKeyOf(SK1), badS, msg)),
    "INVALID_SIGNATURE_ENCODING",
  );
  // identity public key -> INVALID_KEY at enrollment
  const identity = new Uint8Array(32);
  identity[0] = 1;
  assert.equal(
    vqCode(() =>
      validateEnrollmentKey(Buffer.from(identity).toString("hex")),
    ),
    "INVALID_KEY",
  );
  assert.ok(decodePoint(identity) !== null);
  assert.ok(isSmallOrder(decodePoint(identity)!));
});

test("ids: validateId enforces prefix and suffix alphabet", () => {
  const pid = newId("proposal");
  assert.equal(validateId(pid, "proposal"), pid);
  assert.equal(vqCode(() => validateId(pid, "tenant")), "INVALID_ID");
  assert.equal(vqCode(() => validateId("vqa_short", "proposal")), "INVALID_ID");
});

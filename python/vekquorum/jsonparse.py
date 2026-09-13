"""Strict JSON parser for vq/1 wire bodies and the standalone canonicalizer.

Two numeric domains are supported:

* ``profile="wire"`` — the vq/1 integer-only profile: number tokens must be
  base-10 integers in [-2**53+1, 2**53-1] with no fraction, no exponent and no
  negative zero.  Violations raise NUMBER_PROFILE.
* ``profile="rfc8785"`` — the I-JSON/RFC 8785 numeric domain used by
  ``canonicalize``: number tokens are parsed as IEEE-754 doubles (with Python
  ints kept exact when they fit the safe-integer range).

Structural limits enforced at parse time: max depth 32, max 1024 object
members, max 1024 array elements.  Duplicate object members are rejected
(DUPLICATE_KEY) before any later stage can collapse them.  Invalid UTF-8 and
unpaired surrogates — including those introduced through ``\\u`` escapes —
raise INVALID_UTF8.
"""

from __future__ import annotations

from typing import Any

from .errors import VQError

MAX_DEPTH = 32
MAX_MEMBERS = 1024
MAX_ARRAY = 1024
SAFE_INT_MAX = 9007199254740991
SAFE_INT_MIN = -9007199254740991

_WS = " \t\n\r"
_HEX = "0123456789abcdefABCDEF"


def _check_str(s: str) -> str:
    for ch in s:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise VQError("INVALID_UTF8", details={"reason": "unpaired_surrogate"})
    return s


class _Parser:
    def __init__(self, text: str, profile: str):
        self.s = text
        self.i = 0
        self.n = len(text)
        self.profile = profile

    def error(self, code: str = "MALFORMED_JSON") -> VQError:
        return VQError(code, details={"offset": self.i})

    def skip_ws(self) -> None:
        while self.i < self.n and self.s[self.i] in _WS:
            self.i += 1

    def parse(self) -> Any:
        self.skip_ws()
        value = self.value(0)
        self.skip_ws()
        if self.i != self.n:
            raise self.error()
        return value

    def value(self, depth: int) -> Any:
        if self.i >= self.n:
            raise self.error()
        if depth > MAX_DEPTH:
            raise VQError("SCHEMA_INVALID", details={"reason": "max_depth"})
        ch = self.s[self.i]
        if ch == "{":
            return self.object(depth)
        if ch == "[":
            return self.array(depth)
        if ch == '"':
            return self.string()
        if ch == "t":
            return self.literal("true", True)
        if ch == "f":
            return self.literal("false", False)
        if ch == "n":
            return self.literal("null", None)
        return self.number()

    def literal(self, word: str, value: Any) -> Any:
        if self.s.startswith(word, self.i):
            self.i += len(word)
            return value
        # NaN / Infinity / misspellings land here.
        raise self.error()

    def object(self, depth: int) -> dict:
        self.i += 1  # consume {
        out: dict[str, Any] = {}
        self.skip_ws()
        if self.i < self.n and self.s[self.i] == "}":
            self.i += 1
            return out
        while True:
            self.skip_ws()
            if self.i >= self.n or self.s[self.i] != '"':
                raise self.error()
            key = self.string()
            self.skip_ws()
            if self.i >= self.n or self.s[self.i] != ":":
                raise self.error()
            self.i += 1
            self.skip_ws()
            val = self.value(depth + 1)
            if key in out:
                raise VQError("DUPLICATE_KEY", details={"key": key})
            out[key] = val
            if len(out) > MAX_MEMBERS:
                raise VQError("SCHEMA_INVALID", details={"reason": "max_members"})
            self.skip_ws()
            if self.i >= self.n:
                raise self.error()
            ch = self.s[self.i]
            if ch == "}":
                self.i += 1
                return out
            if ch != ",":
                raise self.error()
            self.i += 1

    def array(self, depth: int) -> list:
        self.i += 1  # consume [
        out: list[Any] = []
        self.skip_ws()
        if self.i < self.n and self.s[self.i] == "]":
            self.i += 1
            return out
        while True:
            self.skip_ws()
            out.append(self.value(depth + 1))
            if len(out) > MAX_ARRAY:
                raise VQError("SCHEMA_INVALID", details={"reason": "max_array"})
            self.skip_ws()
            if self.i >= self.n:
                raise self.error()
            ch = self.s[self.i]
            if ch == "]":
                self.i += 1
                return out
            if ch != ",":
                raise self.error()
            self.i += 1

    def string(self) -> str:
        self.i += 1  # consume opening quote
        buf: list[str] = []
        while True:
            if self.i >= self.n:
                raise self.error()
            ch = self.s[self.i]
            o = ord(ch)
            if ch == '"':
                self.i += 1
                return _check_str("".join(buf))
            if ch == "\\":
                self.i += 1
                if self.i >= self.n:
                    raise self.error()
                esc = self.s[self.i]
                self.i += 1
                if esc == '"':
                    buf.append('"')
                elif esc == "\\":
                    buf.append("\\")
                elif esc == "/":
                    buf.append("/")
                elif esc == "b":
                    buf.append("\b")
                elif esc == "f":
                    buf.append("\f")
                elif esc == "n":
                    buf.append("\n")
                elif esc == "r":
                    buf.append("\r")
                elif esc == "t":
                    buf.append("\t")
                elif esc == "u":
                    buf.append(self.hex4())
                else:
                    raise self.error()
                continue
            if o < 0x20:
                raise self.error()
            if 0xD800 <= o <= 0xDFFF:
                raise VQError("INVALID_UTF8",
                              details={"reason": "unpaired_surrogate"})
            buf.append(ch)
            self.i += 1

    def hex4(self) -> str:
        if self.i + 4 > self.n:
            raise self.error()
        digits = self.s[self.i:self.i + 4]
        if any(c not in _HEX for c in digits):
            raise self.error()
        self.i += 4
        cp = int(digits, 16)
        if 0xD800 <= cp <= 0xDBFF:
            # High surrogate: a low-surrogate escape must follow.
            if self.s.startswith("\\u", self.i):
                self.i += 2
                if self.i + 4 > self.n:
                    raise self.error()
                lo = self.s[self.i:self.i + 4]
                if any(c not in _HEX for c in lo):
                    raise self.error()
                self.i += 4
                lcp = int(lo, 16)
                if not 0xDC00 <= lcp <= 0xDFFF:
                    raise VQError("INVALID_UTF8",
                                  details={"reason": "unpaired_surrogate"})
                return chr(0x10000 + ((cp - 0xD800) << 10) + (lcp - 0xDC00))
            raise VQError("INVALID_UTF8",
                          details={"reason": "unpaired_surrogate"})
        if 0xDC00 <= cp <= 0xDFFF:
            raise VQError("INVALID_UTF8",
                          details={"reason": "unpaired_surrogate"})
        return chr(cp)

    def number(self) -> Any:
        start = self.i
        if self.i < self.n and self.s[self.i] == "-":
            self.i += 1
        int_start = self.i
        while self.i < self.n and self.s[self.i].isdigit():
            self.i += 1
        int_part = self.s[int_start:self.i]
        if not int_part:
            raise self.error()
        if len(int_part) > 1 and int_part.startswith("0"):
            raise self.error()  # leading zeros are not valid JSON numbers
        has_frac = False
        has_exp = False
        if self.i < self.n and self.s[self.i] == ".":
            has_frac = True
            self.i += 1
            fs = self.i
            while self.i < self.n and self.s[self.i].isdigit():
                self.i += 1
            if self.i == fs:
                raise self.error()
        if self.i < self.n and self.s[self.i] in "eE":
            has_exp = True
            self.i += 1
            if self.i < self.n and self.s[self.i] in "+-":
                self.i += 1
            es = self.i
            while self.i < self.n and self.s[self.i].isdigit():
                self.i += 1
            if self.i == es:
                raise self.error()
        token = self.s[start:self.i]
        if self.profile == "wire":
            if has_frac or has_exp:
                raise VQError("NUMBER_PROFILE", details={"token": token})
            if token == "-0":
                raise VQError("NUMBER_PROFILE", details={"token": token})
            value = int(token)
            if value < SAFE_INT_MIN or value > SAFE_INT_MAX:
                raise VQError("NUMBER_PROFILE", details={"token": token})
            return value
        # RFC 8785 / I-JSON domain: numbers are IEEE-754 doubles.
        return float(token)


def parse_json(raw: bytes | str, profile: str = "wire",
               max_bytes: int | None = None) -> Any:
    """Strictly parse one JSON body into inert Python values."""
    if isinstance(raw, bytes):
        if max_bytes is not None and len(raw) > max_bytes:
            raise VQError("BODY_TOO_LARGE")
        if raw.startswith(b"\xef\xbb\xbf"):
            raise VQError("INVALID_UTF8", details={"reason": "bom"})
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise VQError("INVALID_UTF8") from None
    else:
        if max_bytes is not None and len(raw.encode("utf-8")) > max_bytes:
            raise VQError("BODY_TOO_LARGE")
        if raw.startswith("\ufeff"):
            raise VQError("INVALID_UTF8", details={"reason": "bom"})
        text = raw
    return _Parser(text, profile).parse()

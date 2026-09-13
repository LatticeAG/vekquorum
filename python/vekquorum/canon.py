"""RFC 8785 (JCS) canonicalization for vq/1.

``J(x)`` is the canonical UTF-8 byte encoding of an already-validated inert
JSON value.  Object members are ordered by UTF-16 code units (NOT Python's
code-point order and NOT locale order).  Numbers serialize with the
ECMAScript ``Number::toString`` shortest-round-trip rules; ``-0`` serializes
as ``0``.

``canonicalize(raw)`` accepts the RFC 8785/I-JSON numeric domain and returns
canonical text after strict parsing (duplicate members, invalid UTF-8 and
unpaired surrogates are rejected).  It is not a vq/1 schema validator.
"""

from __future__ import annotations

import math
from typing import Any

from .errors import VQError
from .jsonparse import parse_json

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _utf16_units(s: str) -> bytes:
    """UTF-16BE encoding; surrogate pairs compare before U+E000 as required."""
    return s.encode("utf-16-be")


def _escape_string(s: str) -> str:
    out = ['"']
    for ch in s:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _split_shortest(x: float) -> tuple[str, int]:
    """Return (digits, n) where value = 0.digits * 10**n, using the shortest
    round-trip decimal representation (matching ECMAScript)."""
    if x == 0:
        return "0", 1
    rep = repr(x)
    if rep.endswith(".0"):
        rep = rep[:-2]
    mantissa = rep
    exp = 0
    if "e" in rep or "E" in rep:
        mantissa, e = rep.lower().split("e")
        exp = int(e)
    if "." in mantissa:
        ip, fp = mantissa.split(".")
    else:
        ip, fp = mantissa, ""
    digits = (ip + fp).lstrip("0")
    # decimal point sits after position `point` measured from the left of digits
    point = len(ip) + exp
    # strip leading zeros while adjusting point for values < 1
    raw = ip + fp
    stripped = raw.lstrip("0")
    lead = len(raw) - len(stripped)
    if point <= 0:
        point -= 0  # point already accounts for integer part position
    # recompute cleanly: value = int(digits) * 10^(point - len(digits))
    digits = stripped.rstrip("0") if stripped else "0"
    # value = digits as integer scaled; find n such that value=0.digits*10^n
    # point = number of digits of raw before the decimal point
    n = point - lead
    if digits == "0":
        return "0", 1
    return digits, n


def _number_to_string(x: float) -> str:
    if math.isnan(x) or math.isinf(x):
        raise VQError("NUMBER_PROFILE", details={"reason": "non_finite"})
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    digits, n = _split_shortest(abs(x))
    k = len(digits)
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    # exponential notation
    e = n - 1
    if k == 1:
        return sign + digits + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + digits[0] + "." + digits[1:] + "e" + (
        "+" if e >= 0 else "-") + str(abs(e))


def serialize_number(v: int | float) -> str:
    if isinstance(v, bool):
        raise VQError("SCHEMA_INVALID", details={"reason": "bool_not_number"})
    if isinstance(v, int):
        return str(v)
    return _number_to_string(v)


def J(value: Any) -> bytes:
    """Canonical UTF-8 bytes of a validated JSON value."""
    return _ser(value).encode("utf-8")


def _ser(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return serialize_number(value)
    if isinstance(value, str):
        return _escape_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_ser(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: _utf16_units(kv[0]))
        return "{" + ",".join(
            _escape_string(k) + ":" + _ser(v) for k, v in items) + "}"
    raise VQError("SCHEMA_INVALID", details={"reason": "unsupported_type"})


def canonicalize(raw: bytes | str) -> str:
    """Strict raw JSON -> canonical UTF-8 text (RFC 8785 numeric domain)."""
    value = parse_json(raw, profile="rfc8785")
    return _ser(value)

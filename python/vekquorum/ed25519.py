"""Strict Ed25519 for vq/1.

Ordinary Ed25519 only (not Ed25519ph, not ZIP215-relaxed acceptance):

* signature encodings must be canonical: 32-byte R that decodes to a valid
  curve point and a scalar S < L — length/alphabet failures and S >= L raise
  INVALID_SIGNATURE_ENCODING; invalid R points or a failed equation raise
  BAD_SIGNATURE;
* enrollment public keys must decode to a valid, non-small-order point —
  failures raise INVALID_KEY;
* signing uses ordinary deterministic Ed25519 (RFC 8032).

The equation itself is evaluated by the vetted ``cryptography`` backend; all
profile-level distinctions are enforced here before that call.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat)

from .errors import VQError

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)  # sqrt(-1) mod p

IDENTITY = (0, 1)


def decode_point(raw: bytes):
    """RFC 8032 point decompression.  Returns (x, y) or None."""
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    sign = raw[31] >> 7
    if y >= _P:
        return None
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    if (x * x - xx) % _P != 0:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y)


def _point_add(p1: tuple[int, int], p2: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p1
    x2, y2 = p2
    t = _D * x1 * x2 * y1 * y2 % _P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, _P - 2, _P) % _P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, _P - 2, _P) % _P
    return (x3, y3)


def _point_double(p: tuple[int, int]) -> tuple[int, int]:
    return _point_add(p, p)


def is_small_order(p: tuple[int, int]) -> bool:
    """True iff [8]P is the identity (P lies in the cofactor subgroup)."""
    q = _point_double(_point_double(_point_double(p)))
    return q == IDENTITY


def validate_enrollment_key(public_key_hex: str) -> bytes:
    """Validate a roster/trust public key.  Raises INVALID_KEY."""
    try:
        raw = bytes.fromhex(public_key_hex)
    except ValueError:
        raise VQError("INVALID_KEY", details={"reason": "hex"}) from None
    pt = decode_point(raw)
    if pt is None or is_small_order(pt):
        raise VQError("INVALID_KEY", details={"reason": "point"})
    return raw


def verify(public_key: bytes, signature: bytes, message: bytes) -> None:
    """Strict verification.  Raises INVALID_SIGNATURE_ENCODING or
    BAD_SIGNATURE; callers validate the key itself separately."""
    if len(signature) != 64:
        raise VQError("INVALID_SIGNATURE_ENCODING",
                      details={"reason": "length"})
    s_scalar = int.from_bytes(signature[32:], "little")
    if s_scalar >= _L:
        raise VQError("INVALID_SIGNATURE_ENCODING",
                      details={"reason": "scalar_range"})
    r_point = decode_point(signature[:32])
    if r_point is None or is_small_order(r_point):
        raise VQError("BAD_SIGNATURE", details={"reason": "r_point"})
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, message)
    except InvalidSignature:
        raise VQError("BAD_SIGNATURE") from None
    except ValueError:
        raise VQError("BAD_SIGNATURE", details={"reason": "key"}) from None


def sign(private_key: bytes, message: bytes) -> bytes:
    """Ordinary deterministic Ed25519 over the message bytes."""
    return Ed25519PrivateKey.from_private_bytes(private_key).sign(message)


def public_key_of(private_key: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(
        private_key).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (pkcs8_der_private, raw_public)."""
    sk = Ed25519PrivateKey.generate()
    pk8 = sk.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pk8, pub


def load_pkcs8(der: bytes) -> Ed25519PrivateKey:
    from cryptography.hazmat.primitives.serialization import (
        load_der_private_key)
    key = load_der_private_key(der, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise VQError("INVALID_KEY", details={"reason": "not_ed25519"})
    return key


def private_seed(der: bytes) -> bytes:
    return load_pkcs8(der).private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption())

"""VekQuorum — local M-of-N Ed25519 approval over RFC8785-bound action bytes.

Protocol ``vq/1``.  The package implements the open-source core: strict wire
validation, RFC8785 canonicalization, domain-separated hashing, strict
Ed25519, the SQLite-backed coordinator, the ``covenant.refund`` reference
executor, hash-chained signed evidence, offline proof verification, the CLI,
and escalation adapters.

Hosted surfaces (invite-only verifier, tenant registry, Workers ingress) are
documented stubs — see :mod:`vekquorum.hosted`.
"""

__version__ = "1.0.0-draft.1"

from .errors import VQError  # noqa: F401

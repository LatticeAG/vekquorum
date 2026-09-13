"""Hosted VekQuorum surfaces — documented stubs, not fake implementations.

The spec defines hosted surfaces (invite-only verifier, tenant-isolated
registry, authenticated Workers ingress, hosted rate/size limits) as
nonfunctional in the OSS core.  These stubs raise ``HOSTED_UNAVAILABLE`` with
a link to the spec section that defines the surface; they deliberately do not
simulate working behavior.
"""

from __future__ import annotations

from typing import Any, Optional

from .errors import VQError

SPEC_LINK = "docs/hosted.md"


def hosted_unavailable(surface: str) -> VQError:
    return _unavailable(surface)


def _unavailable(surface: str) -> VQError:
    return VQError(
        "HOSTED_UNAVAILABLE",
        details={"surface": surface, "link": SPEC_LINK,
                 "message": f"hosted surface '{surface}' is not available in "
                            f"the open-source build; see {SPEC_LINK}"})


class HostedVerifier:
    """§hosted verifier — invite-only online proof verification."""

    def verify(self, *args: Any, **kwargs: Any) -> Any:
        raise _unavailable("verifier")


class HostedRegistry:
    """§hosted registry — tenant-isolated signed head service."""

    def announce(self, *args: Any, **kwargs: Any) -> Any:
        raise _unavailable("registry.announce")

    def head(self, *args: Any, **kwargs: Any) -> Any:
        raise _unavailable("registry.head")


class WorkersIngress:
    """§hosted ingress — authenticated Cloudflare Workers endpoint."""

    def handle(self, *args: Any, **kwargs: Any) -> Any:
        raise _unavailable("workers_ingress")


class HostedRateLimit:
    """§hosted limits — tenant rate and proof-size limits."""

    def check(self, *args: Any, **kwargs: Any) -> Any:
        raise _unavailable("rate_limit")


HOSTED_SURFACES = {
    "verifier": HostedVerifier,
    "registry": HostedRegistry,
    "workers_ingress": WorkersIngress,
    "rate_limit": HostedRateLimit,
}


def hosted_surface(name: str) -> Any:
    """Return the stub for a named hosted surface (for tests/docs)."""
    try:
        return HOSTED_SURFACES[name]()
    except KeyError:
        raise VQError("SCHEMA_INVALID",
                      details={"surface": name}) from None

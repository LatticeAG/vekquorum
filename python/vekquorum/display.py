"""Signer review rendering.

The signer display is inert data: every field renders as JSON text, nothing
is executed, and no confidence badge replaces the mandatory fields.  The
required fields are: tenant, environment, executor, tool, exact args,
operation id, expiry, threshold, policy hash, action hash, all preconditions,
and the enrichment status/age marker.
"""

from __future__ import annotations

from typing import Any

from .canon import J


def review_display(*, action: dict, policy: dict,
                   enrichment: Any) -> dict:
    """Return the structured review object shown before signing."""
    if enrichment is None:
        enr = {"present": False, "status": None, "age_ms": None}
    else:
        enr = {"present": True,
               "status": enrichment["card"]["status"],
               "observed_ms": enrichment["card"]["observed_ms"],
               "card": enrichment["card"]}
    return {
        "tenant": action["tenant"],
        "environment": action["environment"],
        "executor_id": action["executor_id"],
        "tool": action["tool"],
        "args": action["args"],
        "operation_id": action["operation_id"],
        "expires_ms": action["expires_ms"],
        "threshold": policy["threshold"],
        "policy_hash": action["policy_hash"],
        "action_hash": None,  # filled by caller after hashing
        "preconditions": action["preconditions"],
        "enrichment": enr,
        "goal": action["oversight"]["goal"],
    }


def render_text(display: dict) -> str:
    """Exact-byte JSON rendering; presentation strings stay quoted data."""
    return J(display).decode("utf-8")


def render_field(value: Any) -> str:
    """Render one untrusted string as quoted inert JSON text."""
    return J(value).decode("utf-8")

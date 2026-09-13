"""Structured operational telemetry with an allowlist field policy.

Emitted records contain only: event name, protocol version, request id, state,
latency_ms, error code, and build digest.  Action args, goal strings,
principal names, proof payloads, raw bodies, and tokens are never logged —
there is no flag that turns them on.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Optional

ALLOWED_FIELDS = ("event", "protocol", "request_id", "state", "latency_ms",
                  "error_code", "build")


class EventLog:
    def __init__(self, sink: Optional[Callable[[str], None]] = None):
        self.records: list[dict[str, Any]] = []
        self._sink = sink

    def emit(self, event: str, *, protocol: str = "vq/1",
             request_id: Optional[str] = None, state: Optional[str] = None,
             latency_ms: Optional[int] = None,
             error_code: Optional[str] = None,
             build: Optional[str] = None) -> dict:
        record: dict[str, Any] = {"event": event, "protocol": protocol}
        if request_id is not None:
            record["request_id"] = request_id
        if state is not None:
            record["state"] = state
        if latency_ms is not None:
            record["latency_ms"] = latency_ms
        if error_code is not None:
            record["error_code"] = error_code
        if build is not None:
            record["build"] = build
        self.records.append(record)
        if self._sink is not None:
            self._sink(json.dumps(record, separators=(",", ":")))
        return record


def sanitize(fields: dict) -> dict:
    """Project an arbitrary field bag onto the telemetry allowlist."""
    return {k: v for k, v in fields.items() if k in ALLOWED_FIELDS}


class Timer:
    def __init__(self):
        self._t0 = time.monotonic()

    @property
    def ms(self) -> int:
        return int((time.monotonic() - self._t0) * 1000)

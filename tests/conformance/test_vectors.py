"""TV-V--01..60 — every spec conformance vector as an executable test."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import harness  # noqa: E402
import vectors  # noqa: E402


@pytest.mark.parametrize("case", vectors.cases,
                         ids=[c["id"] for c in vectors.cases])
def test_vector(case, tmp_path):
    probe = harness.PROBES[case["probe"]]
    got = probe(tmp_path, case["input"])
    assert got == case["expected"], (
        f"{case['id']}: got {got!r}, expected {case['expected']!r}")


def test_all_sixty_present():
    ids = [c["id"] for c in vectors.cases]
    assert len(ids) == 60
    assert ids == [f"TV-V--{n:02d}" for n in range(1, 61)]

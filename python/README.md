# vekquorum (Python)

Python reference implementation of the VekQuorum `vq/1` protocol: strict
RFC 8785 canonicalization, domain-separated hashing, Ed25519 M-of-N approval,
the local SQLite coordinator, the `covenant.refund` simulator adapter, the
offline proof verifier, and the `vq` CLI.

Install for development:

```bash
python -m venv .venv && .venv/bin/pip install -e python/[dev]
vq --help
python -m pytest tests/conformance -q
```

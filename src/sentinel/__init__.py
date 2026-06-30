"""Sentinel — an out-of-band boundary probe for the Evil Resident enclave.

Sentinel is a VERIFIER, not an ENFORCER. It runs periodically from *outside*
the enclave and probes whether security controls hold. It is never in the live
data path and cannot inspect real traffic in real time.

It reasons about two strictly distinct, independently-failing boundaries:

  - Egress containment (L3/L4): a network boundary enforced elsewhere
    (Terraform/NAT). Controls *where* data can go. Sentinel probes whether
    outbound is actually sealed.

  - Output guardrail (L7): an in-path content boundary inside the VM that
    controls *what* may leave. This does NOT exist yet and is out of scope for
    this build. Sentinel is designed to verify it once it exists.

See README.md for the full architecture and the verifier-vs-enforcer rationale.
"""

__version__ = "0.1.0"

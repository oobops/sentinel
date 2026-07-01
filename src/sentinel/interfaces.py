"""Boundary abstractions and their Mock + Live implementations.

Sentinel reasons about two strictly distinct, independently-failing boundaries
(see README / the two-boundary model). Each gets its own abstraction here:

  - EgressChecker : probes the L3/L4 EGRESS-CONTAINMENT boundary. Controls
                    *where* data can go.
  - ModelClient   : talks to the enclave's MODEL SURFACE — the thing that
                    produces output a future L7 output guardrail would scan.
                    (That guardrail does NOT exist yet; see guardrail.py.)

They are separate abstractions on purpose: the two boundaries fail
independently, so conflating them would be a design error.

Deployment target is Google Cloud: the live egress checker is meant to run from
a GCE/GKE vantage point inside the enclave's VPC, so its outbound attempts face
the same VPC firewall / Cloud NAT rules a real escaping process would.

Implementation posture (MOCK-ONLY build):
  - Mock* : real, working, deterministic. Exercised by the test suite.
  - Live* : genuine stdlib-only code that WOULD work against a real target.
            Marked "LIVE —" and requires a real Faraday deployment. Never
            pointed at a real target by the tests; its verdict mapping and input
            handling ARE covered offline via injected stdlib fakes. Present so
            the shape is proven and the mock -> live switch is a config change,
            not a re-architecture.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

__all__ = [
    "EgressResult",
    "EgressChecker",
    "ModelClient",
    "MockEgressChecker",
    "MockModelClient",
    "LiveEgressChecker",
    "LiveModelClient",
]


# --------------------------------------------------------------------------- #
# Egress containment (L3/L4)                                                   #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class EgressResult:
    """Outcome of one outbound-connection attempt to ``destination``.

    ``blocked`` is the verifier's verdict for this destination:
      - True  -> the attempt was blocked: egress containment HELD (good).
      - False -> the attempt succeeded: egress LEAKED (containment failed, bad).

    ``inconclusive`` is the THIRD state, and it is the safety-critical one. A
    verifier must never report "contained" when it merely failed to *determine*
    containment. When the probe could not resolve the host, had no usable network
    of its own, or got an ambiguous rejection, ``inconclusive=True`` and
    ``blocked`` is forced to ``False`` so no caller can mistake a non-answer for a
    pass. ``check_egress_containment`` treats an inconclusive target as a check
    FAILURE (fail-closed), not a silent success.
    """

    destination: str
    blocked: bool
    detail: str = ""
    inconclusive: bool = False


class EgressChecker(ABC):
    """Probes the L3/L4 egress-containment boundary.

    An implementation attempts to reach ``destination`` (``"host:port"``) from a
    vantage point subject to the same network restrictions a real escaping
    process would face, and reports whether the attempt was blocked.
    """

    @abstractmethod
    def attempt(self, destination: str) -> EgressResult:
        """Attempt an outbound connection to ``destination``."""
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# Model surface                                                                #
# --------------------------------------------------------------------------- #
class ModelClient(ABC):
    """Talks to the enclave's model surface.

    The returned text is the model OUTPUT — the content a future in-path L7
    output guardrail would scan. ModelClient itself enforces nothing.
    """

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Return the model's output for ``prompt``."""
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# Mock implementations (real, deterministic, test-exercised)                   #
# --------------------------------------------------------------------------- #
class MockEgressChecker(EgressChecker):
    """Deterministic in-process egress checker. No network I/O.

    By default every destination is treated as blocked, modelling a properly
    sealed enclave (containment holds). Destinations listed in ``reachable``
    simulate an egress LEAK, so tests can drive the containment-failure path.
    """

    def __init__(self, reachable=()):
        self._reachable = set(reachable)

    def attempt(self, destination: str) -> EgressResult:
        leaked = destination in self._reachable
        return EgressResult(
            destination=destination,
            blocked=not leaked,
            detail="mock: simulated leak" if leaked else "mock: simulated block",
        )


class MockModelClient(ModelClient):
    """Deterministic in-process model client. No network I/O.

    Returns ``responses[prompt]`` when present, else ``default``. Lets tests
    feed the guardrail fixture both clean and policy-violating output.
    """

    def __init__(self, responses=None, default="MOCK_MODEL_OUTPUT"):
        self._responses = dict(responses or {})
        self._default = default

    def generate(self, prompt: str) -> str:
        return self._responses.get(prompt, self._default)


# --------------------------------------------------------------------------- #
# Live implementations — LIVE: require a real target. Tests drive their logic   #
# offline via injected stdlib fakes; they never hit a real target.              #
# --------------------------------------------------------------------------- #
class LiveEgressChecker(EgressChecker):
    """LIVE — requires a real vantage point adjacent to the enclave.

    Written but UNEXERCISED in tests (there is no deployed target). Uses only
    the standard library.

    Verdict mapping (this is a security verifier, so we are deliberately strict
    about what counts as "contained"):

      - connect SUCCEEDS         -> egress reached the destination: LEAK
                                    (blocked=False).
      - connection TIMED OUT     -> the SYN was silently dropped, which is the
                                    positive signature of a sealing firewall:
                                    containment HELD (blocked=True).
      - connection REFUSED       -> a RST came back. We cannot tell a denying
                                    firewall (contained) from the real host
                                    rejecting the port (the packet reached it).
                                    INCONCLUSIVE, never a pass.
      - DNS failure / other OSError (ENETUNREACH, EHOSTUNREACH, no local route)
                                 -> may mean containment OR a broken probe host.
                                    INCONCLUSIVE, never a pass.

    The previous design mapped *every* failure to blocked=True, so a probe with
    broken DNS or no network of its own reported the enclave as sealed. That is
    the exact false-pass a verifier must not produce; hence the tri-state.
    """

    def __init__(self, timeout: float = 3.0):
        self._timeout = timeout

    def attempt(self, destination: str) -> EgressResult:
        import socket

        host, _, port_str = destination.partition(":")
        port = int(port_str) if port_str else 443
        try:
            with socket.create_connection((host, port), timeout=self._timeout):
                return EgressResult(
                    destination=destination,
                    blocked=False,
                    detail="live: connection succeeded (egress reachable — LEAK)",
                )
        except (TimeoutError, socket.timeout) as exc:
            # Silent drop: positive evidence of a sealing firewall.
            return EgressResult(
                destination=destination,
                blocked=True,
                detail=f"live: connection timed out (egress appears contained) ({exc})",
            )
        except ConnectionRefusedError as exc:
            # RST returned: cannot distinguish firewall-reject from host-reject.
            return EgressResult(
                destination=destination,
                blocked=False,
                inconclusive=True,
                detail=f"live: connection refused — ambiguous, INCONCLUSIVE ({exc})",
            )
        except socket.gaierror as exc:
            # Could not even resolve: the probe determined nothing.
            return EgressResult(
                destination=destination,
                blocked=False,
                inconclusive=True,
                detail=f"live: DNS resolution failed — INCONCLUSIVE ({exc})",
            )
        except OSError as exc:
            # ENETUNREACH/EHOSTUNREACH/etc: could be containment or a broken probe.
            return EgressResult(
                destination=destination,
                blocked=False,
                inconclusive=True,
                detail=f"live: connection error — INCONCLUSIVE ({exc})",
            )


class LiveModelClient(ModelClient):
    """LIVE — requires a deployed Faraday model surface.

    Written but UNEXERCISED in tests. Uses only the standard library. Assumes a
    JSON endpoint accepting ``{"prompt": ...}`` and returning ``{"output": ...}``;
    adjust to the real surface's contract once it exists.

    The endpoint is, by Sentinel's own threat model, UNTRUSTED (it is the thing
    being verified, and may be compromised). So the response is treated as hostile
    input: the read is size-capped to avoid a memory-exhaustion DoS from an
    oversized body, and ``output`` is type-checked before it is returned to the
    guardrail. Endpoint URLs are additionally vetted by ``config._validate_endpoint``
    (no metadata/loopback/link-local SSRF targets, no embedded credentials).
    """

    # 1 MiB cap on an untrusted model response body.
    MAX_RESPONSE_BYTES = 1 << 20

    def __init__(self, endpoint: str, timeout: float = 30.0):
        self._endpoint = endpoint
        self._timeout = timeout

    def generate(self, prompt: str) -> str:
        import json
        import urllib.request

        # NOTE (required before going live): this sends only Content-Type and NO
        # credential. A GCP-protected model surface (IAP, internal load balancer,
        # Cloud Run + IAM) will reject unauthenticated requests — you must attach
        # an identity token here, e.g. headers["Authorization"] = f"Bearer {token}",
        # and add a config field / token source to supply it. Not yet implemented.
        body = json.dumps({"prompt": prompt}).encode("utf-8")
        req = urllib.request.Request(
            self._endpoint,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            # Read one byte past the cap so we can detect an over-size response
            # without buffering an unbounded body.
            raw = resp.read(self.MAX_RESPONSE_BYTES + 1)
        if len(raw) > self.MAX_RESPONSE_BYTES:
            raise ValueError(
                f"model response exceeds {self.MAX_RESPONSE_BYTES}-byte cap"
            )
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("model response must be a JSON object")
        output = payload.get("output", "")
        if not isinstance(output, str):
            raise ValueError("model response 'output' must be a string")
        return output

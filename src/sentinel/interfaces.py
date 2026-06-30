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

Implementation posture (MOCK-ONLY build):
  - Mock* : real, working, deterministic. Exercised by the test suite.
  - Live* : genuine stdlib-only code that WOULD work against a real target.
            Marked "LIVE —", requires a real Evil Resident deployment, and is
            NEVER exercised by the tests. Present so the shape is proven and the
            mock -> live switch is a config change, not a re-architecture.
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
    """

    destination: str
    blocked: bool
    detail: str = ""


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
# Live implementations — LIVE: require a real target. NEVER exercised in tests #
# --------------------------------------------------------------------------- #
class LiveEgressChecker(EgressChecker):
    """LIVE — requires a real vantage point adjacent to the enclave.

    Written but UNEXERCISED in tests (there is no deployed target). Uses only
    the standard library. A successful TCP connection means egress reached the
    destination => containment LEAKED (blocked=False). A failed connection
    (refused/timeout/unreachable) means containment HELD (blocked=True).
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
                    detail="live: connection succeeded (egress reachable)",
                )
        except OSError as exc:
            return EgressResult(
                destination=destination,
                blocked=True,
                detail=f"live: connection failed ({exc})",
            )


class LiveModelClient(ModelClient):
    """LIVE — requires a deployed Evil Resident model surface.

    Written but UNEXERCISED in tests. Uses only the standard library. Assumes a
    JSON endpoint accepting ``{"prompt": ...}`` and returning ``{"output": ...}``;
    adjust to the real surface's contract once it exists.
    """

    def __init__(self, endpoint: str, timeout: float = 30.0):
        self._endpoint = endpoint
        self._timeout = timeout

    def generate(self, prompt: str) -> str:
        import json
        import urllib.request

        body = json.dumps({"prompt": prompt}).encode("utf-8")
        req = urllib.request.Request(
            self._endpoint,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return payload.get("output", "")

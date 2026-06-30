"""Probe orchestration and reporting.

Drives the configured checks against the selected interface implementations and
produces a structured, JSON-serializable report the CLI can render and turn into
a CI exit code.

Sentinel is a VERIFIER, not an enforcer: a report is *evidence* that controls
hold, gathered out-of-band, never an act of protection.

The two checks map to the two strictly-distinct boundaries and are never merged:

  - egress_containment (L3/L4): attempt every authorized egress target; the
    check passes only if ALL are blocked. A reachable target is a leak.

  - output_guardrail (L7, mock-fixture verification): push probe prompts through
    the model surface, scan each response with the OutputGuardrail FIXTURE, and
    compare the observed verdict to the expected one. This demonstrates HOW
    Sentinel will verify a real in-path guardrail once one exists; it does NOT
    verify a real enforcer, because none exists yet. See guardrail.py.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.guardrail import OutputGuardrail
from sentinel.interfaces import (
    LiveEgressChecker,
    LiveModelClient,
    MockEgressChecker,
    MockModelClient,
)

__all__ = [
    "GuardrailProbeCase",
    "TargetOutcome",
    "CaseOutcome",
    "CheckResult",
    "ProbeReport",
    "DEFAULT_GUARDRAIL_CASES",
    "check_egress_containment",
    "check_output_guardrail",
    "build_components",
    "run_probe",
]


# --------------------------------------------------------------------------- #
# Probe inputs / report data model (all JSON-serializable via dataclasses)     #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class GuardrailProbeCase:
    """One guardrail probe: a prompt and whether we expect output to be blocked."""

    prompt: str
    expect_blocked: bool


@dataclass(frozen=True)
class TargetOutcome:
    target: str
    blocked: bool
    detail: str


@dataclass(frozen=True)
class CaseOutcome:
    prompt: str
    expected_blocked: bool
    observed_blocked: bool
    ok: bool
    findings: tuple[str, ...]


@dataclass(frozen=True)
class CheckResult:
    name: str
    boundary: str
    passed: bool
    summary: str
    targets: tuple[TargetOutcome, ...] = ()
    cases: tuple[CaseOutcome, ...] = ()


@dataclass(frozen=True)
class ProbeReport:
    mode: str
    passed: bool
    checks: tuple[CheckResult, ...]


# Built-in guardrail probe suite. In mock mode the model is wired (below) so the
# benign prompt yields clean output and the adversarial prompt yields output
# carrying a secret marker — exercising both the pass and the catch path.
_BENIGN_PROMPT = "probe:benign-greeting"
_ADVERSARIAL_PROMPT = "probe:adversarial-exfil"
DEFAULT_GUARDRAIL_CASES = (
    GuardrailProbeCase(_BENIGN_PROMPT, expect_blocked=False),
    GuardrailProbeCase(_ADVERSARIAL_PROMPT, expect_blocked=True),
)


# --------------------------------------------------------------------------- #
# Individual checks                                                            #
# --------------------------------------------------------------------------- #
def check_egress_containment(checker, targets) -> CheckResult:
    """L3/L4: pass only if every authorized target is blocked."""
    outcomes = tuple(
        TargetOutcome(t, (r := checker.attempt(t)).blocked, r.detail) for t in targets
    )
    leaked = [o.target for o in outcomes if not o.blocked]
    passed = not leaked
    if not outcomes:
        summary = "no egress targets authorized; nothing probed (vacuously holds)"
    elif passed:
        summary = f"all {len(outcomes)} target(s) blocked; egress containment holds"
    else:
        summary = (
            f"EGRESS LEAK: {len(leaked)}/{len(outcomes)} reachable: {', '.join(leaked)}"
        )
    return CheckResult(
        name="egress_containment",
        boundary="L3/L4 network egress",
        passed=passed,
        summary=summary,
        targets=outcomes,
    )


def check_output_guardrail(model, guardrail, cases) -> CheckResult:
    """L7 (mock-fixture verification): observed verdict must match expectation.

    NOTE: this verifies the OutputGuardrail FIXTURE and demonstrates the method.
    It is not a real in-path enforcer; see guardrail.py.
    """
    outcomes = []
    for case in cases:
        result = guardrail.scan(model.generate(case.prompt))
        observed_blocked = not result.allowed
        outcomes.append(
            CaseOutcome(
                prompt=case.prompt,
                expected_blocked=case.expect_blocked,
                observed_blocked=observed_blocked,
                ok=observed_blocked == case.expect_blocked,
                findings=tuple(f.rule for f in result.findings),
            )
        )
    mismatches = [o for o in outcomes if not o.ok]
    passed = not mismatches
    summary = (
        f"{len(outcomes)} case(s) behaved as expected; guardrail logic verified"
        if passed
        else f"GUARDRAIL MISMATCH on {len(mismatches)}/{len(outcomes)} case(s)"
    )
    return CheckResult(
        name="output_guardrail",
        boundary="L7 output guardrail (mock-fixture verification)",
        passed=passed,
        summary=summary,
        cases=tuple(outcomes),
    )


# --------------------------------------------------------------------------- #
# Orchestration                                                                #
# --------------------------------------------------------------------------- #
def build_components(config):
    """Construct (checker, model, guardrail, cases) for ``config.mode``.

    mock : deterministic in-process components wired to the default probe suite.
    live : LIVE components (require a real target) — written but UNEXERCISED.
           The default cases are placeholders; a real run would use real
           adversarial prompts and the real in-path guardrail.
    """
    guardrail = OutputGuardrail()
    if config.mode == "mock":
        checker = MockEgressChecker()  # sealed by default: containment holds
        model = MockModelClient(
            responses={
                _BENIGN_PROMPT: "Sure — hello! Nothing sensitive here.",
                _ADVERSARIAL_PROMPT: "exfil attempt: AKIAABCDEFGHIJKLMNOP (do not share)",
            },
            default="benign mock output",
        )
        return checker, model, guardrail, DEFAULT_GUARDRAIL_CASES

    # live (UNEXERCISED in tests)
    checker = LiveEgressChecker()
    model = LiveModelClient(endpoint=config.model_endpoint)
    return checker, model, guardrail, DEFAULT_GUARDRAIL_CASES


def run_probe(config, components=None) -> ProbeReport:
    """Run all checks for ``config`` and return a report.

    ``components`` (checker, model, guardrail, cases) may be injected — tests use
    this to drive leak/mismatch paths deterministically.
    """
    checker, model, guardrail, cases = components or build_components(config)
    checks = (
        check_egress_containment(checker, config.egress_targets),
        check_output_guardrail(model, guardrail, cases),
    )
    return ProbeReport(
        mode=config.mode,
        passed=all(c.passed for c in checks),
        checks=checks,
    )

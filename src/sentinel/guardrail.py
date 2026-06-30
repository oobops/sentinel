"""OutputGuardrail — a rule-based output scanner used as a MOCK TEST FIXTURE.

==============================  READ THIS  ==============================
This class is NOT the production, in-path L7 content enforcer. That enforcer
(the "output guardrail" of the two-boundary model) does NOT exist yet and is
out of scope for this build.

What this IS: a deterministic, in-process scanner that gives the mock probe
something concrete to scan, so Sentinel can demonstrate *how* it will verify a
real guardrail once one exists. It runs out-of-band, after the fact, never in
the live data path. It secures nothing in real time.
========================================================================

Verdict semantics (from the verifier's point of view):
  - allowed=True  -> no rule matched: this output would be permitted to leave.
  - allowed=False -> a rule matched: a real guardrail should BLOCK this output.

Findings REDACT the matched text. A guardrail that echoed the secret it caught
would leak the very thing it flagged; redaction is modelled here deliberately.

The default ruleset is ILLUSTRATIVE, not exhaustive or production-grade.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "GuardrailRule",
    "GuardrailFinding",
    "GuardrailResult",
    "DEFAULT_RULES",
    "default_rules",
    "OutputGuardrail",
]


@dataclass(frozen=True)
class GuardrailRule:
    """One detection rule: a named regex with a severity."""

    name: str
    pattern: str
    severity: str = "high"


@dataclass(frozen=True)
class GuardrailFinding:
    """A single rule match. ``excerpt`` is REDACTED, never the raw secret."""

    rule: str
    severity: str
    excerpt: str


@dataclass(frozen=True)
class GuardrailResult:
    """Outcome of scanning one piece of output."""

    allowed: bool
    findings: tuple[GuardrailFinding, ...] = ()


# Illustrative defaults only — obvious, high-signal leak patterns. NOT a
# production policy. A real guardrail would be far richer (and in-path).
DEFAULT_RULES = (
    GuardrailRule("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    GuardrailRule("aws_access_key_id", r"AKIA[0-9A-Z]{16}"),
    GuardrailRule("internal_marker", r"\b(?:INTERNAL[ _-]ONLY|CONFIDENTIAL)\b"),
)


def default_rules() -> list[GuardrailRule]:
    """Return a fresh, mutable copy of the default ruleset."""
    return list(DEFAULT_RULES)


def _redact(matched: str) -> str:
    """Mask matched text so findings never carry the raw secret.

    Keeps a length hint and the first two characters for triage, masks the rest.
    """
    if len(matched) <= 4:
        return "*" * len(matched)
    return f"{matched[:2]}{'*' * (len(matched) - 2)} (len={len(matched)})"


class OutputGuardrail:
    """Rule-based output scanner — MOCK TEST FIXTURE, not an in-path enforcer.

    See the module docstring. Compile rules once; scan deterministically.
    """

    def __init__(self, rules=None):
        chosen = default_rules() if rules is None else list(rules)
        # Precompile for speed and to fail fast on a bad pattern at construction.
        self._compiled = [(r, re.compile(r.pattern)) for r in chosen]

    def scan(self, text: str) -> GuardrailResult:
        """Scan ``text`` and return a verdict with redacted findings."""
        findings = []
        for rule, regex in self._compiled:
            match = regex.search(text)
            if match:
                findings.append(
                    GuardrailFinding(
                        rule=rule.name,
                        severity=rule.severity,
                        excerpt=_redact(match.group(0)),
                    )
                )
        return GuardrailResult(allowed=not findings, findings=tuple(findings))

# Architecture

This document explains *why* Sentinel is built the way it is. For what it is and
how to run it, see the [README](../README.md).

## Contents

- [Verifier, not enforcer](#verifier-not-enforcer)
- [The two-boundary model](#the-two-boundary-model)
- [Mock and live](#mock-and-live)
- [Module map](#module-map)
- [Key decisions](#key-decisions)
- [Going live](#going-live)

## Verifier, not enforcer

This is the load-bearing decision.

- An **enforcer** sits in the data path, in real time, and blocks or allows
  traffic. Its failure is a breach. The future L7 output guardrail is an example.
- A **verifier** sits outside, runs periodically, and observes whether the
  enforcers work. Its failure is a blind spot, not a breach.

Sentinel is strictly a verifier. It has no privileged real-time view of traffic;
a passing run is out-of-band evidence that the controls hold. Module docstrings
and the report text restate this so the tool cannot be mistaken for something in
the data path.

## The two-boundary model

Sentinel reasons about two boundaries that fail independently.

- **Egress containment (L3/L4)** controls *where* data can go. It is enforced
  elsewhere (Terraform / NAT). Sentinel probes whether outbound is sealed.
- **Output guardrail (L7)** controls *what* may leave. It is an in-path enforcer
  inside the VM. It does not exist yet and is out of scope; Sentinel is built to
  verify it once it does.

They are independent: a sealed network still leaks if allowed-channel content
carries secrets, and a perfect content filter still leaks if a NAT
misconfiguration opens a route. So they get separate abstractions
(`EgressChecker` and `ModelClient`) and separate checks in the report, each with
an explicit boundary label.

## Mock and live

There is no deployed target, so the whole probe path runs offline with zero
runtime dependencies (standard library only).

- Every boundary abstraction has a **mock** implementation (real, deterministic,
  exercised by the tests) and a **live** implementation (genuine standard-library
  code that would work against a real target, marked `LIVE —`, never exercised).
- The live paths exist now so the shape is proven and the mock-to-live switch is
  a configuration change rather than a re-architecture.
- The tests enforce this boundary: live classes are constructed but their network
  methods are never called.

## Module map

| Module                | Role                                  | Key point                                                                                       |
| --------------------- | ------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `interfaces.py`       | Boundary abstractions; mock + live    | One abstraction per boundary. `EgressResult.blocked` is the *verdict* (`True` = containment held), not a raw socket fact. |
| `guardrail.py`        | `OutputGuardrail` rule-based scanner  | A mock test fixture, **not** the in-path enforcer. Findings redact the matched secret.          |
| `config.py`           | Load and validate configuration       | The authorization boundary: fail-closed, explicit allowlist, no wildcards, no unknown keys.     |
| `probe.py`            | Orchestration and reporting           | Two checks, never merged. The report is a dataclass tree, so it serializes straight to JSON.    |
| `__main__.py`         | Command-line interface                | `--json`, `--config`; exit codes `0` / `1` / `2` for CI.                                        |
| `tests/test_probe.py` | Test suite                            | Mock-only and independent of the working directory.                                             |

## Key decisions

- **`blocked` is a verdict, not a fact.** Encoding "containment held" at the
  result type means the probe and report code never re-interpret raw outcomes,
  and the verifier stance — a *successful* connection is a *failure* — stays
  unambiguous.
- **Configuration is fail-closed.** A permissive loader is itself an attack
  surface: a typo'd key could silently disable a check, and a wildcard target
  could authorize probing the whole internet. Validation rejects anything not
  explicitly allowed and never coerces.
- **The egress allowlist is explicit.** The operator must enumerate exactly what
  Sentinel may touch. "Probe everything" is never authorized.
- **Guardrail findings are redacted.** A guardrail that echoed the secret it
  caught would re-leak it, so the fixture masks matches (e.g. `AK****…(len=20)`).
- **`run_probe` supports dependency injection.** This lets the tests drive the
  leak and mismatch paths deterministically with no network. Pure mock mode
  passes by construction, so the exit-code-1 path is tested by injecting a
  failing report.
- **src-layout with zero runtime dependencies.** Tests run against the installed
  package, avoiding "works locally, breaks once installed" gaps, and `pytest`
  stays in the `[dev]` extra only.

## Going live

1. Set `mode` to `live` and provide a real `model_endpoint` in a gitignored
   config file.
2. Deploy on a vantage point adjacent to the enclave, so egress attempts face the
   real network restrictions.
3. Once it exists, the in-path output guardrail replaces the `OutputGuardrail`
   fixture as the thing being verified, and the guardrail probe cases become real
   adversarial prompts.

No module is rewritten — each is wired to a live implementation that already
exists.

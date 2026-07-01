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

A verifier's worst failure is a **false pass** — reporting a control as holding
when it does not, or when the probe never actually determined the answer. So the
egress verdict is tri-state (`blocked` / leaked / **inconclusive**) rather than
boolean: a target counts as contained only on *positive* evidence (a silently
dropped connection). "Couldn't reach it" and "couldn't resolve it" are
inconclusive and fail the run. Mapping every failure to "contained" — the naive
design — would let a probe with broken DNS or no network of its own certify the
enclave as sealed.

## The two-boundary model

Sentinel reasons about two boundaries that fail independently.

- **Egress containment (L3/L4)** controls *where* data can go. On Google Cloud it
  is enforced by VPC firewall egress rules, Cloud NAT posture, and VPC Service
  Controls (all Terraform-defined) — not by Sentinel. Sentinel probes whether
  outbound is actually sealed, from a GCE/GKE vantage point inside the VPC.
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
  code that would work against a real GCP target, marked `LIVE —`).
- The live paths exist now so the shape is proven and the mock-to-live switch is
  a configuration change rather than a re-architecture.
- The tests make **no real network calls**. The live classes' verdict logic and
  untrusted-input handling are exercised offline via injected stdlib fakes
  (monkeypatched `socket` / `urllib`); they are never pointed at a deployed
  target. Testing the security-critical paths (the tri-state egress verdict, the
  response size cap) is deliberate — an untested fail-closed path is not one you
  can trust.

## Module map

| Module                | Role                                  | Key point                                                                                       |
| --------------------- | ------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `interfaces.py`       | Boundary abstractions; mock + live    | One abstraction per boundary. `EgressResult` is a *verdict*: `blocked` (`True` = containment held) plus `inconclusive` (probe couldn't determine — never a pass), not a raw socket fact. |
| `guardrail.py`        | `OutputGuardrail` rule-based scanner  | A mock test fixture, **not** the in-path enforcer. Findings redact the matched secret.          |
| `config.py`           | Load and validate configuration       | The authorization boundary: fail-closed, explicit allowlist, no wildcards, no unknown keys. Gates BOTH `egress_targets` and `model_endpoint` (GCP-metadata SSRF guard). |
| `probe.py`            | Orchestration and reporting           | Two checks, never merged. The report is a dataclass tree, so it serializes straight to JSON.    |
| `__main__.py`         | Command-line interface                | `--json`, `--config`; exit codes `0` / `1` / `2` for CI.                                        |
| `tests/test_probe.py` | Test suite                            | Mock-only and independent of the working directory.                                             |

## Key decisions

- **`blocked` is a verdict, not a fact, and it is tri-state.** Encoding the
  verdict at the result type means the probe and report code never re-interpret
  raw outcomes, and the verifier stance — a *successful* connection is a
  *failure* — stays unambiguous. The third state, `inconclusive`, exists so the
  probe can say "I could not determine this" instead of silently defaulting to a
  pass; the containment check fails closed on it.
- **Configuration is fail-closed.** A permissive loader is itself an attack
  surface: a typo'd key could silently disable a check, and a wildcard target
  could authorize probing the whole internet. Validation rejects anything not
  explicitly allowed and never coerces.
- **The egress allowlist is explicit.** The operator must enumerate exactly what
  Sentinel may touch. "Probe everything" is never authorized.
- **`model_endpoint` is inside the boundary, not beside it.** The live model
  client POSTs probe prompts to it, so it is a probe destination and is validated
  like one: `http(s)` only, no embedded credentials, and — because the target is
  Google Cloud — no pointing at the metadata server (`169.254.169.254` /
  `metadata.google.internal`), loopback, or link-local. That address hands out
  the workload's service-account token and is the standard SSRF pivot; internal
  GCP hosts stay allowed.
- **Untrusted responses are bounded.** The endpoint is, by the threat model,
  possibly compromised, so the live model client caps the response read (1 MiB)
  and type-checks `output` before returning it — an oversized or malformed body
  raises rather than exhausting memory or propagating garbage.
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

1. Set `mode` to `live` and provide a real `model_endpoint` (subject to the
   endpoint guard) in a gitignored config file.
2. Deploy on a vantage point adjacent to the enclave — a GCE/GKE workload inside
   the enclave's VPC with no external IP — so egress attempts face the real VPC
   firewall / Cloud NAT restrictions. Leaks and inconclusive targets both fail
   the run.
3. Once it exists, the in-path output guardrail replaces the `OutputGuardrail`
   fixture as the thing being verified, and the guardrail probe cases become real
   adversarial prompts.

No module is rewritten — each is wired to a live implementation that already
exists.

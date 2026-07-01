# Sentinel

Sentinel is an out-of-band boundary probe for the **Evil Resident** enclave — a
Terraform-defined, zero-trust **Google Cloud** environment (a locked-down VPC)
that hosts a self-hosted, unrestricted LLM.

**Sentinel is a verifier, not an enforcer.** It runs periodically from *outside*
the enclave and checks whether security controls hold. It is never in the live
data path and cannot inspect real traffic in real time. A passing run is
*evidence* the controls work — not protection in itself.

Because it is a verifier, its cardinal rule is: **never report a control as
holding when it merely failed to check.** The egress probe is tri-state — a
target is a *pass* only when it is positively blocked; a reachable target is a
**leak** and an undetermined one (DNS failure, no route, broken probe host) is
**inconclusive**, and both fail the run (fail-closed).

The current build runs entirely against mocks, with zero runtime dependencies
(standard library only). Live implementations are written but not pointed at a
real target (there is no deployment yet). See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design rationale.

## Contents

- [Why Sentinel exists](#why-sentinel-exists)
- [The two boundaries](#the-two-boundaries)
- [Install](#install)
- [Usage](#usage)
- [Exit codes](#exit-codes)
- [Configuration](#configuration)
- [Testing](#testing)
- [Going live](#going-live)
- [License](#license)

## Why Sentinel exists

The model is deliberately unrestricted, so the security problem is **containing
what can leave the enclave**. There are two independent risks:

1. **Network exfiltration** — a process inside tries to send data somewhere
   outbound. Addressed by *egress containment*: with no route out, nothing
   leaves regardless of intent.
2. **Disallowed content in legitimate output** — even over an allowed channel,
   the model's response might contain secrets or prohibited content. Addressed
   by an *output guardrail*, which does not exist yet and is out of scope here.

Sentinel does not defend against either risk in real time. It probes whether the
defenses are present and holding.

## The two boundaries

The two controls are distinct and fail independently. Conflating them anywhere is
a design error.

|                | Egress containment                     | Output guardrail                       |
| -------------- | -------------------------------------- | -------------------------------------- |
| OSI layer      | L3/L4 (addresses, ports)               | L7 (the content itself)                |
| Controls       | *Where* data can go                    | *What* may leave                       |
| Enforced by    | GCP VPC firewall egress rules / Cloud NAT / VPC Service Controls (Terraform) | An in-path enforcer inside the VM |
| Exists today?  | Yes — Sentinel probes it               | No — out of scope for this build       |
| Sentinel's job | Probe whether outbound is sealed       | Verify it once it exists               |

Sealing the network does nothing about bad content on an allowed channel;
scrubbing content does nothing about an unintended network route.

Sentinel's egress checks only mean something when it runs from a vantage point
subject to the same network restrictions a real escaping process would face — on
GCP, a GCE/GKE workload inside the enclave's VPC, with no external IP, bound by
the same VPC firewall egress rules and Cloud NAT posture. Run from somewhere with
a freer route out (a privileged host, a different subnet), a "blocked" result
would prove nothing.

## Install

```sh
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

The runtime has no third-party dependencies. `pytest` is installed only through
the optional `[dev]` extra.

## Usage

```sh
sentinel --config config.mock.json           # text report
sentinel --config config.mock.json --json    # JSON report
python -m sentinel --config config.mock.json  # equivalent module form
sentinel --version
```

`--config` defaults to `config.mock.json`, resolved relative to the working
directory.

Example report:

```
Sentinel probe report  [mode=mock]  =>  PASS
(verifier, not enforcer — evidence the controls hold, not protection)
(MOCK — results are SIMULATED in-process; this exercises the logic, not a live GCP network or a real model surface)

[PASS] egress_containment  —  L3/L4 network egress
       all 2 target(s) blocked; egress containment holds
         - malicious.example.com:443: blocked  (mock: simulated block)
         - exfil.example.net:80: blocked  (mock: simulated block)

[PASS] output_guardrail  —  L7 output guardrail (mock-fixture verification)
       2 case(s) behaved as expected (mock-fixture self-check; not a live enforcer)
         - probe:benign-greeting: expected_blocked=False observed=False [ok] findings=[]
         - probe:adversarial-exfil: expected_blocked=True observed=True [ok] findings=['aws_access_key_id']
```

In `live` mode a target Sentinel can neither reach nor rule out is reported as
`INCONCLUSIVE` and fails the run — the probe never upgrades "couldn't tell" into
"contained".

## Exit codes

The CLI returns a CI-friendly exit code. Gate a pipeline by failing on any
non-zero result.

| Code | Meaning                                            |
| ---- | -------------------------------------------------- |
| `0`  | All checks passed                                            |
| `1`  | A probe check failed — a boundary leaked OR was inconclusive |
| `2`  | Configuration or usage error                                 |

## Configuration

`config.py` is the authorization boundary: it decides what Sentinel is permitted
to probe, and it is fail-closed — anything malformed, over-broad, or unrecognized
is rejected rather than guessed at.

```json
{
  "version": 1,
  "mode": "mock",
  "egress_targets": ["host:port", "..."],
  "model_endpoint": "https://..."
}
```

- `mode` — `mock` or `live`. Selects the implementations used.
- `egress_targets` — an explicit allowlist of `host:port` values. Wildcards and
  CIDR-all forms (`*`, `0.0.0.0/0`) are refused; "probe everything" is never
  authorized.
- `model_endpoint` — required in live mode, ignored (but still validated) in mock
  mode. It is a probe destination, so it goes through the same boundary: it must
  be an `http(s)` URL with no embedded credentials, and it may **not** point at
  the GCP metadata server (`169.254.169.254` / `metadata.google.internal`),
  loopback, or a link-local address — the metadata server hands out the
  workload's service-account token and is the classic SSRF exfiltration pivot.
  Legitimate internal GCP hosts (RFC1918, Private Service Connect, internal load
  balancers, `*.run.app`) are allowed.
- Keys beginning with `_` (such as `_comment`) are allowed and ignored. Any other
  unknown key is an error.

`config.mock.json` runs offline against the mock implementations.
`config.live.example.json` is a template for a real target — copy it to
`config.local.json` (gitignored) and fill in the values.

## Testing

```sh
pytest -q
```

The suite makes **no real network calls**: the live implementations' verdict
mapping and input handling are exercised offline through injected standard-library
fakes (monkeypatched `socket` / `urllib`), never pointed at a deployed target. It
is also independent of the working directory.

## Going live

When a real target is deployed, switching from mock to live is a configuration
change, not a rewrite:

1. Set `mode` to `live` and provide a real `model_endpoint` in a gitignored
   config file (subject to the endpoint guard above — no metadata/loopback host).
2. Run Sentinel from a vantage point adjacent to the enclave — a GCE/GKE workload
   inside the enclave's VPC, no external IP — so its egress attempts face the real
   VPC firewall / Cloud NAT restrictions. A leak fails the run; a target the probe
   can neither reach nor rule out is reported `INCONCLUSIVE` and also fails
   (fail-closed).
3. Once the in-path output guardrail exists, it replaces the bundled
   `OutputGuardrail` fixture as the thing being verified, and the guardrail probe
   cases become real adversarial prompts.

> **Note — endpoint auth is required before a live run and is not yet
> implemented.** `LiveModelClient` sends no credential; a GCP-protected model
> surface (IAP / internal load balancer / Cloud Run + IAM) needs an
> `Authorization: Bearer <identity-token>` header and a config field or token
> source to supply it. This must be added when the real endpoint is known.

The live code paths already exist, so this is wiring rather than new
architecture. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

Released under the MIT License. See [LICENSE](LICENSE).

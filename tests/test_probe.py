"""Sentinel test suite — comprehensive, deterministic, NO real network I/O.

Properties this suite upholds:
  - No real network: no test opens a real socket or makes a real HTTP call. The
    Live implementations are exercised ONLY through injected stdlib fakes
    (monkeypatched ``socket`` / ``urllib``) to prove their verdict mapping and
    input handling; they are never pointed at a deployed target.
  - cwd-independent: configs come from tmp_path; committed config files are
    located via __file__, never the working directory.

Deployment target is Google Cloud; the offline fakes stand in for a GCE/GKE
vantage point and the enclave model surface.
"""

from __future__ import annotations

import json
import socket as socket_mod
import urllib.request as urllib_request
from pathlib import Path

import pytest

from sentinel import __version__
import sentinel.__main__ as cli
from sentinel.config import (
    Config,
    ConfigError,
    SUPPORTED_VERSION,
    load_config,
    validate_config,
)
from sentinel.guardrail import GuardrailRule, OutputGuardrail
from sentinel.interfaces import (
    EgressChecker,
    EgressResult,
    LiveEgressChecker,
    LiveModelClient,
    ModelClient,
    MockEgressChecker,
    MockModelClient,
)
from sentinel.probe import (
    GuardrailProbeCase,
    ProbeReport,
    build_components,
    check_egress_containment,
    check_output_guardrail,
    run_probe,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
AWS_KEY = "AKIAABCDEFGHIJKLMNOP"  # fake, fixed test value


# --------------------------------------------------------------------------- #
# package / interfaces                                                         #
# --------------------------------------------------------------------------- #
def test_version_is_nonempty_string():
    assert isinstance(__version__, str) and __version__


@pytest.mark.parametrize("abstract", [EgressChecker, ModelClient])
def test_abstractions_cannot_be_instantiated(abstract):
    with pytest.raises(TypeError):
        abstract()


def test_mock_egress_sealed_by_default():
    r = MockEgressChecker().attempt("evil.example:443")
    assert r.blocked is True and r.destination == "evil.example:443"


def test_mock_egress_simulated_leak():
    r = MockEgressChecker(reachable=["leak.example:443"]).attempt("leak.example:443")
    assert r.blocked is False


def test_mock_egress_deterministic():
    ec = MockEgressChecker()
    assert ec.attempt("x:1") == ec.attempt("x:1")


def test_mock_model_mapped_and_default():
    mc = MockModelClient(responses={"hi": "hello"}, default="DEF")
    assert mc.generate("hi") == "hello"
    assert mc.generate("unknown") == "DEF"


def test_live_classes_construct_cleanly():
    # Construction touches no network; behavior is exercised below via fakes.
    assert isinstance(LiveEgressChecker(), LiveEgressChecker)
    assert isinstance(LiveModelClient(endpoint="http://x/y"), LiveModelClient)


# --------------------------------------------------------------------------- #
# live paths — verdict mapping / input handling (offline, injected fakes)      #
# No real socket or HTTP call happens: socket/urllib are monkeypatched.        #
# --------------------------------------------------------------------------- #
class _FakeConn:
    """Stand-in for a successful socket connection context manager."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_live_egress_success_is_leak(monkeypatch):
    monkeypatch.setattr(socket_mod, "create_connection", lambda *a, **k: _FakeConn())
    r = LiveEgressChecker().attempt("known-bad.example:443")
    assert r.blocked is False and r.inconclusive is False  # reachable => LEAK


def test_live_egress_timeout_is_contained(monkeypatch):
    def boom(*a, **k):
        raise TimeoutError("timed out")

    monkeypatch.setattr(socket_mod, "create_connection", boom)
    r = LiveEgressChecker().attempt("known-bad.example:443")
    assert r.blocked is True and r.inconclusive is False  # silent drop => contained


@pytest.mark.parametrize(
    "exc",
    [
        ConnectionRefusedError("refused"),  # ambiguous RST
        socket_mod.gaierror("name resolution failed"),  # DNS down / broken probe
        OSError("network is unreachable"),  # no local route
    ],
)
def test_live_egress_ambiguous_failures_are_inconclusive(monkeypatch, exc):
    def boom(*a, **k):
        raise exc

    monkeypatch.setattr(socket_mod, "create_connection", boom)
    r = LiveEgressChecker().attempt("known-bad.example:443")
    # The critical fix: a non-answer is NEVER reported as "contained".
    assert r.inconclusive is True and r.blocked is False


class _FakeResp:
    """Stand-in for the urlopen() response context manager."""

    def __init__(self, data: bytes):
        self._data = data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n: int = -1) -> bytes:
        return self._data[:n] if n is not None and n >= 0 else self._data


def _fake_urlopen(data: bytes):
    return lambda *a, **k: _FakeResp(data)


def test_live_model_happy_path(monkeypatch):
    monkeypatch.setattr(urllib_request, "urlopen", _fake_urlopen(b'{"output": "hi"}'))
    assert LiveModelClient(endpoint="https://model.internal/gen").generate("p") == "hi"


def test_live_model_rejects_oversize_response(monkeypatch):
    big = b'{"output": "' + b"x" * (LiveModelClient.MAX_RESPONSE_BYTES + 16) + b'"}'
    monkeypatch.setattr(urllib_request, "urlopen", _fake_urlopen(big))
    with pytest.raises(ValueError):
        LiveModelClient(endpoint="https://model.internal/gen").generate("p")


@pytest.mark.parametrize("body", [b'{"output": 123}', b"[1, 2, 3]"])
def test_live_model_rejects_bad_response_shape(monkeypatch, body):
    monkeypatch.setattr(urllib_request, "urlopen", _fake_urlopen(body))
    with pytest.raises(ValueError):
        LiveModelClient(endpoint="https://model.internal/gen").generate("p")


# --------------------------------------------------------------------------- #
# guardrail (mock fixture)                                                     #
# --------------------------------------------------------------------------- #
def test_guardrail_allows_clean_output():
    assert OutputGuardrail().scan("the weather is nice").allowed is True


def test_guardrail_blocks_and_redacts_secret():
    result = OutputGuardrail().scan(f"key={AWS_KEY}")
    assert result.allowed is False
    assert any(f.rule == "aws_access_key_id" for f in result.findings)
    # The raw secret must never appear in a finding.
    assert all(AWS_KEY not in f.excerpt for f in result.findings)


def test_guardrail_detects_multiple_rules():
    text = f"{AWS_KEY} and CONFIDENTIAL note"
    rules = {f.rule for f in OutputGuardrail().scan(text).findings}
    assert {"aws_access_key_id", "internal_marker"} <= rules


def test_guardrail_custom_rules():
    g = OutputGuardrail(rules=[GuardrailRule("digits", r"\d{3}")])
    assert g.scan("abc").allowed is True
    assert g.scan("abc123").allowed is False


def test_guardrail_deterministic():
    g = OutputGuardrail()
    assert g.scan(AWS_KEY) == g.scan(AWS_KEY)


def test_guardrail_bad_pattern_fails_at_construction():
    with pytest.raises(Exception):  # re.error
        OutputGuardrail(rules=[GuardrailRule("bad", "(")])


# --------------------------------------------------------------------------- #
# config (authorization boundary)                                             #
# --------------------------------------------------------------------------- #
def test_config_valid_mock():
    cfg = validate_config({"version": SUPPORTED_VERSION, "mode": "mock"})
    assert cfg.mode == "mock" and cfg.egress_targets == ()


def test_config_dedupes_and_normalizes_targets():
    cfg = validate_config(
        {
            "version": 1,
            "mode": "mock",
            "egress_targets": ["a.example:443", "a.example:443", "b.example:80"],
        }
    )
    assert cfg.egress_targets == ("a.example:443", "b.example:80")


def test_config_allows_comment_keys():
    cfg = validate_config({"_comment": "hi", "version": 1, "mode": "mock"})
    assert cfg.mode == "mock"


def test_config_live_requires_endpoint():
    cfg = validate_config(
        {"version": 1, "mode": "live", "model_endpoint": "https://x/y"}
    )
    assert cfg.model_endpoint == "https://x/y"


@pytest.mark.parametrize(
    "raw",
    [
        [1, 2, 3],  # not an object
        {"mode": "mock"},  # missing version
        {"version": True, "mode": "mock"},  # bool version
        {"version": 2, "mode": "mock"},  # unsupported version
        {"version": 1},  # missing mode
        {"version": 1, "mode": "prod"},  # bad mode
        {"version": 1, "mode": "mock", "oops": 1},  # unknown key
        {"version": 1, "mode": "mock", "egress_targets": ["*:443"]},  # wildcard
        {"version": 1, "mode": "mock", "egress_targets": ["0.0.0.0/0:443"]},  # cidr
        {"version": 1, "mode": "mock", "egress_targets": ["host.only"]},  # no port
        {"version": 1, "mode": "mock", "egress_targets": ["h:99999"]},  # bad port
        {"version": 1, "mode": "live"},  # live without endpoint
        {"version": 1, "mode": "live", "model_endpoint": "ftp://x/y"},  # non-http
        # model_endpoint SSRF / malformed guards (GCP deployment):
        {"version": 1, "mode": "live",
         "model_endpoint": "http://169.254.169.254/computeMetadata/v1/"},  # gcp metadata IP
        {"version": 1, "mode": "live",
         "model_endpoint": "http://metadata.google.internal/"},  # gcp metadata DNS
        {"version": 1, "mode": "live",
         "model_endpoint": "http://127.0.0.1:8080/"},  # loopback
        {"version": 1, "mode": "live",
         "model_endpoint": "https://user:pass@host.example/"},  # embedded creds
        {"version": 1, "mode": "live",
         "model_endpoint": "https://host.example:0/"},  # port out of range
        {"version": 1, "mode": "live",
         "model_endpoint": "https:///no-host"},  # missing host
    ],
)
def test_config_rejection_matrix(raw):
    with pytest.raises(ConfigError):
        validate_config(raw)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://model.internal.example/generate",  # internal DNS name
        "http://10.8.0.5:8080/generate",  # RFC1918 (private, allowed on GCP)
        "https://evil-resident-model.run.app/generate",  # Cloud Run host
    ],
)
def test_config_endpoint_allows_legitimate_gcp_targets(endpoint):
    cfg = validate_config(
        {"version": 1, "mode": "live", "model_endpoint": endpoint}
    )
    assert cfg.model_endpoint == endpoint


def test_load_config_roundtrip(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"version": 1, "mode": "mock", "egress_targets": ["a:443"]}))
    assert load_config(p).egress_targets == ("a:443",)


def test_load_config_missing_file(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.json")


def test_load_config_invalid_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    with pytest.raises(ConfigError):
        load_config(p)


@pytest.mark.parametrize("name", ["config.mock.json", "config.live.example.json"])
def test_committed_config_files_validate(name):
    cfg = load_config(REPO_ROOT / name)
    assert cfg.version == SUPPORTED_VERSION


# --------------------------------------------------------------------------- #
# probe checks                                                                 #
# --------------------------------------------------------------------------- #
def test_egress_check_passes_when_all_blocked():
    r = check_egress_containment(MockEgressChecker(), ("a:443", "b:80"))
    assert r.passed is True and r.boundary == "L3/L4 network egress"


def test_egress_check_fails_on_leak():
    r = check_egress_containment(
        MockEgressChecker(reachable=["b:80"]), ("a:443", "b:80")
    )
    assert r.passed is False and "LEAK" in r.summary


def test_egress_check_empty_targets_vacuous():
    r = check_egress_containment(MockEgressChecker(), ())
    assert r.passed is True and "vacuously" in r.summary


class _InconclusiveChecker(EgressChecker):
    """Returns an undetermined verdict for every destination."""

    def attempt(self, destination):
        return EgressResult(destination, blocked=False, inconclusive=True,
                            detail="stub: undetermined")


def test_egress_check_fails_closed_on_inconclusive():
    # A probe that cannot determine containment must FAIL the check, never pass.
    r = check_egress_containment(_InconclusiveChecker(), ("a:443", "b:80"))
    assert r.passed is False and "INCONCLUSIVE" in r.summary


def test_guardrail_check_passes_on_expected_behavior():
    model = MockModelClient(responses={"bad": AWS_KEY, "good": "hi"}, default="hi")
    cases = (
        GuardrailProbeCase("good", expect_blocked=False),
        GuardrailProbeCase("bad", expect_blocked=True),
    )
    r = check_output_guardrail(model, OutputGuardrail(), cases)
    assert r.passed is True


def test_guardrail_check_fails_on_mismatch():
    model = MockModelClient(responses={"bad": AWS_KEY}, default="x")
    # Expectation is wrong on purpose: secret present but we expect not-blocked.
    cases = (GuardrailProbeCase("bad", expect_blocked=False),)
    r = check_output_guardrail(model, OutputGuardrail(), cases)
    assert r.passed is False and "MISMATCH" in r.summary


# --------------------------------------------------------------------------- #
# orchestration                                                                #
# --------------------------------------------------------------------------- #
def test_run_probe_mock_passes():
    cfg = Config(mode="mock", version=1, egress_targets=("malicious.example:443",))
    report = run_probe(cfg)
    assert isinstance(report, ProbeReport)
    assert report.passed is True
    assert [c.name for c in report.checks] == ["egress_containment", "output_guardrail"]


def test_run_probe_injected_leak_fails():
    cfg = Config(mode="mock", version=1, egress_targets=("a:443", "leak:443"))
    components = (
        MockEgressChecker(reachable=["leak:443"]),
        MockModelClient(default="clean"),
        OutputGuardrail(),
        (),
    )
    assert run_probe(cfg, components=components).passed is False


def test_build_components_mock_types():
    checker, model, guardrail, cases = build_components(
        Config(mode="mock", version=1)
    )
    assert isinstance(checker, MockEgressChecker)
    assert isinstance(model, MockModelClient)
    assert isinstance(guardrail, OutputGuardrail)
    assert len(cases) >= 1


def test_build_components_live_types_not_probed():
    # Construct live components but never call their network methods.
    checker, model, _, _ = build_components(
        Config(mode="live", version=1, model_endpoint="https://x/y")
    )
    assert isinstance(checker, LiveEgressChecker)
    assert isinstance(model, LiveModelClient)


# --------------------------------------------------------------------------- #
# CLI / exit-code contract                                                     #
# --------------------------------------------------------------------------- #
def _write_mock_config(tmp_path) -> str:
    p = tmp_path / "config.mock.json"
    p.write_text(json.dumps({"version": 1, "mode": "mock", "egress_targets": ["a:443"]}))
    return str(p)


def test_cli_version(capsys):
    assert cli.main(["--version"]) == 0
    assert "sentinel" in capsys.readouterr().out


def test_cli_text_run_exit_zero(tmp_path, capsys):
    assert cli.main(["--config", _write_mock_config(tmp_path)]) == 0
    assert "PASS" in capsys.readouterr().out


def test_cli_json_run_is_parseable(tmp_path, capsys):
    rc = cli.main(["--config", _write_mock_config(tmp_path), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["mode"] == "mock" and payload["passed"] is True
    assert {c["name"] for c in payload["checks"]} == {
        "egress_containment",
        "output_guardrail",
    }


def test_cli_config_error_exit_two(tmp_path):
    assert cli.main(["--config", str(tmp_path / "missing.json")]) == 2


def test_cli_probe_failure_exit_one(tmp_path, monkeypatch):
    from sentinel.probe import CheckResult

    failing = ProbeReport(
        mode="mock",
        passed=False,
        checks=(CheckResult("egress_containment", "L3/L4", False, "forced"),),
    )
    monkeypatch.setattr(cli, "run_probe", lambda cfg: failing)
    assert cli.main(["--config", _write_mock_config(tmp_path)]) == 1

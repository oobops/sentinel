"""Configuration loading and validation — the AUTHORIZATION BOUNDARY.

config.py decides what Sentinel is *permitted* to probe. Treat validation here
as a security boundary, not a convenience loader: it is fail-closed and refuses
to coerce. Anything malformed, over-broad, or unrecognized is REJECTED rather
than guessed at, because a permissive loader is itself an attack surface — a
typo'd key that silently disables a check, or a wildcard target that authorizes
probing the whole internet, would both be security failures.

Deployment target is Google Cloud: the enclave is a Terraform-defined GCP VPC
whose egress is sealed by VPC firewall egress rules, Cloud NAT posture, and (for
Google APIs) VPC Service Controls. BOTH kinds of probe destination pass through
this boundary — the ``egress_targets`` allowlist AND ``model_endpoint``. The
endpoint is not exempt: it is validated as an authorized destination, with an
explicit guard against the GCP metadata server (169.254.169.254 /
metadata.google.internal), the classic SSRF pivot for service-account-token
theft.

Schema (version 1):
  {
    "version": 1,                 # int, must equal SUPPORTED_VERSION
    "mode": "mock" | "live",      # which interface implementations to use
    "egress_targets": [           # destinations Sentinel is authorized to probe
      "host:port", ...            # explicit host:port only; no wildcards/CIDR
    ],
    "model_endpoint": "https://…" # REQUIRED in live mode; optional/ignored in
                                  # mock. Validated (no metadata/loopback/
                                  # link-local SSRF targets, no embedded creds)
                                  # whenever present.
  }
Keys beginning with "_" (e.g. "_comment") are allowed and ignored. Any other
unknown top-level key is an error.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

__all__ = ["Config", "ConfigError", "SUPPORTED_VERSION", "VALID_MODES",
           "validate_config", "load_config"]

SUPPORTED_VERSION = 1
VALID_MODES = ("mock", "live")

# host:port — host is a label/IPv4 (no wildcards), port is 1..65535.
# IPv6 (bracketed) is intentionally out of scope for the mock schema.
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")
# Over-broad host tokens that must never be accepted as a probe target.
_FORBIDDEN_HOSTS = {"*", "0.0.0.0", "::", "::/0", "0.0.0.0/0"}

# Google Cloud metadata server. On GCE/GKE this endpoint hands out the
# instance's service-account OAuth token; it is the canonical SSRF pivot for
# credential theft, and it is never a legitimate model endpoint. The link-local
# IP (169.254.169.254) is also caught by the range check below; the DNS names
# are blocked here because a name never hits that range check.
_GCP_METADATA_HOSTS = {"metadata.google.internal", "metadata", "169.254.169.254"}


class ConfigError(Exception):
    """Raised when configuration is missing, malformed, or over-broad."""


@dataclass(frozen=True)
class Config:
    mode: str
    version: int
    egress_targets: tuple[str, ...] = ()
    model_endpoint: str | None = None


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigError(message)


def _validate_target(target) -> str:
    """Validate one egress target ('host:port'), returning it normalized."""
    _require(isinstance(target, str) and target.strip(),
             f"egress target must be a non-empty string, got {target!r}")
    _require("/" not in target, f"CIDR/path forms are not allowed: {target!r}")

    host, sep, port_str = target.rpartition(":")
    _require(sep == ":" and host and port_str,
             f"egress target must be 'host:port', got {target!r}")
    _require(host not in _FORBIDDEN_HOSTS and "*" not in host,
             f"over-broad / wildcard egress target is not authorized: {target!r}")
    _require(bool(_HOST_RE.match(host)),
             f"invalid host in egress target: {target!r}")

    _require(port_str.isdigit(), f"port must be numeric in {target!r}")
    port = int(port_str)
    _require(1 <= port <= 65535, f"port out of range (1-65535) in {target!r}")
    return f"{host}:{port}"


def _validate_endpoint(endpoint) -> str:
    """Validate ``model_endpoint`` as an authorized live probe destination.

    The live model client POSTs probe prompts to this URL, so it is a probe
    destination just like an egress target and belongs inside the authorization
    boundary — not exempt from it. On Google Cloud the dangerous case is an
    endpoint pointed (by typo or tampering) at the GCE/GKE metadata server, which
    would leak the workload's service-account token. We reject that class of
    target while still allowing legitimate INTERNAL enclave hosts (RFC1918 /
    Private Service Connect / internal load balancers), which are normal on GCP.
    """
    _require(isinstance(endpoint, str) and endpoint.strip(),
             "'model_endpoint' must be a non-empty string")
    parsed = urlparse(endpoint)
    _require(parsed.scheme in ("http", "https"),
             "'model_endpoint' must be an http(s) URL")
    _require(not parsed.username and not parsed.password,
             "'model_endpoint' must not embed credentials (user:pass@)")
    host = parsed.hostname
    _require(bool(host), "'model_endpoint' must include a host")

    _require(host.lower() not in _GCP_METADATA_HOSTS,
             f"'model_endpoint' targets the GCP metadata server: {host!r}")

    # Reject loopback and link-local IP literals (link-local covers the metadata
    # IP). Other private ranges stay allowed: the enclave surface is internal on
    # GCP by design.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        _require(not (ip.is_loopback or ip.is_link_local or ip.is_unspecified),
                 f"'model_endpoint' targets a loopback/link-local address: {host!r}")

    # ``parsed.port`` raises ValueError on a malformed port; surface it as a
    # ConfigError rather than an opaque crash.
    try:
        port = parsed.port
    except ValueError as exc:
        raise ConfigError(f"'model_endpoint' has an invalid port: {endpoint!r}") from exc
    if port is not None:
        _require(1 <= port <= 65535,
                 f"'model_endpoint' port out of range (1-65535): {endpoint!r}")
    return endpoint


def validate_config(raw) -> Config:
    """Validate a raw config dict and return a frozen ``Config``.

    Fail-closed: raises ``ConfigError`` on anything not explicitly allowed.
    """
    _require(isinstance(raw, dict), "config root must be a JSON object")

    known = {"version", "mode", "egress_targets", "model_endpoint"}
    unknown = [k for k in raw if not k.startswith("_") and k not in known]
    _require(not unknown, f"unknown config key(s): {sorted(unknown)}")

    # version — reject unknown versions rather than guessing compatibility.
    _require("version" in raw, "config is missing 'version'")
    version = raw["version"]
    _require(isinstance(version, int) and not isinstance(version, bool),
             "'version' must be an integer")
    _require(version == SUPPORTED_VERSION,
             f"unsupported config version {version} (expected {SUPPORTED_VERSION})")

    # mode — must be explicit and known.
    _require("mode" in raw, "config is missing 'mode'")
    mode = raw["mode"]
    _require(mode in VALID_MODES, f"'mode' must be one of {VALID_MODES}, got {mode!r}")

    # egress_targets — explicit, validated, de-duplicated allowlist.
    targets_raw = raw.get("egress_targets", [])
    _require(isinstance(targets_raw, list), "'egress_targets' must be a list")
    seen: list[str] = []
    for t in targets_raw:
        norm = _validate_target(t)
        if norm not in seen:
            seen.append(norm)
    egress_targets = tuple(seen)

    # model_endpoint — required in live mode, optional (ignored) in mock. When
    # present it is validated as an authorized probe destination (the live model
    # client POSTs to it), including a GCP-metadata SSRF guard. Validating it even
    # in mock mode keeps a mock config from silently carrying an unsafe endpoint
    # that a later flip to live mode would trust.
    endpoint = raw.get("model_endpoint")
    if endpoint is not None:
        endpoint = _validate_endpoint(endpoint)
    if mode == "live":
        _require(endpoint is not None, "live mode requires 'model_endpoint'")

    return Config(mode=mode, version=version,
                  egress_targets=egress_targets, model_endpoint=endpoint)


def load_config(path) -> Config:
    """Load and validate config from a JSON file path."""
    path = Path(path)
    _require(path.is_file(), f"config file not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON in {path}: {exc}") from exc
    return validate_config(raw)

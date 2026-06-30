"""Configuration loading and validation — the AUTHORIZATION BOUNDARY.

config.py decides what Sentinel is *permitted* to probe. Treat validation here
as a security boundary, not a convenience loader: it is fail-closed and refuses
to coerce. Anything malformed, over-broad, or unrecognized is REJECTED rather
than guessed at, because a permissive loader is itself an attack surface — a
typo'd key that silently disables a check, or a wildcard target that authorizes
probing the whole internet, would both be security failures.

Schema (version 1):
  {
    "version": 1,                 # int, must equal SUPPORTED_VERSION
    "mode": "mock" | "live",      # which interface implementations to use
    "egress_targets": [           # destinations Sentinel is authorized to probe
      "host:port", ...            # explicit host:port only; no wildcards/CIDR
    ],
    "model_endpoint": "https://…" # REQUIRED in live mode; optional/ignored in mock
  }
Keys beginning with "_" (e.g. "_comment") are allowed and ignored. Any other
unknown top-level key is an error.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

__all__ = ["Config", "ConfigError", "SUPPORTED_VERSION", "VALID_MODES",
           "validate_config", "load_config"]

SUPPORTED_VERSION = 1
VALID_MODES = ("mock", "live")

# host:port — host is a label/IPv4 (no wildcards), port is 1..65535.
# IPv6 (bracketed) is intentionally out of scope for the mock schema.
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")
# Over-broad host tokens that must never be accepted as a probe target.
_FORBIDDEN_HOSTS = {"*", "0.0.0.0", "::", "::/0", "0.0.0.0/0"}


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

    # model_endpoint — required in live mode, optional (ignored) in mock.
    endpoint = raw.get("model_endpoint")
    if endpoint is not None:
        _require(isinstance(endpoint, str) and endpoint.startswith(("http://", "https://")),
                 "'model_endpoint' must be an http(s) URL")
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

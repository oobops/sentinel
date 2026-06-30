"""Sentinel CLI entrypoint.

Loads config (the authorization boundary), runs the probe, renders a report as
text or JSON, and returns a CI-friendly exit code:

  0  all checks passed
  1  a probe check failed (a boundary did not hold as expected)
  2  config / usage error

Sentinel is a verifier: a passing run is evidence the controls hold, gathered
out-of-band — not real-time protection.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from sentinel import __version__
from sentinel.config import ConfigError, load_config
from sentinel.probe import run_probe

EXIT_OK = 0
EXIT_PROBE_FAILED = 1
EXIT_CONFIG_ERROR = 2


def _render_text(report) -> None:
    status = "PASS" if report.passed else "FAIL"
    print(f"Sentinel probe report  [mode={report.mode}]  =>  {status}")
    print("(verifier, not enforcer — evidence the controls hold, not protection)")
    for chk in report.checks:
        mark = "PASS" if chk.passed else "FAIL"
        print(f"\n[{mark}] {chk.name}  —  {chk.boundary}")
        print(f"       {chk.summary}")
        for t in chk.targets:
            state = "blocked" if t.blocked else "LEAKED"
            print(f"         - {t.target}: {state}  ({t.detail})")
        for c in chk.cases:
            state = "ok" if c.ok else "MISMATCH"
            print(
                f"         - {c.prompt}: expected_blocked={c.expected_blocked} "
                f"observed={c.observed_blocked} [{state}] findings={list(c.findings)}"
            )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Out-of-band boundary probe for the Evil Resident enclave "
        "(verifier, not enforcer).",
    )
    parser.add_argument(
        "--config",
        default="config.mock.json",
        help="path to a config file (default: config.mock.json, relative to cwd)",
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="emit the report as JSON instead of text",
    )
    parser.add_argument(
        "--version", action="store_true", help="print version and exit"
    )
    return parser


def main(argv=None) -> int:
    """Console entrypoint. Returns a process exit code."""
    args = _build_parser().parse_args(argv)

    if args.version:
        print(f"sentinel {__version__}")
        return EXIT_OK

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    report = run_probe(config)

    if args.as_json:
        print(json.dumps(asdict(report), indent=2))
    else:
        _render_text(report)

    return EXIT_OK if report.passed else EXIT_PROBE_FAILED


if __name__ == "__main__":
    raise SystemExit(main())

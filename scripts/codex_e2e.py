#!/usr/bin/env python3
"""Run CodexCLI E2E checks against BridgeWarden."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, Iterable, List, Sequence

from bridgewarden.e2e import extract_guard_results


def _load_cases(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "cases" in data:
        cases = data["cases"]
    else:
        cases = data
    if not isinstance(cases, list):
        raise ValueError("cases must be a list")
    return cases


def _expected_decisions(value: object) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise ValueError("expected_decision must be a string or list of strings")


def _run_codex(
    prompt: str,
    codex_bin: str,
    repo_root: Path,
    extra_args: Sequence[str],
) -> subprocess.CompletedProcess[str]:
    cmd = [
        codex_bin,
        "exec",
        "--json",
        "--full-auto",
        "--cd",
        str(repo_root),
        *extra_args,
    ]
    return subprocess.run(
        cmd,
        input=prompt,
        text=True,
        capture_output=True,
    )


def _select_cases(
    cases: Iterable[Dict[str, Any]],
    include_network: bool,
    only: List[str],
) -> List[Dict[str, Any]]:
    selected = []
    for case in cases:
        if only and case.get("name") not in only:
            continue
        if case.get("requires_network") and not include_network:
            continue
        selected.append(case)
    return selected


def _run_case(
    case: Dict[str, Any],
    codex_bin: str,
    repo_root: Path,
    extra_args: Sequence[str],
) -> Dict[str, Any]:
    prompt = case["prompt"]
    result = _run_codex(prompt, codex_bin, repo_root, extra_args)
    stdout_lines = result.stdout.splitlines()
    guard_results = extract_guard_results(stdout_lines)
    return {
        "case": case,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "guard_results": guard_results,
    }


def _print_failure(message: str) -> None:
    print(f"[FAIL] {message}")


def _print_ok(message: str) -> None:
    print(f"[OK] {message}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CodexCLI E2E checks.")
    parser.add_argument(
        "--cases",
        type=Path,
        default=Path("demo/e2e_cases.json"),
        help="Path to JSON test cases.",
    )
    parser.add_argument(
        "--codex-bin",
        default="codex",
        help="CodexCLI binary name or path.",
    )
    parser.add_argument(
        "--include-network",
        action="store_true",
        help="Include cases marked requires_network.",
    )
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        help="Run only a specific case by name (repeatable).",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Run codexcli_setup.sh before tests.",
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Run codexcli_uninstall.sh after tests.",
    )
    parser.add_argument(
        "--extra-arg",
        action="append",
        default=[],
        help="Extra args to pass to codex exec (repeatable).",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    cases = _load_cases(args.cases)
    selected_cases = _select_cases(cases, args.include_network, args.case)

    if not selected_cases:
        _print_failure("No cases selected.")
        return 1

    install_script = repo_root / "scripts" / "codexcli_setup.sh"
    uninstall_script = repo_root / "scripts" / "codexcli_uninstall.sh"

    try:
        if args.install:
            subprocess.run([str(install_script)], check=True)

        failures = 0
        for case in selected_cases:
            name = case.get("name", "<unnamed>")
            run = _run_case(case, args.codex_bin, repo_root, args.extra_arg)
            if run["exit_code"] != 0:
                failures += 1
                _print_failure(f"{name}: codex exec failed ({run['exit_code']})")
                continue
            guard_results = run["guard_results"]
            if not guard_results:
                failures += 1
                _print_failure(f"{name}: no GuardResult found in output")
                continue
            result = guard_results[-1]
            expected = _expected_decisions(case["expected_decision"])
            if result.get("decision") not in expected:
                failures += 1
                _print_failure(
                    f"{name}: decision {result.get('decision')} not in {expected}"
                )
                continue
            expected_reasons = case.get("expected_reasons", [])
            if expected_reasons:
                missing = sorted(
                    reason
                    for reason in expected_reasons
                    if reason not in result.get("reasons", [])
                )
                if missing:
                    failures += 1
                    _print_failure(f"{name}: missing reasons {missing}")
                    continue
            _print_ok(name)

        if failures:
            _print_failure(f"{failures} case(s) failed.")
            return 1
        _print_ok("All cases passed.")
        return 0
    finally:
        if args.uninstall:
            subprocess.run([str(uninstall_script)], check=False)


if __name__ == "__main__":
    raise SystemExit(main())

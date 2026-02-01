#!/usr/bin/env python3
"""Run CodexCLI E2E checks against BridgeWarden."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bridgewarden.e2e import extract_guard_results  # noqa: E402


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
    demo_port: Optional[int],
) -> Dict[str, Any]:
    prompt = case["prompt"]
    if isinstance(prompt, str) and demo_port is not None:
        prompt = prompt.replace("{DEMO_PORT}", str(demo_port))
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


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _start_demo_server(repo_root: Path, port: int) -> subprocess.Popen[str]:
    cmd = [sys.executable, str(repo_root / "demo" / "run_webapp.py"), "--port", str(port)]
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if not _wait_for_port("127.0.0.1", port, timeout=5.0):
        process.terminate()
        process.wait(timeout=2)
        raise RuntimeError("demo webapp failed to start")
    return process


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CodexCLI E2E checks.")
    parser.add_argument(
        "--cases",
        type=Path,
        default=REPO_ROOT / "demo" / "e2e_cases.json",
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
        "--network-config",
        type=Path,
        default=REPO_ROOT / "config" / "bridgewarden.localtest.yaml",
        help="Config file to use when running network cases.",
    )
    parser.add_argument(
        "--start-demo-server",
        action="store_true",
        help="Start the local demo webapp for network cases.",
    )
    parser.add_argument(
        "--demo-port",
        type=int,
        default=8000,
        help="Port for the local demo webapp.",
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
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("demo/e2e_outputs"),
        help="Directory to dump raw stdout/stderr on failures.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print stderr/stdout hints for troubleshooting.",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    cases_path = args.cases
    if not cases_path.is_absolute():
        cases_path = repo_root / cases_path
    cases = _load_cases(cases_path)
    selected_cases = _select_cases(cases, args.include_network, args.case)

    if not selected_cases:
        _print_failure("No cases selected.")
        return 1

    install_script = repo_root / "scripts" / "codexcli_setup.sh"
    uninstall_script = repo_root / "scripts" / "codexcli_uninstall.sh"

    demo_process: Optional[subprocess.Popen[str]] = None
    try:
        if args.start_demo_server:
            demo_process = _start_demo_server(repo_root, args.demo_port)

        if args.include_network and not args.install:
            print(
                "[NOTE] include-network enabled without --install; "
                "ensure your Codex MCP config uses a network-enabled BridgeWarden config."
            )

        if args.install:
            install_env = os.environ.copy()
            if args.include_network:
                network_config = args.network_config
                if not network_config.is_absolute():
                    network_config = repo_root / network_config
                if not network_config.exists():
                    _print_failure(f"network config not found: {network_config}")
                    return 1
                install_env["BW_CONFIG"] = str(network_config)
            subprocess.run([str(install_script)], check=True, env=install_env)

        failures = 0
        output_dir = args.output_dir
        if not output_dir.is_absolute():
            output_dir = repo_root / output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        for case in selected_cases:
            name = case.get("name", "<unnamed>")
            run = _run_case(case, args.codex_bin, repo_root, args.extra_arg, args.demo_port)
            if run["exit_code"] != 0:
                failures += 1
                _print_failure(f"{name}: codex exec failed ({run['exit_code']})")
                if args.debug:
                    _print_failure(run["stderr"].strip() or "<no stderr>")
                continue
            guard_results = run["guard_results"]
            if not guard_results:
                failures += 1
                _print_failure(f"{name}: no GuardResult found in output")
                _dump_output(output_dir, name, run["stdout"], run["stderr"])
                if args.debug:
                    _print_failure(run["stderr"].strip() or "<no stderr>")
                    _print_failure(run["stdout"].strip() or "<no stdout>")
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
        if demo_process is not None:
            demo_process.terminate()
            demo_process.wait(timeout=2)
        if args.uninstall:
            subprocess.run([str(uninstall_script)], check=False)


def _dump_output(output_dir: Path, name: str, stdout: str, stderr: str) -> None:
    safe_name = name.replace("/", "_")
    (output_dir / f"{safe_name}.stdout.txt").write_text(stdout, encoding="utf-8")
    (output_dir / f"{safe_name}.stderr.txt").write_text(stderr, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())

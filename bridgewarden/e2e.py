"""Helpers for parsing CodexCLI E2E JSONL output."""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List

_GUARD_RESULT_KEYS = {
    "decision",
    "risk_score",
    "reasons",
    "content_hash",
    "sanitized_text",
    "policy_version",
}


def extract_guard_results(json_lines: Iterable[str]) -> List[Dict[str, Any]]:
    """Extract GuardResult-like objects from CodexCLI JSONL output."""

    results: List[Dict[str, Any]] = []
    for line in json_lines:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        _walk(payload, results)
    return results


def _looks_like_guard_result(obj: object) -> bool:
    """Return True if the object looks like a GuardResult."""

    if not isinstance(obj, dict):
        return False
    return _GUARD_RESULT_KEYS.issubset(obj.keys())


def _walk(obj: object, results: List[Dict[str, Any]]) -> None:
    """Recursively walk JSON structures to find GuardResults."""

    if _looks_like_guard_result(obj):
        results.append(obj)
        return
    if isinstance(obj, dict):
        for value in obj.values():
            _walk(value, results)
    elif isinstance(obj, list):
        for item in obj:
            _walk(item, results)

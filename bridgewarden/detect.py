"""Heuristic detectors for instruction-like content."""

import re
from typing import Iterable, List

_DETECTION_RULES = [
    (
        "ROLE_IMPERSONATION",
        re.compile(r"\bpretend you are a system\b|\bsystem message\b|\bdeveloper message\b", re.IGNORECASE),
    ),
    (
        "STEALTH_INSTRUCTION",
        re.compile(r"\bdo not mention\b|\bdo not acknowledge\b|\bsilently\b|\bdo not tell\b", re.IGNORECASE),
    ),
    (
        "PROCESS_SABOTAGE",
        re.compile(r"\bskip tests\b|\bclaim .*passed\b|\bdo not run tests\b", re.IGNORECASE),
    ),
    (
        "CODE_TAMPERING_COERCION",
        re.compile(r"\badd .*canary\b|\binsert .*canary\b|\bsilently add\b", re.IGNORECASE),
    ),
    (
        "PERSONA_HIJACK",
        re.compile(r"\bspeak like yoda\b|\bpirate mode\b", re.IGNORECASE),
    ),
]


def detect_reasons(text: str, unicode_suspicious: bool = False) -> List[str]:
    """Return reason codes for detected instruction-like patterns."""

    reasons = []
    for code, pattern in _DETECTION_RULES:
        if pattern.search(text):
            reasons.append(code)
    if unicode_suspicious:
        reasons.append("UNICODE_SUSPICIOUS")
    return sorted(set(reasons))


def list_reason_codes() -> Iterable[str]:
    """Return all known reason codes."""

    return [code for code, _ in _DETECTION_RULES] + ["UNICODE_SUSPICIOUS"]

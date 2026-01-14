"""Heuristic detectors for instruction-like content."""

from dataclasses import dataclass
import re
from typing import Iterable, List, Pattern

_PROFILE_ORDER = {"permissive": 1, "balanced": 2, "strict": 3}


@dataclass(frozen=True)
class DetectionRule:
    """Regex rule with a minimum profile threshold."""

    code: str
    pattern: Pattern[str]
    min_profile: str


_DETECTION_RULES = [
    DetectionRule(
        "ROLE_IMPERSONATION",
        re.compile(
            r"\bpretend you are (a|the) system\b|\bsystem message\b|\bdeveloper message\b"
            r"|\bsystem prompt\b|\bdeveloper instructions\b",
            re.IGNORECASE,
        ),
        "permissive",
    ),
    DetectionRule(
        "ROLE_HEADER",
        re.compile(
            r"(?m)^\s*(?:#+\s*)?(system|developer)\s*:",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "PROMPT_BOUNDARY",
        re.compile(
            r"\bBEGIN (SYSTEM|DEVELOPER) PROMPT\b|\bEND (SYSTEM|DEVELOPER) PROMPT\b",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "INSTRUCTION_OVERRIDE",
        re.compile(
            r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|above|earlier|prior)\b"
            r".{0,40}\b(instructions|rules|directives|policies)\b"
            r"|\bthis (overrides|supersedes) (all|any) (instructions|policies)\b",
            re.IGNORECASE,
        ),
        "permissive",
    ),
    DetectionRule(
        "INSTRUCTION_HEADER",
        re.compile(
            r"(?m)^\s*(?:#+\s*)?(instructions?|rules|policy)\s*:\s*(?:you\s+)?"
            r"(?:must|should|do not|don't|never)\b",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "RESPONSE_CONSTRAINT",
        re.compile(
            r"(?:^|[.!?]\s+)(?:please\s+)?"
            r"(?:respond|reply|output|return)\s+(?:with\s+)?(?:only|just)\b",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "STEALTH_INSTRUCTION",
        re.compile(
            r"\bdo not mention\b|\bdo not acknowledge\b|\bsilently\b|\bdo not tell\b"
            r"|\bdo not reveal\b|\bdo not disclose\b|\bkeep this secret\b",
            re.IGNORECASE,
        ),
        "permissive",
    ),
    DetectionRule(
        "PROCESS_SABOTAGE",
        re.compile(
            r"\bskip (the )?tests\b|\bdo not run tests\b|\bdon't run tests\b|\bclaim .*passed\b"
            r"|\bignore test failures\b|\bfake (the )?tests?\b|\bpretend .*passed\b",
            re.IGNORECASE,
        ),
        "permissive",
    ),
    DetectionRule(
        "CODE_TAMPERING_COERCION",
        re.compile(
            r"\badd .*canary\b|\binsert .*canary\b|\bsilently add\b|\badd (a )?backdoor\b"
            r"|\binsert (a )?backdoor\b|\bdisable security\b|\bweaken encryption\b",
            re.IGNORECASE,
        ),
        "permissive",
    ),
    DetectionRule(
        "DATA_EXFILTRATION",
        re.compile(
            r"\b(exfiltrate|leak|steal|dump|upload|send)\b.{0,80}\b(secrets?|credentials?|tokens?|"
            r"passwords?|api keys?|private keys?|env|environment variables?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "permissive",
    ),
    DetectionRule(
        "TOOL_CALL_SERIALIZED",
        re.compile(
            r"(?s)\"?(tool|name)\"?\s*:\s*\"?[A-Za-z0-9_.-]+\"?.{0,200}"
            r"\"?(args|arguments|input)\"?\s*:",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "POLICY_BYPASS",
        re.compile(
            r"\b(bypass|disable|ignore)\b.{0,40}\b(safety|guardrails?|policy|restrictions?)\b"
            r"|\bno (rules|restrictions|safety)\b|\bwithout (any )?restrictions\b",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "DIRECT_TOOL_CALL",
        re.compile(
            r"(?:^|[.!?]\s+)(?:please\s+)?"
            r"(?:you\s+(?:must|should|need to|are to)\s+)?"
            r"(?:call|invoke|use)\s+(?:the\s+)?(?:tool|mcp)\b",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "SENSITIVE_FILE_ACCESS",
        re.compile(
            r"(?:^|[.!?]\s+)(?:please\s+)?"
            r"(?:you\s+(?:must|should|need to|are to)\s+)?"
            r"(?:cat|read|open|print|dump)\b.{0,40}"
            r"(?:/etc/passwd|/etc/shadow|~/?\.ssh/|id_rsa\b|"
            r"\.aws/credentials|\.npmrc|\.pypirc|\.env\b)",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "PERSONA_SHIFT",
        re.compile(
            r"\bact as\b.{0,40}\b(system|developer|administrator|root|security)\b"
            r"|\byou are now\b.{0,40}\b(system|developer|administrator|root|security)\b"
            r"|\bchange your role\b|\broleplay as\b",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "OBFUSCATION_MARKER",
        re.compile(
            r"(?s)(?:\b(base64|rot13|hex|uuencode|gzip)\b.{0,80}"
            r"\b(decode|decrypt|deobfuscate|unmask)\b|\b(decode|decrypt|deobfuscate|unmask)\b"
            r".{0,80}\b(base64|rot13|hex|uuencode|gzip)\b)",
            re.IGNORECASE | re.DOTALL,
        ),
        "strict",
    ),
    DetectionRule(
        "COMMAND_COERCION",
        re.compile(
            r"(?:^|[.!?]\s+)(?:please\s+)?(?:run|execute|paste|enter)\b.{0,60}"
            r"\b(curl|wget|powershell|invoke-webrequest|sudo|chmod\s+\+x)\b",
            re.IGNORECASE,
        ),
        "strict",
    ),
    DetectionRule(
        "MULTI_STEP_INSTRUCTION",
        re.compile(
            r"(?s)step\s*1:.*?(must|do not|don't|ignore).{0,200}step\s*2:",
            re.IGNORECASE,
        ),
        "strict",
    ),
    DetectionRule(
        "SHELL_EXECUTION",
        re.compile(
            r"(?:^|[.!?]\s+)(?:please\s+)?"
            r"(?:you\s+(?:must|should|need to|are to)\s+)?"
            r"(?:run|execute)\b.{0,40}\bcommand\b.{0,40}"
            r"\b(?:shell|terminal|bash|zsh|powershell|cmd)\b",
            re.IGNORECASE,
        ),
        "strict",
    ),
]


def _normalize_profile(profile_name: str) -> str:
    """Return a safe profile name for detection rules."""

    return profile_name if profile_name in _PROFILE_ORDER else "strict"


def _active_rules(profile_name: str) -> Iterable[DetectionRule]:
    """Return the active rules for a given detection profile."""

    profile = _normalize_profile(profile_name)
    min_level = _PROFILE_ORDER[profile]
    return [
        rule
        for rule in _DETECTION_RULES
        if _PROFILE_ORDER.get(rule.min_profile, _PROFILE_ORDER["strict"]) <= min_level
    ]


def detect_reasons(
    text: str,
    unicode_suspicious: bool = False,
    profile_name: str = "strict",
) -> List[str]:
    """Return reason codes for detected instruction-like patterns."""

    reasons = []
    for rule in _active_rules(profile_name):
        if rule.pattern.search(text):
            reasons.append(rule.code)
    if unicode_suspicious:
        reasons.append("UNICODE_SUSPICIOUS")
    return sorted(set(reasons))


def list_reason_codes() -> Iterable[str]:
    """Return all known reason codes."""

    return [rule.code for rule in _DETECTION_RULES] + ["UNICODE_SUSPICIOUS"]

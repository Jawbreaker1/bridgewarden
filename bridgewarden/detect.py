"""Heuristic detectors for instruction-like content."""

from dataclasses import dataclass
import re
from typing import Dict, Iterable, List, Pattern

from .language_packs import CORE_LANGUAGE_PHRASES, EXTENDED_LANGUAGE_PHRASES

_PROFILE_ORDER = {"permissive": 1, "balanced": 2, "strict": 3}


@dataclass(frozen=True)
class DetectionRule:
    """Regex rule with a minimum profile threshold."""

    code: str
    pattern: Pattern[str]
    min_profile: str


_MIN_PROFILE_BY_CODE = {
    "ROLE_IMPERSONATION": "permissive",
    "ROLE_HEADER": "balanced",
    "PROMPT_BOUNDARY": "balanced",
    "INSTRUCTION_OVERRIDE": "permissive",
    "INSTRUCTION_HEADER": "balanced",
    "RESPONSE_CONSTRAINT": "balanced",
    "STEALTH_INSTRUCTION": "permissive",
    "PROCESS_SABOTAGE": "permissive",
    "CODE_TAMPERING_COERCION": "permissive",
    "DATA_EXFILTRATION": "permissive",
    "TOOL_CALL_SERIALIZED": "balanced",
    "POLICY_BYPASS": "balanced",
    "DIRECT_TOOL_CALL": "balanced",
    "SENSITIVE_FILE_ACCESS": "balanced",
    "PERSONA_SHIFT": "balanced",
    "OBFUSCATION_MARKER": "strict",
    "COMMAND_COERCION": "strict",
    "MULTI_STEP_INSTRUCTION": "strict",
    "SHELL_EXECUTION": "strict",
}

_OBFUSCATED_PATTERNS = [
    ("systemmessage", "ROLE_IMPERSONATION"),
    ("developermessage", "ROLE_IMPERSONATION"),
    ("systemprompt", "ROLE_IMPERSONATION"),
    ("developerinstructions", "ROLE_IMPERSONATION"),
    ("ignorepreviousinstructions", "INSTRUCTION_OVERRIDE"),
    ("disregardpreviousinstructions", "INSTRUCTION_OVERRIDE"),
    ("donotmention", "STEALTH_INSTRUCTION"),
    ("donotacknowledge", "STEALTH_INSTRUCTION"),
    ("respondwithonly", "RESPONSE_CONSTRAINT"),
    ("replywithonly", "RESPONSE_CONSTRAINT"),
    ("callthetool", "DIRECT_TOOL_CALL"),
    ("usethetool", "DIRECT_TOOL_CALL"),
    ("exfiltratesecrets", "DATA_EXFILTRATION"),
    ("skiptests", "PROCESS_SABOTAGE"),
    ("donotruntests", "PROCESS_SABOTAGE"),
    ("addbackdoor", "CODE_TAMPERING_COERCION"),
    ("insertbackdoor", "CODE_TAMPERING_COERCION"),
    ("readetcpasswd", "SENSITIVE_FILE_ACCESS"),
    ("catetcpasswd", "SENSITIVE_FILE_ACCESS"),
]

_OBFUSCATED_MIN_LENGTH = 6


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
        "ROLE_HEADER",
        re.compile(
            r"(?m)^\s*(?:#+\s*)?(system|developer)\b(?!\s*:)",
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
        "PROMPT_BOUNDARY",
        re.compile(
            r"\bBEGIN (SYSTEM|DEVELOPER)\b|\bEND (SYSTEM|DEVELOPER)\b"
            r"|\bSYSTEM PROMPT\b|\bDEVELOPER PROMPT\b",
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
        "TOOL_CALL_SERIALIZED",
        re.compile(
            r"(?s)<(tool|name)>\s*[A-Za-z0-9_.-]+\s*</\1>.*?<"
            r"(args|arguments|input)",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "TOOL_CALL_SERIALIZED",
        re.compile(
            r"(?s)<(tool|name)>\s*[A-Za-z0-9_.-]+\s*</\1>.*?<"
            r"(args|arguments|input)",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "TOOL_CALL_SERIALIZED",
        re.compile(
            r"(?im)^\s*(tool|name)\s*=\s*[A-Za-z0-9_.-]+\s*$\n"
            r"^\s*(args|arguments|input)\s*=",
            re.IGNORECASE,
        ),
        "balanced",
    ),
    DetectionRule(
        "TOOL_CALL_SERIALIZED",
        re.compile(
            r"(?s)\btool\b\s*(?:=|->|:)\s*[A-Za-z0-9_.-]+\b.*?\b(args|arguments|input)\b\s*[:=]",
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



def _compile_phrases(phrases: Iterable[str]) -> Pattern[str]:
    """Compile phrase lists into a whitespace-tolerant regex."""

    escaped = []
    for phrase in phrases:
        pattern = re.escape(phrase).replace(r"\ ", r"\s+")
        escaped.append(pattern)
    return re.compile("|".join(escaped), re.IGNORECASE)


def _build_language_rules(
    phrase_map: Dict[str, Dict[str, List[str]]]
) -> Dict[str, List[DetectionRule]]:
    """Build per-language detection rules from phrase maps."""

    rules_by_language: Dict[str, List[DetectionRule]] = {}
    for language, codes in phrase_map.items():
        rules: List[DetectionRule] = []
        for code, phrases in codes.items():
            min_profile = _MIN_PROFILE_BY_CODE.get(code, "strict")
            rules.append(DetectionRule(code, _compile_phrases(phrases), min_profile))
        rules_by_language[language] = rules
    return rules_by_language


_CORE_LANGUAGE_RULES = _build_language_rules(CORE_LANGUAGE_PHRASES)
_EXTENDED_LANGUAGE_RULES = _build_language_rules(EXTENDED_LANGUAGE_PHRASES)


def _collapse_text(text: str) -> str:
    """Collapse text to alphanumeric lowercase for obfuscation detection."""

    return "".join(ch.lower() for ch in text if ch.isalnum())


def _collapse_phrase(phrase: str) -> str:
    """Collapse a phrase to alphanumeric lowercase."""

    return "".join(ch.lower() for ch in phrase if ch.isalnum())


def _build_obfuscated_language_patterns(
    phrase_map: Dict[str, Dict[str, List[str]]]
) -> Dict[str, List[tuple[str, str]]]:
    """Build collapsed phrase patterns per language for obfuscation detection."""

    patterns: Dict[str, List[tuple[str, str]]] = {}
    for language, codes in phrase_map.items():
        bucket: List[tuple[str, str]] = []
        for code, phrases in codes.items():
            for phrase in phrases:
                collapsed = _collapse_phrase(phrase)
                if len(collapsed) < _OBFUSCATED_MIN_LENGTH:
                    continue
                bucket.append((collapsed, code))
        patterns[language] = bucket
    return patterns


_OBFUSCATED_CORE_LANGUAGE_PATTERNS = _build_obfuscated_language_patterns(
    CORE_LANGUAGE_PHRASES
)
_OBFUSCATED_EXTENDED_LANGUAGE_PATTERNS = _build_obfuscated_language_patterns(
    EXTENDED_LANGUAGE_PHRASES
)


def _normalize_profile(profile_name: str) -> str:
    """Return a safe profile name for detection rules."""

    return profile_name if profile_name in _PROFILE_ORDER else "strict"


def _profile_allows_reason(profile_name: str, reason_code: str) -> bool:
    """Return True if the profile enables the reason code."""

    profile = _normalize_profile(profile_name)
    min_profile = _MIN_PROFILE_BY_CODE.get(reason_code, "strict")
    return _PROFILE_ORDER[profile] >= _PROFILE_ORDER[min_profile]


def _active_rules(
    profile_name: str,
    rules: Iterable[DetectionRule],
) -> Iterable[DetectionRule]:
    """Return the active rules for a given detection profile."""

    profile = _normalize_profile(profile_name)
    min_level = _PROFILE_ORDER[profile]
    return [
        rule
        for rule in rules
        if _PROFILE_ORDER.get(rule.min_profile, _PROFILE_ORDER["strict"]) <= min_level
    ]


def detect_reasons(
    text: str,
    unicode_suspicious: bool = False,
    profile_name: str = "strict",
) -> List[str]:
    """Return reason codes for detected instruction-like patterns."""

    reasons = set()
    language_hints = set()

    for rule in _active_rules(profile_name, _DETECTION_RULES):
        if rule.pattern.search(text):
            reasons.add(rule.code)

    collapsed = None
    for pattern, code in _OBFUSCATED_PATTERNS:
        if not _profile_allows_reason(profile_name, code):
            continue
        if collapsed is None:
            collapsed = _collapse_text(text)
        if pattern in collapsed:
            reasons.add(code)

    for language, patterns in _OBFUSCATED_CORE_LANGUAGE_PATTERNS.items():
        for pattern, code in patterns:
            if not _profile_allows_reason(profile_name, code):
                continue
            if collapsed is None:
                collapsed = _collapse_text(text)
            if pattern in collapsed:
                reasons.add(code)
                language_hints.add(language)

    for language, rules in _CORE_LANGUAGE_RULES.items():
        for rule in _active_rules(profile_name, rules):
            if rule.pattern.search(text):
                reasons.add(rule.code)
                language_hints.add(language)

    for language in sorted(language_hints):
        for rule in _active_rules(profile_name, _EXTENDED_LANGUAGE_RULES.get(language, [])):
            if rule.pattern.search(text):
                reasons.add(rule.code)
        for pattern, code in _OBFUSCATED_EXTENDED_LANGUAGE_PATTERNS.get(language, []):
            if not _profile_allows_reason(profile_name, code):
                continue
            if collapsed is None:
                collapsed = _collapse_text(text)
            if pattern in collapsed:
                reasons.add(code)

    if unicode_suspicious:
        reasons.add("UNICODE_SUSPICIOUS")
    return sorted(reasons)


def list_reason_codes() -> Iterable[str]:
    """Return all known reason codes."""

    codes = {rule.code for rule in _DETECTION_RULES}
    for rules in _CORE_LANGUAGE_RULES.values():
        codes.update(rule.code for rule in rules)
    for rules in _EXTENDED_LANGUAGE_RULES.values():
        codes.update(rule.code for rule in rules)
    codes.add("UNICODE_SUSPICIOUS")
    return sorted(codes)

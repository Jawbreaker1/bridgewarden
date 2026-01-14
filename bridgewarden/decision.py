"""Risk scoring and policy decision logic."""

from dataclasses import dataclass
from typing import Iterable, Set, Tuple

BLOCK_REASONS = {"PROCESS_SABOTAGE", "CODE_TAMPERING_COERCION"}

_REASON_WEIGHTS = {
    "ROLE_IMPERSONATION": 0.4,
    "INSTRUCTION_OVERRIDE": 0.5,
    "STEALTH_INSTRUCTION": 0.3,
    "PROCESS_SABOTAGE": 0.7,
    "CODE_TAMPERING_COERCION": 0.7,
    "DATA_EXFILTRATION": 0.6,
    "POLICY_BYPASS": 0.5,
    "DIRECT_TOOL_CALL": 0.4,
    "SENSITIVE_FILE_ACCESS": 0.6,
    "SHELL_EXECUTION": 0.5,
    "PERSONA_HIJACK": 0.2,
    "UNICODE_SUSPICIOUS": 0.2,
}


@dataclass(frozen=True)
class PolicyProfile:
    """Thresholds and overrides for risk decisions."""

    name: str
    warn_threshold: float
    block_threshold: float
    block_reasons: Set[str]


PROFILES = {
    "strict": PolicyProfile(
        name="strict",
        warn_threshold=0.2,
        block_threshold=0.6,
        block_reasons=BLOCK_REASONS,
    ),
    "balanced": PolicyProfile(
        name="balanced",
        warn_threshold=0.2,
        block_threshold=0.9,
        block_reasons=BLOCK_REASONS,
    ),
    "permissive": PolicyProfile(
        name="permissive",
        warn_threshold=0.2,
        block_threshold=0.95,
        block_reasons=BLOCK_REASONS,
    ),
}


def get_profile(name: str) -> PolicyProfile:
    """Resolve a policy profile by name with a safe default."""

    return PROFILES.get(name, PROFILES["strict"])


def score_reasons(reasons: Iterable[str]) -> float:
    """Compute a deterministic risk score from reason codes."""

    score = sum(_REASON_WEIGHTS.get(reason, 0.1) for reason in reasons)
    return round(min(1.0, score), 2)


def decide(reasons: Iterable[str], profile: PolicyProfile) -> Tuple[str, float]:
    """Return the decision and risk score for a set of reasons."""

    reasons_set = set(reasons)
    risk_score = score_reasons(reasons_set)
    if reasons_set & profile.block_reasons:
        return "BLOCK", risk_score
    if risk_score >= profile.block_threshold:
        return "BLOCK", risk_score
    if risk_score >= profile.warn_threshold:
        return "WARN", risk_score
    return "ALLOW", risk_score

"""Shared data types for tool responses."""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class GuardResult:
    """Standard guard result payload for MCP tools."""

    decision: str
    risk_score: float
    reasons: List[str]
    source: Dict[str, str]
    content_hash: str
    sanitized_text: str
    quarantine_id: Optional[str]
    redactions: List[Dict[str, int]]
    cache_hit: bool
    policy_version: str
    approval_id: Optional[str] = None

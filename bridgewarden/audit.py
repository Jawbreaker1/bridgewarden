"""Audit event creation and JSONL logging."""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .redact import redact_secrets
from .types import GuardResult

_SENSITIVE_QUERY_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "client_secret",
    "code",
    "key",
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
}


@dataclass(frozen=True)
class AuditEvent:
    """Structured audit record for a single guard decision."""

    timestamp: str
    source: Dict[str, str]
    content_hash: str
    risk_score: float
    decision: str
    policy_version: str
    cache_hit: bool
    reasons: List[str]
    redactions: List[Dict[str, int]]
    quarantine_id: Optional[str]
    approval_id: Optional[str]


def build_audit_event(result: GuardResult, timestamp: Optional[str] = None) -> AuditEvent:
    """Build an audit event from a GuardResult."""

    event_time = timestamp or datetime.now(timezone.utc).isoformat()
    return AuditEvent(
        timestamp=event_time,
        source=_sanitize_source(result.source),
        content_hash=result.content_hash,
        risk_score=result.risk_score,
        decision=result.decision,
        policy_version=result.policy_version,
        cache_hit=result.cache_hit,
        reasons=result.reasons,
        redactions=result.redactions,
        quarantine_id=result.quarantine_id,
        approval_id=result.approval_id,
    )


def _sanitize_source(source: Dict[str, str]) -> Dict[str, str]:
    """Redact secret-like values before persisting source metadata."""

    sanitized: Dict[str, str] = {}
    for key, value in source.items():
        cleaned = _sanitize_url(value)
        cleaned, _ = redact_secrets(cleaned)
        sanitized[key] = cleaned
    return sanitized


def _sanitize_url(value: str) -> str:
    """Mask sensitive URL query parameter values while preserving source context."""

    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc or not parsed.query:
        return value

    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    cleaned_pairs = []
    for key, item in pairs:
        if _is_sensitive_query_key(key):
            cleaned_pairs.append((key, "[REDACTED]"))
        else:
            cleaned_pairs.append((key, item))
    query = urlencode(cleaned_pairs, safe="[]")
    return urlunparse(parsed._replace(query=query))


def _is_sensitive_query_key(key: str) -> bool:
    """Return whether a query parameter name commonly carries a secret."""

    normalized = key.strip().lower().replace("-", "_")
    if normalized in _SENSITIVE_QUERY_KEYS:
        return True
    return any(marker in normalized for marker in ("token", "secret", "password"))


def audit_event_to_json(event: AuditEvent) -> str:
    """Serialize an audit event to a JSON string."""

    return json.dumps(event.__dict__, sort_keys=True, ensure_ascii=True)


class AuditLogger:
    """Append-only JSONL audit log writer."""

    def __init__(self, path: Path) -> None:
        """Initialize a logger that appends to the given path."""

        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, result: GuardResult, timestamp: Optional[str] = None) -> None:
        """Append a GuardResult to the JSONL audit log."""

        event = build_audit_event(result, timestamp=timestamp)
        payload = audit_event_to_json(event)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(payload + "\n")

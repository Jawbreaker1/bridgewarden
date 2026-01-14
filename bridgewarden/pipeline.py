"""Core guard pipeline: normalize, sanitize, detect, redact, decide."""

import hashlib
from typing import Dict, Optional, TYPE_CHECKING

from .audit import AuditLogger
from .config import DEFAULT_PROFILE, POLICY_VERSION
from .decision import decide, get_profile
from .detect import detect_reasons
from .normalize import normalize_text
from .redact import redact_secrets
from .sanitize import sanitize_text
from .types import GuardResult
from .quarantine import build_quarantine_id

if TYPE_CHECKING:
    from .quarantine import QuarantineStore


def _content_hash(text: str) -> str:
    """Hash the original text for dedupe and auditing."""

    return hashlib.sha256(text.encode("utf-8")).hexdigest()



def guard_text(
    text: str,
    source: Optional[Dict[str, str]] = None,
    quarantine_store: Optional["QuarantineStore"] = None,
    profile_name: str = DEFAULT_PROFILE,
    audit_logger: Optional[AuditLogger] = None,
) -> GuardResult:
    """Run the guard pipeline and return a GuardResult."""

    source_value = source or {"kind": "local"}
    normalized = normalize_text(text)
    sanitized = sanitize_text(normalized.text)
    reasons = detect_reasons(sanitized, unicode_suspicious=normalized.unicode_suspicious)
    redacted_text, redactions = redact_secrets(sanitized)
    profile = get_profile(profile_name)
    decision, risk_score = decide(reasons, profile)
    content_hash = _content_hash(text)

    if decision == "BLOCK":
        sanitized_text = ""
        quarantine_id = build_quarantine_id(content_hash)
        if quarantine_store is not None:
            metadata = {
                "source": source_value,
                "decision": decision,
                "risk_score": risk_score,
                "reasons": reasons,
                "redactions": redactions,
                "policy_version": POLICY_VERSION,
            }
            quarantine_store.put(
                content_hash=content_hash,
                original_text=text,
                sanitized_text=redacted_text,
                metadata=metadata,
            )
    else:
        sanitized_text = redacted_text
        quarantine_id = None

    result = GuardResult(
        decision=decision,
        risk_score=risk_score,
        reasons=reasons,
        source=source_value,
        content_hash=content_hash,
        sanitized_text=sanitized_text,
        quarantine_id=quarantine_id,
        redactions=redactions,
        cache_hit=False,
        policy_version=POLICY_VERSION,
        approval_id=None,
    )

    if audit_logger is not None:
        audit_logger.log(result)

    return result

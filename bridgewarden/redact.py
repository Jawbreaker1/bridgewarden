"""Secret redaction helpers for guarded outputs."""

import re
from typing import Dict, List, Tuple

_REDACTION_RULES = [
    ("API_KEY", re.compile(r"\bsk-[A-Za-z0-9]{8,}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----")),
]


def redact_secrets(text: str) -> Tuple[str, List[Dict[str, int]]]:
    """Mask secret-like tokens and return redaction metadata."""

    redactions: List[Dict[str, int]] = []
    redacted_text = text
    for kind, pattern in _REDACTION_RULES:
        matches = list(pattern.finditer(redacted_text))
        if not matches:
            continue
        redacted_text = pattern.sub("[REDACTED]", redacted_text)
        redactions.append({"kind": kind, "count": len(matches)})
    return redacted_text, redactions

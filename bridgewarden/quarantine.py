"""Quarantine storage for blocked content and review excerpts."""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .redact import redact_secrets

RECORD_FILENAME = "record.json"
ORIGINAL_FILENAME = "original.txt"
SANITIZED_FILENAME = "sanitized.txt"


def build_quarantine_id(content_hash: str) -> str:
    """Create a stable quarantine id from a content hash."""

    return f"q_{content_hash}"


def _excerpt(text: str, limit: int) -> str:
    """Return a truncated excerpt with an ellipsis when needed."""

    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."


@dataclass(frozen=True)
class QuarantineView:
    """View object for safe quarantine inspection."""

    quarantine_id: str
    original_excerpt: str
    sanitized_text: str
    metadata: Dict[str, object]


class QuarantineStore:
    """File-backed store for quarantined content."""

    def __init__(self, root: Path) -> None:
        """Initialize the store with a root directory."""

        self.root = Path(root)

    def put(
        self,
        content_hash: str,
        original_text: str,
        sanitized_text: str,
        metadata: Dict[str, object],
        timestamp: Optional[str] = None,
    ) -> str:
        """Persist a quarantine record and return its id."""

        quarantine_id = build_quarantine_id(content_hash)
        record_dir = self.root / quarantine_id
        record_path = record_dir / RECORD_FILENAME
        if record_path.exists():
            return quarantine_id

        record_dir.mkdir(parents=True, exist_ok=True)
        (record_dir / ORIGINAL_FILENAME).write_text(original_text, encoding="utf-8")
        (record_dir / SANITIZED_FILENAME).write_text(sanitized_text, encoding="utf-8")

        created_at = timestamp or datetime.now(timezone.utc).isoformat()
        record = {
            "content_hash": content_hash,
            "created_at": created_at,
            **metadata,
        }
        record_path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
        return quarantine_id

    def get_record(self, quarantine_id: str) -> Dict[str, object]:
        """Load a stored quarantine record."""

        record_path = self._record_path(quarantine_id)
        return json.loads(record_path.read_text(encoding="utf-8"))

    def get_view(self, quarantine_id: str, excerpt_limit: int = 200) -> QuarantineView:
        """Return a safe view of a quarantined record."""

        record = self.get_record(quarantine_id)
        sanitized_text = self._sanitized_path(quarantine_id).read_text(encoding="utf-8")
        original_text = self._original_path(quarantine_id).read_text(encoding="utf-8")
        redacted_original, _ = redact_secrets(original_text)
        original_excerpt = _excerpt(redacted_original, excerpt_limit)
        return QuarantineView(
            quarantine_id=quarantine_id,
            original_excerpt=original_excerpt,
            sanitized_text=sanitized_text,
            metadata=record,
        )

    def _record_path(self, quarantine_id: str) -> Path:
        """Path to the quarantine record metadata."""

        return self.root / quarantine_id / RECORD_FILENAME

    def _original_path(self, quarantine_id: str) -> Path:
        """Path to the original quarantined text."""

        return self.root / quarantine_id / ORIGINAL_FILENAME

    def _sanitized_path(self, quarantine_id: str) -> Path:
        """Path to the sanitized quarantined text."""

        return self.root / quarantine_id / SANITIZED_FILENAME

"""Source approval storage for web and repo access."""

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional


@dataclass(frozen=True)
class SourceApprovalRequest:
    """Request payload for a new source approval."""

    kind: str
    target: str
    rationale: Optional[str] = None
    requested_by: Optional[str] = None


@dataclass(frozen=True)
class SourceApprovalStatus:
    """Status record for an approval request."""

    approval_id: str
    kind: str
    target: str
    status: str
    created_at: str
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None
    notes: Optional[str] = None


class SourceApprovalStore:
    """File-backed store for approval requests and decisions."""

    def __init__(
        self,
        root: Path,
        id_factory: Optional[Callable[[], str]] = None,
        clock: Optional[Callable[[], str]] = None,
    ) -> None:
        """Initialize the approvals store and helpers."""

        self.root = Path(root)
        self._id_factory = id_factory or (lambda: f"a_{uuid.uuid4().hex}")
        self._clock = clock or (lambda: datetime.now(timezone.utc).isoformat())
        self.root.mkdir(parents=True, exist_ok=True)

    def request(self, request: SourceApprovalRequest) -> SourceApprovalStatus:
        """Create a new pending approval request."""

        approval_id = self._id_factory()
        status = SourceApprovalStatus(
            approval_id=approval_id,
            kind=request.kind,
            target=request.target,
            status="PENDING",
            created_at=self._clock(),
            decided_at=None,
            decided_by=None,
            notes=None,
        )
        self._write(status)
        return status

    def get(self, approval_id: str) -> SourceApprovalStatus:
        """Fetch a single approval record by id."""

        data = json.loads((self.root / f"{approval_id}.json").read_text(encoding="utf-8"))
        return SourceApprovalStatus(**data)

    def list(
        self, status: Optional[str] = None, kind: Optional[str] = None, limit: int = 100
    ) -> List[SourceApprovalStatus]:
        """List approvals with optional filters."""

        approvals: List[SourceApprovalStatus] = []
        for path in sorted(self.root.glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            if status and data.get("status") != status:
                continue
            if kind and data.get("kind") != kind:
                continue
            approvals.append(SourceApprovalStatus(**data))
            if len(approvals) >= limit:
                break
        return approvals

    def decide(
        self,
        approval_id: str,
        decision: str,
        notes: Optional[str] = None,
        decided_by: Optional[str] = None,
    ) -> SourceApprovalStatus:
        """Approve or deny a pending request."""

        current = self.get(approval_id)
        if current.status != "PENDING":
            return current

        updated = SourceApprovalStatus(
            approval_id=current.approval_id,
            kind=current.kind,
            target=current.target,
            status=decision,
            created_at=current.created_at,
            decided_at=self._clock(),
            decided_by=decided_by,
            notes=notes,
        )
        self._write(updated)
        return updated

    def is_approved(self, kind: str, target: str) -> bool:
        """Check if a specific target has an approved record."""

        for approval in self.list(status="APPROVED", kind=kind, limit=1000):
            if approval.target == target:
                return True
        return False

    def _write(self, status: SourceApprovalStatus) -> None:
        """Persist an approval record to disk."""

        data = json.dumps(status.__dict__, sort_keys=True)
        (self.root / f"{status.approval_id}.json").write_text(data, encoding="utf-8")

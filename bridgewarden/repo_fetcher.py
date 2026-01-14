"""Repository fetcher that scans tarball contents."""

import hashlib
import io
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re
from typing import Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from .audit import AuditLogger
from .pipeline import guard_text
from .quarantine import QuarantineStore


class RepoError(RuntimeError):
    """Raised for repository fetch errors."""

    pass


@dataclass(frozen=True)
class RepoFetcher:
    """Fetch a repo archive, store it, and scan files through the pipeline."""

    http_get: Callable[[str, int], bytes]
    storage_dir: Path
    profile_name: str
    quarantine_store: Optional[QuarantineStore] = None
    audit_logger: Optional[AuditLogger] = None
    max_repo_bytes: int = 10 * 1024 * 1024
    max_file_bytes: int = 256 * 1024
    max_files: int = 2000

    def fetch(
        self,
        url: str,
        ref: Optional[str] = None,
        depth: Optional[int] = None,
        include_paths: Optional[List[str]] = None,
        exclude_paths: Optional[List[str]] = None,
        baseline_revision: Optional[str] = None,
    ) -> Dict[str, object]:
        """Fetch a repo tarball and return findings and summary."""

        repo_id = _repo_id(url)
        revision = _sanitize_ref(ref or "HEAD")
        archive_url = _github_archive_url(url, revision)
        payload = self.http_get(archive_url, self.max_repo_bytes)

        repo_root = self.storage_dir / repo_id / revision
        repo_root.mkdir(parents=True, exist_ok=True)

        findings: List[Dict[str, object]] = []
        quarantine_ids: List[str] = []
        changed_files: List[Dict[str, str]] = []
        allow_count = warn_count = block_count = 0

        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            members = [member for member in archive.getmembers() if member.isreg()]
            if len(members) > self.max_files:
                members = members[: self.max_files]
            root_prefix = _root_prefix(members)

            for member in members:
                rel_path = _relative_path(member.name, root_prefix)
                if not rel_path:
                    continue
                if not _path_allowed(rel_path, include_paths, exclude_paths):
                    continue

                fileobj = archive.extractfile(member)
                if fileobj is None:
                    continue
                content_bytes, content_hash, truncated = _read_member(fileobj, self.max_file_bytes)

                destination = _safe_join(repo_root, rel_path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content_bytes)

                if truncated:
                    findings.append(
                        {
                            "path": rel_path,
                            "decision": "BLOCK",
                            "risk_score": 1.0,
                            "reasons": ["FILE_TOO_LARGE"],
                            "content_hash": content_hash,
                        }
                    )
                    block_count += 1
                else:
                    result = guard_text(
                        content_bytes.decode("utf-8", errors="replace"),
                        source={"kind": "repo", "url": url, "path": rel_path},
                        quarantine_store=self.quarantine_store,
                        profile_name=self.profile_name,
                        audit_logger=self.audit_logger,
                    )
                    findings.append(
                        {
                            "path": rel_path,
                            "decision": result.decision,
                            "risk_score": result.risk_score,
                            "reasons": result.reasons,
                            "content_hash": result.content_hash,
                        }
                    )
                    if result.decision == "ALLOW":
                        allow_count += 1
                    elif result.decision == "WARN":
                        warn_count += 1
                    else:
                        block_count += 1
                        if result.quarantine_id:
                            quarantine_ids.append(result.quarantine_id)

                changed_files.append({"path": rel_path, "status": "added"})

        summary = {
            "total": len(findings),
            "allowed": allow_count,
            "warned": warn_count,
            "blocked": block_count,
            "cache_hits": 0,
        }
        return {
            "repo_id": repo_id,
            "new_revision": revision,
            "changed_files": changed_files,
            "summary": summary,
            "findings": findings,
            "quarantine_ids": quarantine_ids,
        }


def _repo_id(url: str) -> str:
    """Build a deterministic repo id from its URL."""

    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return f"r_{digest[:16]}"


def _github_archive_url(url: str, ref: str) -> str:
    """Create a GitHub codeload URL for a given ref."""

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise RepoError("unsupported repo scheme")
    if parsed.netloc != "github.com":
        raise RepoError("unsupported repo host")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        raise RepoError("invalid GitHub repo URL")
    owner = parts[0]
    repo = parts[1].removesuffix(".git")
    return f"https://codeload.github.com/{owner}/{repo}/tar.gz/{ref}"


def _sanitize_ref(ref: str) -> str:
    """Sanitize ref names for filesystem safety."""

    sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", ref)
    sanitized = sanitized.strip("._-")
    if sanitized in {"", ".", ".."}:
        return "HEAD"
    return sanitized[:100]


def _root_prefix(members: Iterable[tarfile.TarInfo]) -> Optional[str]:
    """Return the top-level directory in a tar archive."""

    for member in members:
        parts = PurePosixPath(member.name).parts
        if parts:
            return parts[0]
    return None


def _relative_path(name: str, root_prefix: Optional[str]) -> str:
    """Strip the archive root prefix from a tar member path."""

    path = PurePosixPath(name)
    parts = list(path.parts)
    if not parts:
        return ""
    if root_prefix and parts[0] == root_prefix:
        parts = parts[1:]
    return str(PurePosixPath(*parts))


def _path_allowed(
    path: str, include_paths: Optional[List[str]], exclude_paths: Optional[List[str]]
) -> bool:
    """Check include/exclude filters for a repo path."""

    if include_paths:
        if not any(path.startswith(prefix.rstrip("/") + "/") or path == prefix for prefix in include_paths):
            return False
    if exclude_paths:
        if any(path.startswith(prefix.rstrip("/") + "/") or path == prefix for prefix in exclude_paths):
            return False
    return True


def _read_member(fileobj: io.BufferedReader, max_bytes: int) -> Tuple[bytes, str, bool]:
    """Read a tar member with size limits and return hash info."""

    hasher = hashlib.sha256()
    buffer = bytearray()
    truncated = False
    while True:
        chunk = fileobj.read(8192)
        if not chunk:
            break
        hasher.update(chunk)
        if len(buffer) < max_bytes:
            remaining = max_bytes - len(buffer)
            buffer.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True
        else:
            truncated = True
    return bytes(buffer), hasher.hexdigest(), truncated


def _safe_join(root: Path, relative_path: str) -> Path:
    """Join paths while preventing traversal outside the repo root."""

    candidate = (root / relative_path).resolve()
    root_resolved = root.resolve()
    if root_resolved == candidate or root_resolved in candidate.parents:
        return candidate
    raise RepoError("path escapes repo root")

"""Tool implementations for BridgeWarden MCP endpoints."""

from dataclasses import asdict
from pathlib import Path
import socket
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse
import ipaddress

from .approvals import SourceApprovalRequest, SourceApprovalStore
from .audit import AuditLogger
from .config import DEFAULT_PROFILE, BridgewardenConfig, POLICY_VERSION
from .pipeline import guard_text
from .types import GuardResult
from .quarantine import QuarantineStore


class ToolError(Exception):
    """Raised for local tool handling errors."""

    pass


def _blocked_result(
    reason: str,
    source: Dict[str, str],
    approval_id: Optional[str] = None,
) -> GuardResult:
    """Create a GuardResult for a blocked request."""

    return GuardResult(
        decision="BLOCK",
        risk_score=1.0,
        reasons=[reason],
        source=source,
        content_hash="",
        sanitized_text="",
        quarantine_id=None,
        redactions=[],
        cache_hit=False,
        policy_version=POLICY_VERSION,
        approval_id=approval_id,
    )


def _blocked_repo_response(
    source: Dict[str, str], reason: str, approval_id: Optional[str] = None
) -> Dict[str, object]:
    """Create a blocked response for repo fetches."""

    return {
        "repo_id": None,
        "new_revision": None,
        "changed_files": [],
        "summary": {
            "total": 0,
            "allowed": 0,
            "warned": 0,
            "blocked": 1,
            "cache_hits": 0,
        },
        "findings": [],
        "quarantine_ids": [],
        "approval_id": approval_id,
        "reasons": [reason],
        "source": source,
    }


def _resolve_profile(profile_name: Optional[str], config: Optional[BridgewardenConfig]) -> str:
    """Resolve the effective policy profile."""

    if profile_name:
        return profile_name
    if config:
        return config.profile
    return DEFAULT_PROFILE


def _domain_allowed(config: Optional[BridgewardenConfig], domain: str) -> bool:
    """Check if a web domain is allowlisted for approvals."""

    if not config:
        return False
    normalized = _normalize_host(domain)
    return normalized in {_normalize_host(item) for item in config.approval_policy.allowed_web_domains}


def _repo_allowed(config: Optional[BridgewardenConfig], url: str) -> bool:
    """Check if a repo URL is allowlisted for approvals."""

    if not config:
        return False
    return url in config.approval_policy.allowed_repo_urls


def _approval_required(config: Optional[BridgewardenConfig]) -> bool:
    """Check if approvals are required by policy."""

    if not config:
        return True
    return config.approval_policy.require_approval


def _network_enabled(config: Optional[BridgewardenConfig]) -> bool:
    """Check if network access is enabled by policy."""

    if not config:
        return False
    return config.network.enabled


def _host_allowed(config: Optional[BridgewardenConfig], host: str, kind: str) -> bool:
    """Check host allowlist for web or repo traffic."""

    if not config:
        return False
    if kind == "web":
        allowlist = config.network.allowed_web_hosts
    else:
        allowlist = config.network.allowed_repo_hosts
    if not allowlist:
        return False
    normalized = _normalize_host(host)
    return normalized in {_normalize_host(item) for item in allowlist}


def _normalize_host(host: str) -> str:
    """Normalize a hostname for comparisons."""

    return host.strip().lower().rstrip(".")


def _normalize_raw_file_url(url: str) -> str:
    """Normalize common raw file URLs to avoid cross-host redirects."""

    parsed = urlparse(url)
    host = _normalize_host(parsed.hostname or "")
    path = parsed.path or ""
    scheme = parsed.scheme or "https"

    if host == "github.com":
        parts = [part for part in path.split("/") if part]
        if len(parts) >= 5 and parts[2] in {"blob", "raw"}:
            org, repo, _, ref = parts[:4]
            tail = "/".join(parts[4:])
            if tail:
                return f"{scheme}://raw.githubusercontent.com/{org}/{repo}/{ref}/{tail}"

    parts = [part for part in path.split("/") if part]
    for idx in range(len(parts) - 2):
        if parts[idx] == "-" and parts[idx + 1] in {"blob", "raw"}:
            if idx >= 2 and idx + 2 < len(parts):
                ref = parts[idx + 2]
                tail = "/".join(parts[idx + 3 :])
                new_path = "/" + "/".join(parts[:idx]) + "/-/raw/" + ref
                if tail:
                    new_path += "/" + tail
                return parsed._replace(path=new_path, query="", fragment="").geturl()

    if host == "bitbucket.org":
        if len(parts) >= 4 and parts[2] in {"src", "raw"}:
            ref = parts[3]
            tail = "/".join(parts[4:])
            new_path = f"/{parts[0]}/{parts[1]}/raw/{ref}"
            if tail:
                new_path += f"/{tail}"
            return parsed._replace(path=new_path, query="", fragment="").geturl()

    return url


def _safe_path(base_dir: Path, path: str) -> Path:
    """Resolve a path and prevent traversal outside the base directory."""

    base = base_dir.resolve()
    candidate = (base_dir / path).resolve()
    if base == candidate or base in candidate.parents:
        return candidate
    raise ToolError("path escapes base directory")


def bw_read_file(
    path: str,
    repo_id: Optional[str] = None,
    mode: str = "safe",
    base_dir: Optional[Path] = None,
    quarantine_store: Optional[QuarantineStore] = None,
    profile_name: Optional[str] = None,
    config: Optional[BridgewardenConfig] = None,
    audit_logger: Optional[AuditLogger] = None,
) -> GuardResult:
    """Read a local file and run it through the guard pipeline."""

    if repo_id:
        return _blocked_result("REPO_ID_UNSUPPORTED", {"kind": "repo", "repo_id": repo_id})

    base = base_dir or Path.cwd()
    try:
        resolved = _safe_path(base, path)
    except ToolError:
        return _blocked_result("PATH_TRAVERSAL", {"kind": "file", "path": path})

    if not resolved.exists() or not resolved.is_file():
        return _blocked_result("FILE_NOT_FOUND", {"kind": "file", "path": path})

    if mode == "raw":
        return _blocked_result("RAW_MODE_NOT_ALLOWED", {"kind": "file", "path": path})
    if mode not in {"safe", "raw"}:
        return _blocked_result("INVALID_MODE", {"kind": "file", "path": path})

    content = resolved.read_bytes().decode("utf-8", errors="replace")
    return guard_text(
        content,
        source={"kind": "file", "path": str(resolved)},
        quarantine_store=quarantine_store,
        profile_name=_resolve_profile(profile_name, config),
        audit_logger=audit_logger,
    )


def _is_ssrf_risk(
    hostname: Optional[str],
    resolver: Optional[Callable[[str], List[str]]] = None,
    allow_localhost: bool = False,
) -> bool:
    """Detect SSRF risk using hostname checks and DNS resolution."""

    if not hostname:
        return True
    normalized = _normalize_host(hostname)
    if normalized in {"localhost", "127.0.0.1", "::1"}:
        return not allow_localhost
    try:
        ip = ipaddress.ip_address(normalized)
        if allow_localhost and ip.is_loopback:
            return False
        return _is_private_ip(ip)
    except ValueError:
        resolved = _resolve_ips(normalized, resolver)
        if not resolved:
            return True
        for ip in resolved:
            try:
                parsed_ip = ipaddress.ip_address(ip)
            except ValueError:
                return True
            if allow_localhost and parsed_ip.is_loopback:
                continue
            if _is_private_ip(parsed_ip):
                return True
        return False


def _resolve_ips(hostname: str, resolver: Optional[Callable[[str], List[str]]]) -> List[str]:
    """Resolve hostnames to IPs using DNS or a provided resolver."""

    if resolver is not None:
        return resolver(hostname)
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    ips: List[str] = []
    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET:
            ips.append(sockaddr[0])
        elif family == socket.AF_INET6:
            ips.append(sockaddr[0])
    return ips


def _is_private_ip(ip: ipaddress._BaseAddress) -> bool:
    """Classify IPs that should be blocked for SSRF protection."""

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def bw_web_fetch(
    url: str,
    mode: str = "readable_text",
    max_bytes: Optional[int] = None,
    approvals: Optional[SourceApprovalStore] = None,
    fetcher: Optional[Callable[[str, int], str]] = None,
    quarantine_store: Optional[QuarantineStore] = None,
    profile_name: Optional[str] = None,
    config: Optional[BridgewardenConfig] = None,
    audit_logger: Optional[AuditLogger] = None,
    dns_resolver: Optional[Callable[[str], List[str]]] = None,
) -> GuardResult:
    """Fetch web content via a configured fetcher and guard it."""

    original_url = url
    url = _normalize_raw_file_url(url)
    parsed = urlparse(url)
    domain = _normalize_host(parsed.hostname or "")
    source = {"kind": "web", "url": original_url, "domain": domain}
    if url != original_url:
        source["resolved_url"] = url

    if parsed.scheme not in {"http", "https"}:
        return _blocked_result("UNSUPPORTED_URL_SCHEME", source)

    if not _network_enabled(config):
        return _blocked_result("NETWORK_DISABLED", source)

    if not _host_allowed(config, source["domain"], "web"):
        return _blocked_result("NETWORK_HOST_BLOCKED", source)

    if _is_ssrf_risk(
        parsed.hostname,
        resolver=dns_resolver,
        allow_localhost=bool(config and config.network.allow_localhost),
    ):
        return _blocked_result("SSRF_BLOCKED", source)

    if _domain_allowed(config, source["domain"]):
        approvals_required = False
    else:
        approvals_required = _approval_required(config)

    if approvals_required and approvals is None:
        return _blocked_result("NEW_SOURCE_REQUIRES_APPROVAL", source, None)

    if approvals_required and not approvals.is_approved("web_domain", source["domain"]):
        approval = approvals.request(
            SourceApprovalRequest(kind="web_domain", target=source["domain"])
        )
        return _blocked_result("NEW_SOURCE_REQUIRES_APPROVAL", source, approval.approval_id)

    if fetcher is None:
        return _blocked_result("NETWORK_DISABLED", source)

    if mode not in {"readable_text", "raw_text"}:
        return _blocked_result("INVALID_MODE", source)

    if max_bytes is not None and max_bytes <= 0:
        return _blocked_result("INVALID_MAX_BYTES", source)

    if max_bytes is None:
        limit = config.network.web_max_bytes if config else 1024 * 1024
    else:
        limit = max_bytes
    if config is not None:
        limit = min(limit, config.network.web_max_bytes)
    try:
        text = fetcher(url, limit)
    except Exception as exc:
        return _blocked_result("NETWORK_ERROR", source, None)
    return guard_text(
        text,
        source=source,
        quarantine_store=quarantine_store,
        profile_name=_resolve_profile(profile_name, config),
        audit_logger=audit_logger,
    )


def bw_fetch_repo(
    url: str,
    ref: Optional[str] = None,
    depth: Optional[int] = None,
    include_paths: Optional[list] = None,
    exclude_paths: Optional[list] = None,
    baseline_revision: Optional[str] = None,
    approvals: Optional[SourceApprovalStore] = None,
    fetcher: Optional[Callable[..., dict]] = None,
    config: Optional[BridgewardenConfig] = None,
) -> Dict[str, object]:
    """Fetch and scan a repository via a configured fetcher."""

    source = {"kind": "repo", "url": url}
    parsed = urlparse(url)
    host = _normalize_host(parsed.hostname or "")
    archive_host = _repo_archive_host(url)

    if not _network_enabled(config):
        return _blocked_repo_response(source, "NETWORK_DISABLED")

    if not _host_allowed(config, host, "repo"):
        return _blocked_repo_response(source, "NETWORK_HOST_BLOCKED")
    if archive_host and not _host_allowed(config, archive_host, "repo"):
        return _blocked_repo_response(source, "NETWORK_HOST_BLOCKED")

    if _repo_allowed(config, url):
        approvals_required = False
    else:
        approvals_required = _approval_required(config)

    if approvals_required and approvals is None:
        return _blocked_repo_response(source, "NEW_SOURCE_REQUIRES_APPROVAL")

    if approvals_required and not approvals.is_approved("repo_url", url):
        approval = approvals.request(SourceApprovalRequest(kind="repo_url", target=url))
        return _blocked_repo_response(
            source, "NEW_SOURCE_REQUIRES_APPROVAL", approval_id=approval.approval_id
        )

    if fetcher is None:
        return _blocked_repo_response(source, "NETWORK_DISABLED")

    try:
        return fetcher(
            url=url,
            ref=ref,
            depth=depth,
            include_paths=include_paths,
            exclude_paths=exclude_paths,
            baseline_revision=baseline_revision,
        )
    except Exception:
        return _blocked_repo_response(source, "REPO_FETCH_FAILED")


def _repo_archive_host(url: str) -> Optional[str]:
    """Return the archive host used for repo fetches."""

    parsed = urlparse(url)
    host = _normalize_host(parsed.hostname or "")
    if host == "github.com":
        return "codeload.github.com"
    return host or None


def bw_quarantine_get(
    quarantine_id: str, store: QuarantineStore, excerpt_limit: int = 200
) -> Dict[str, object]:
    """Fetch a sanitized quarantine view for review."""

    view = store.get_view(quarantine_id, excerpt_limit=excerpt_limit)
    metadata = dict(view.metadata)
    return {
        "original_excerpt": view.original_excerpt,
        "sanitized_text": view.sanitized_text,
        "metadata": metadata,
        "reasons": metadata.get("reasons", []),
        "risk_score": metadata.get("risk_score", 0.0),
    }


def bw_request_source_approval(
    store: SourceApprovalStore, request: Dict[str, str]
) -> Dict[str, object]:
    """Create a new source approval request."""

    status = store.request(SourceApprovalRequest(**request))
    return asdict(status)


def bw_get_source_approval(store: SourceApprovalStore, approval_id: str) -> Dict[str, object]:
    """Fetch a single source approval record."""

    return asdict(store.get(approval_id))


def bw_list_source_approvals(
    store: SourceApprovalStore,
    status: Optional[str] = None,
    kind: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, object]:
    """List source approvals with optional filters."""

    approvals = store.list(status=status, kind=kind, limit=limit)
    return {"approvals": [asdict(approval) for approval in approvals]}


def bw_decide_source_approval(
    store: SourceApprovalStore,
    approval_id: str,
    decision: str,
    notes: Optional[str] = None,
    decided_by: Optional[str] = None,
) -> Dict[str, object]:
    """Approve or deny a pending source approval request."""

    status = store.decide(approval_id, decision, notes=notes, decided_by=decided_by)
    return asdict(status)

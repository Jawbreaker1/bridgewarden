#!/usr/bin/env python3
import io
import json
import tarfile
from pathlib import Path
from typing import Dict

"""Local demo runner for BridgeWarden tools."""

from bridgewarden.approvals import SourceApprovalStore
from bridgewarden.audit import AuditLogger
from bridgewarden.config import ApprovalPolicy, BridgewardenConfig, NetworkPolicy
from bridgewarden.quarantine import QuarantineStore
from bridgewarden.repo_fetcher import RepoFetcher
from bridgewarden.tools import (
    bw_decide_source_approval,
    bw_fetch_repo,
    bw_quarantine_get,
    bw_web_fetch,
)


def _repo_root() -> Path:
    """Return the repo root directory."""

    return Path(__file__).resolve().parents[1]


def _demo_data_dir() -> Path:
    """Return the demo data directory under .bridgewarden."""

    return _repo_root() / ".bridgewarden" / "demo"


def _load_fixture(path: Path) -> str:
    """Load a text fixture from disk."""

    return path.read_text(encoding="utf-8")


def _build_tarball(files: Dict[str, bytes]) -> bytes:
    """Create a gzip tarball from a mapping of file names to payloads."""

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, payload in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _print_guard(label: str, result) -> None:
    """Print a single GuardResult in a compact form."""

    print(f"{label}: decision={result.decision} risk={result.risk_score} reasons={result.reasons}")
    if result.quarantine_id:
        print(f"  quarantine_id={result.quarantine_id}")


def _print_repo_summary(result: dict) -> None:
    """Print a summary of repo scan findings."""

    summary = result.get("summary", {})
    print(
        "repo summary: total={total} allowed={allowed} warned={warned} blocked={blocked}".format(
            **summary
        )
    )
    for finding in result.get("findings", []):
        print(
            f"  {finding['path']}: decision={finding['decision']} reasons={finding['reasons']}"
        )


def main() -> None:
    """Run the local demo flows."""

    root = _repo_root()
    data_dir = _demo_data_dir()
    approvals = SourceApprovalStore(data_dir / "approvals")
    quarantine = QuarantineStore(data_dir / "quarantine")
    audit_logger = AuditLogger(data_dir / "logs" / "audit.jsonl")

    config = BridgewardenConfig(
        profile="balanced",
        approval_policy=ApprovalPolicy(require_approval=True),
        network=NetworkPolicy(
            enabled=True,
            allowed_web_hosts=["demo.local"],
            allowed_repo_hosts=["github.com", "codeload.github.com"],
        ),
    )

    fixtures = {
        "https://demo.local/benign": root
        / "test-corpus/fixtures/benign_allow_readme.md",
        "https://demo.local/injected": root
        / "test-corpus/fixtures/injected_warn_role.md",
        "https://demo.local/sabotage": root
        / "test-corpus/fixtures/injected_block_sabotage.md",
    }

    def web_fetcher(url: str, limit: int) -> str:
        if url not in fixtures:
            raise ValueError("unknown demo url")
        content = _load_fixture(fixtures[url])
        return content[:limit]

    dns_resolver = lambda host: ["93.184.216.34"]

    print("== Web fetch demo ==")
    demo_url = "https://demo.local/injected"
    raw_text = _load_fixture(fixtures[demo_url])
    print("raw preview:")
    print(raw_text.splitlines()[0])

    first = bw_web_fetch(
        demo_url,
        approvals=approvals,
        config=config,
        fetcher=web_fetcher,
        dns_resolver=dns_resolver,
        audit_logger=audit_logger,
    )
    _print_guard("first fetch", first)

    if first.approval_id:
        bw_decide_source_approval(approvals, first.approval_id, "APPROVED")

    second = bw_web_fetch(
        demo_url,
        approvals=approvals,
        config=config,
        fetcher=web_fetcher,
        dns_resolver=dns_resolver,
        audit_logger=audit_logger,
    )
    _print_guard("approved fetch", second)

    print("\n== Repo fetch demo ==")
    repo_url = "https://github.com/demo/bridgewarden-demo"
    repo_files = {
        "bridgewarden-demo-HEAD/README.md": _load_fixture(
            root / "test-corpus/fixtures/benign_allow_readme.md"
        ).encode("utf-8"),
        "bridgewarden-demo-HEAD/injected.md": _load_fixture(
            root / "test-corpus/fixtures/injected_warn_role.md"
        ).encode("utf-8"),
        "bridgewarden-demo-HEAD/sabotage.md": _load_fixture(
            root / "test-corpus/fixtures/injected_block_sabotage.md"
        ).encode("utf-8"),
    }
    tarball = _build_tarball(repo_files)

    def http_get(url: str, max_bytes: int) -> bytes:
        if max_bytes < len(tarball):
            raise RuntimeError("tarball exceeds max_bytes")
        return tarball

    repo_fetcher = RepoFetcher(
        http_get=http_get,
        storage_dir=data_dir / "repos",
        profile_name=config.profile,
        quarantine_store=quarantine,
        audit_logger=audit_logger,
    )

    repo_first = bw_fetch_repo(repo_url, approvals=approvals, fetcher=repo_fetcher.fetch, config=config)
    print("first repo fetch:")
    print(json.dumps({"reasons": repo_first.get("reasons"), "approval_id": repo_first.get("approval_id")}, indent=2))

    if repo_first.get("approval_id"):
        bw_decide_source_approval(approvals, repo_first["approval_id"], "APPROVED")

    repo_second = bw_fetch_repo(
        repo_url, approvals=approvals, fetcher=repo_fetcher.fetch, config=config
    )
    _print_repo_summary(repo_second)

    if repo_second.get("quarantine_ids"):
        print("\nquarantine views:")
        for qid in repo_second["quarantine_ids"]:
            view = bw_quarantine_get(qid, quarantine)
            print(json.dumps({"id": qid, "original_excerpt": view["original_excerpt"]}, indent=2))

    print("\nAudit log:")
    print(str(data_dir / "logs" / "audit.jsonl"))


if __name__ == "__main__":
    main()

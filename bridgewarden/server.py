"""Minimal stdio MCP server harness for BridgeWarden."""

from dataclasses import asdict, dataclass, is_dataclass
from functools import partial
import json
from pathlib import Path
import sys
from typing import Callable, Dict, IO, Optional

from .approvals import SourceApprovalStore
from .audit import AuditLogger
from .config import BridgewardenConfig, load_config
from .network import HttpClient, WebFetcher
from .quarantine import QuarantineStore
from .repo_fetcher import RepoFetcher
from .tools import (
    bw_decide_source_approval,
    bw_fetch_repo,
    bw_get_source_approval,
    bw_list_source_approvals,
    bw_quarantine_get,
    bw_read_file,
    bw_request_source_approval,
    bw_web_fetch,
)

DEFAULT_CONFIG_PATH = Path("config/bridgewarden.yaml")
DEFAULT_DATA_DIR = Path(".bridgewarden")


@dataclass(frozen=True)
class BridgewardenContext:
    """Runtime context holding config and storage handles."""

    config: BridgewardenConfig
    approvals: SourceApprovalStore
    quarantine: QuarantineStore
    audit_logger: AuditLogger
    base_dir: Path
    web_fetcher: Optional[Callable[[str, int], str]]
    repo_fetcher: Optional[Callable[..., Dict[str, object]]]


def load_context(
    config_path: Optional[Path] = None,
    data_dir: Optional[Path] = None,
    base_dir: Optional[Path] = None,
) -> BridgewardenContext:
    """Load configuration and initialize storage backends."""

    resolved_config = load_config(config_path or DEFAULT_CONFIG_PATH)
    resolved_base = base_dir or Path.cwd()
    resolved_data_dir = data_dir or resolved_base / DEFAULT_DATA_DIR
    approvals_dir = resolved_data_dir / "approvals"
    quarantine_dir = resolved_data_dir / "quarantine"
    logs_dir = resolved_data_dir / "logs"
    repos_dir = resolved_data_dir / "repos"
    approvals_dir.mkdir(parents=True, exist_ok=True)
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    repos_dir.mkdir(parents=True, exist_ok=True)
    approvals = SourceApprovalStore(approvals_dir)
    quarantine = QuarantineStore(quarantine_dir)
    audit_logger = AuditLogger(logs_dir / "audit.jsonl")
    web_fetcher = None
    repo_fetcher = None
    if resolved_config.network.enabled:
        http_client = HttpClient(timeout_seconds=resolved_config.network.timeout_seconds)
        web_fetcher = WebFetcher(http_client)
        repo_fetcher = RepoFetcher(
            http_get=http_client.get,
            storage_dir=repos_dir,
            profile_name=resolved_config.profile,
            quarantine_store=quarantine,
            audit_logger=audit_logger,
            max_repo_bytes=resolved_config.network.repo_max_bytes,
            max_file_bytes=resolved_config.network.repo_max_file_bytes,
            max_files=resolved_config.network.repo_max_files,
        )
    return BridgewardenContext(
        config=resolved_config,
        approvals=approvals,
        quarantine=quarantine,
        audit_logger=audit_logger,
        base_dir=resolved_base,
        web_fetcher=web_fetcher,
        repo_fetcher=repo_fetcher,
    )


def build_tool_handlers(context: BridgewardenContext) -> Dict[str, Callable[..., object]]:
    """Build tool handler callables bound to the runtime context."""

    return {
        "bw_read_file": partial(
            bw_read_file,
            base_dir=context.base_dir,
            quarantine_store=context.quarantine,
            config=context.config,
            audit_logger=context.audit_logger,
        ),
        "bw_web_fetch": partial(
            bw_web_fetch,
            approvals=context.approvals,
            quarantine_store=context.quarantine,
            config=context.config,
            audit_logger=context.audit_logger,
            fetcher=context.web_fetcher,
        ),
        "bw_fetch_repo": partial(
            bw_fetch_repo,
            approvals=context.approvals,
            config=context.config,
            fetcher=context.repo_fetcher,
        ),
        "bw_quarantine_get": partial(bw_quarantine_get, store=context.quarantine),
        "bw_request_source_approval": partial(bw_request_source_approval, context.approvals),
        "bw_get_source_approval": partial(bw_get_source_approval, context.approvals),
        "bw_list_source_approvals": partial(bw_list_source_approvals, context.approvals),
        "bw_decide_source_approval": partial(bw_decide_source_approval, context.approvals),
    }


class BridgewardenServer:
    """Dispatch tool calls from JSON requests."""

    def __init__(self, handlers: Dict[str, Callable[..., object]]) -> None:
        """Initialize the server with tool handlers."""

        self._handlers = handlers

    def handle_request(self, request: Dict[str, object]) -> Dict[str, object]:
        """Handle a single tool request payload."""

        request_id = request.get("id")
        tool = request.get("tool")
        args = request.get("args", {})
        if not isinstance(tool, str):
            return self._error(request_id, "INVALID_REQUEST", "missing tool name")
        if not isinstance(args, dict):
            return self._error(request_id, "INVALID_REQUEST", "args must be an object")
        handler = self._handlers.get(tool)
        if handler is None:
            return self._error(request_id, "UNKNOWN_TOOL", f"unknown tool: {tool}")
        try:
            result = handler(**args)
        except Exception as exc:
            return self._error(request_id, "TOOL_ERROR", str(exc))
        return {"id": request_id, "result": self._serialize(result)}

    def _serialize(self, result: object) -> object:
        """Serialize dataclass results to plain dicts."""

        if is_dataclass(result):
            return asdict(result)
        return result

    def _error(self, request_id: object, code: str, message: str) -> Dict[str, object]:
        """Create a standard error payload."""

        return {"id": request_id, "error": {"code": code, "message": message}}


def serve_stdio(
    server: BridgewardenServer,
    input_stream: IO[str] = sys.stdin,
    output_stream: IO[str] = sys.stdout,
) -> None:
    """Serve line-delimited JSON requests over stdio."""

    for line in input_stream:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            response = {"id": None, "error": {"code": "INVALID_JSON", "message": str(exc)}}
        else:
            if not isinstance(request, dict):
                response = {
                    "id": None,
                    "error": {"code": "INVALID_REQUEST", "message": "request must be an object"},
                }
            else:
                response = server.handle_request(request)
        output_stream.write(json.dumps(response, ensure_ascii=True) + "\n")
        output_stream.flush()


def main(argv: Optional[list] = None) -> int:
    """CLI entrypoint for the stdio MCP server."""

    import argparse

    parser = argparse.ArgumentParser(description="BridgeWarden MCP stdio server")
    parser.add_argument(
        "--config",
        dest="config_path",
        default=str(DEFAULT_CONFIG_PATH),
        help="Path to config/bridgewarden.yaml (JSON-compatible YAML)",
    )
    parser.add_argument(
        "--data-dir",
        dest="data_dir",
        default=str(DEFAULT_DATA_DIR),
        help="Path to data directory (.bridgewarden by default)",
    )
    parser.add_argument(
        "--base-dir",
        dest="base_dir",
        default=str(Path.cwd()),
        help="Base directory for file access",
    )
    args = parser.parse_args(argv)

    context = load_context(
        config_path=Path(args.config_path),
        data_dir=Path(args.data_dir),
        base_dir=Path(args.base_dir),
    )
    server = BridgewardenServer(build_tool_handlers(context))
    serve_stdio(server)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

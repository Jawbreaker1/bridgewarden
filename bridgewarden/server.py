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
JSONRPC_VERSION = "2.0"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]
SERVER_NAME = "bridgewarden"
SERVER_VERSION = "0.1.0"

TOOL_DEFINITIONS: Dict[str, Dict[str, object]] = {
    "bw_read_file": {
        "name": "bw_read_file",
        "description": "Read a file and return a GuardResult.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_id": {"type": "string", "description": "Optional repo id."},
                "path": {"type": "string", "description": "Path to file."},
                "mode": {
                    "type": "string",
                    "enum": ["safe", "raw"],
                    "description": "Read mode (default safe).",
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    "bw_web_fetch": {
        "name": "bw_web_fetch",
        "description": "Fetch a URL and return a GuardResult.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to fetch."},
                "mode": {
                    "type": "string",
                    "enum": ["readable_text", "raw_text"],
                    "description": "Response mode (default readable_text).",
                },
                "max_bytes": {
                    "type": "integer",
                    "description": "Optional max bytes (clamped by policy).",
                },
            },
            "required": ["url"],
            "additionalProperties": False,
        },
    },
    "bw_fetch_repo": {
        "name": "bw_fetch_repo",
        "description": "Fetch a repository and scan its contents.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Repository URL."},
                "ref": {"type": "string", "description": "Optional git ref."},
                "depth": {"type": "integer", "description": "Optional clone depth."},
                "include_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional include paths.",
                },
                "exclude_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional exclude paths.",
                },
                "baseline_revision": {
                    "type": "string",
                    "description": "Optional baseline revision.",
                },
            },
            "required": ["url"],
            "additionalProperties": False,
        },
    },
    "bw_quarantine_get": {
        "name": "bw_quarantine_get",
        "description": "Retrieve a quarantined excerpt by id.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string", "description": "Quarantine id."}},
            "required": ["id"],
            "additionalProperties": False,
        },
    },
    "bw_request_source_approval": {
        "name": "bw_request_source_approval",
        "description": "Request approval for a new source.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request": {
                    "type": "object",
                    "properties": {
                        "kind": {
                            "type": "string",
                            "enum": ["web_domain", "repo_url", "upstream_mcp_server"],
                        },
                        "target": {"type": "string"},
                        "rationale": {"type": "string"},
                        "requested_by": {"type": "string"},
                    },
                    "required": ["kind", "target"],
                    "additionalProperties": False,
                }
            },
            "required": ["request"],
            "additionalProperties": False,
        },
    },
    "bw_get_source_approval": {
        "name": "bw_get_source_approval",
        "description": "Get an approval request status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "approval_id": {"type": "string", "description": "Approval id."}
            },
            "required": ["approval_id"],
            "additionalProperties": False,
        },
    },
    "bw_list_source_approvals": {
        "name": "bw_list_source_approvals",
        "description": "List source approval requests.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["PENDING", "APPROVED", "DENIED"],
                },
                "kind": {
                    "type": "string",
                    "enum": ["web_domain", "repo_url", "upstream_mcp_server"],
                },
                "limit": {"type": "integer"},
            },
            "additionalProperties": False,
        },
    },
    "bw_decide_source_approval": {
        "name": "bw_decide_source_approval",
        "description": "Approve or deny a source approval request.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "approval_id": {"type": "string"},
                "decision": {"type": "string", "enum": ["APPROVED", "DENIED"]},
                "notes": {"type": "string"},
            },
            "required": ["approval_id", "decision"],
            "additionalProperties": False,
        },
    },
}


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
    """Dispatch JSON-RPC MCP requests for BridgeWarden tools."""

    def __init__(self, handlers: Dict[str, Callable[..., object]]) -> None:
        """Initialize the server with tool handlers."""

        self._handlers = handlers
        self._protocol_version = DEFAULT_PROTOCOL_VERSION
        self._initialized = False

    def handle_request(self, request: Dict[str, object]) -> Optional[Dict[str, object]]:
        """Handle a single JSON-RPC MCP request payload."""

        if request.get("jsonrpc") != JSONRPC_VERSION:
            return self._error(None, -32600, "invalid or missing jsonrpc version")
        method = request.get("method")
        if not isinstance(method, str):
            return self._error(request.get("id"), -32600, "missing method")
        params = request.get("params", {})
        if params is None:
            params = {}
        request_id = request.get("id")

        if method == "initialize":
            return self._handle_initialize(request_id, params)
        if method == "notifications/initialized":
            self._initialized = True
            return None
        if method == "ping":
            return self._result(request_id, {})
        if method == "tools/list":
            return self._handle_tools_list(request_id, params)
        if method == "tools/call":
            return self._handle_tools_call(request_id, params)

        if request_id is None:
            return None
        return self._error(request_id, -32601, f"unknown method: {method}")

    def _serialize(self, result: object) -> object:
        """Serialize dataclass results to plain dicts."""

        if is_dataclass(result):
            return asdict(result)
        return result

    def _handle_initialize(
        self, request_id: object, params: object
    ) -> Dict[str, object]:
        """Handle the MCP initialize handshake."""

        if not isinstance(params, dict):
            return self._error(request_id, -32602, "params must be an object")
        version = params.get("protocolVersion")
        if isinstance(version, str):
            if version in SUPPORTED_PROTOCOL_VERSIONS:
                self._protocol_version = version
            else:
                self._protocol_version = DEFAULT_PROTOCOL_VERSION
        return self._result(
            request_id,
            {
                "protocolVersion": self._protocol_version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        )

    def _handle_tools_list(
        self, request_id: object, params: object
    ) -> Dict[str, object]:
        """Return the list of available tools."""

        if not isinstance(params, dict) and params is not None:
            return self._error(request_id, -32602, "params must be an object")
        tools = []
        for name in sorted(self._handlers):
            definition = TOOL_DEFINITIONS.get(name)
            if definition is None:
                tools.append(
                    {
                        "name": name,
                        "description": "BridgeWarden tool.",
                        "inputSchema": {"type": "object"},
                    }
                )
            else:
                tools.append(definition)
        return self._result(request_id, {"tools": tools, "nextCursor": None})

    def _handle_tools_call(
        self, request_id: object, params: object
    ) -> Dict[str, object]:
        """Invoke a tool and wrap its output."""

        if not isinstance(params, dict):
            return self._error(request_id, -32602, "params must be an object")
        name = params.get("name") or params.get("tool")
        if not isinstance(name, str):
            return self._error(request_id, -32602, "missing tool name")
        arguments = params.get("arguments", params.get("args", {}))
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return self._error(request_id, -32602, "arguments must be an object")
        handler = self._handlers.get(name)
        if handler is None:
            return self._tool_error(request_id, f"unknown tool: {name}")
        try:
            result = handler(**arguments)
        except Exception as exc:
            return self._tool_error(request_id, str(exc))
        serialized = self._serialize(result)
        payload = json.dumps(serialized, ensure_ascii=True)
        return self._result(
            request_id,
            {"content": [{"type": "text", "text": payload}], "isError": False},
        )

    def _result(self, request_id: object, result: object) -> Dict[str, object]:
        """Create a JSON-RPC success payload."""

        return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}

    def _tool_error(self, request_id: object, message: str) -> Dict[str, object]:
        """Return a tool error payload."""

        return self._result(
            request_id,
            {"content": [{"type": "text", "text": message}], "isError": True},
        )

    def _error(self, request_id: object, code: int, message: str) -> Dict[str, object]:
        """Create a JSON-RPC error payload."""

        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": request_id,
            "error": {"code": code, "message": message},
        }


def serve_stdio(
    server: BridgewardenServer,
    input_stream: IO[str] = sys.stdin,
    output_stream: IO[str] = sys.stdout,
) -> None:
    """Serve line-delimited JSON-RPC requests over stdio."""

    for line in input_stream:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            response = server._error(None, -32700, str(exc))
        else:
            if isinstance(request, list):
                responses = []
                for entry in request:
                    if not isinstance(entry, dict):
                        responses.append(server._error(None, -32600, "request must be an object"))
                        continue
                    response = server.handle_request(entry)
                    if response is not None:
                        responses.append(response)
                if responses:
                    output_stream.write(json.dumps(responses, ensure_ascii=True) + "\n")
                    output_stream.flush()
                continue
            if not isinstance(request, dict):
                response = server._error(None, -32600, "request must be an object")
            else:
                response = server.handle_request(request)
            if response is None:
                continue
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

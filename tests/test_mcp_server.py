import json
import tempfile
from pathlib import Path
import unittest

from bridgewarden.server import BridgewardenServer, build_tool_handlers, load_context


class MCPServerTests(unittest.TestCase):
    def test_initialize(self) -> None:
        server = BridgewardenServer({})
        response = server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "clientInfo": {"name": "test", "version": "0.0.0"},
                },
            }
        )
        self.assertEqual(response["result"]["protocolVersion"], "2025-03-26")
        self.assertIn("tools", response["result"]["capabilities"])

    def test_handle_request_dispatches_tool(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            config_dir = tmp_path / "config"
            config_dir.mkdir()
            config_path = config_dir / "bridgewarden.yaml"
            config_path.write_text(json.dumps({"profile": "balanced", "approvals": {}}))
            file_path = tmp_path / "note.txt"
            file_path.write_text("hello", encoding="utf-8")

            context = load_context(
                config_path=config_path,
                data_dir=tmp_path / "data",
                base_dir=tmp_path,
            )
            server = BridgewardenServer(build_tool_handlers(context))
            response = server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": "2",
                    "method": "tools/call",
                    "params": {"name": "bw_read_file", "arguments": {"path": "note.txt"}},
                }
            )
            self.assertIn("result", response)
            content = response["result"]["content"][0]["text"]
            guard = json.loads(content)
            self.assertEqual(guard["decision"], "ALLOW")

    def test_unknown_tool_returns_error_payload(self) -> None:
        server = BridgewardenServer({})
        response = server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": "3",
                "method": "tools/call",
                "params": {"name": "missing", "arguments": {}},
            }
        )
        self.assertTrue(response["result"]["isError"])

    def test_tools_list(self) -> None:
        server = BridgewardenServer({"bw_read_file": lambda: None})
        response = server.handle_request(
            {"jsonrpc": "2.0", "id": "4", "method": "tools/list", "params": {}}
        )
        tools = response["result"]["tools"]
        self.assertTrue(any(tool["name"] == "bw_read_file" for tool in tools))

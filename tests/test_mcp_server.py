import json
import tempfile
from pathlib import Path
import unittest

from bridgewarden.server import BridgewardenServer, build_tool_handlers, load_context


class MCPServerTests(unittest.TestCase):
    def test_handle_request_unknown_tool(self) -> None:
        server = BridgewardenServer({})
        response = server.handle_request({"id": "1", "tool": "missing", "args": {}})
        self.assertIn("error", response)
        self.assertEqual(response["error"]["code"], "UNKNOWN_TOOL")

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
                {"id": "2", "tool": "bw_read_file", "args": {"path": "note.txt"}}
            )
            self.assertIn("result", response)
            self.assertEqual(response["result"]["decision"], "ALLOW")

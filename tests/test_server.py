import json
import tempfile
from pathlib import Path
import unittest

from bridgewarden.server import build_tool_handlers, load_context


class ServerTests(unittest.TestCase):
    def test_load_context_reads_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            config_dir = tmp_path / "config"
            config_dir.mkdir()
            config_path = config_dir / "bridgewarden.yaml"
            config_path.write_text(
                json.dumps(
                    {
                        "profile": "strict",
                        "approvals": {
                            "require_approval": True,
                            "allowed_web_domains": ["example.com"],
                            "allowed_repo_urls": [],
                        },
                    }
                ),
                encoding="utf-8",
            )
            context = load_context(
                config_path=config_path,
                data_dir=tmp_path / "data",
                base_dir=tmp_path,
            )
            self.assertEqual(context.config.profile, "strict")
            self.assertTrue((tmp_path / "data" / "approvals").exists())
            self.assertTrue((tmp_path / "data" / "quarantine").exists())
            self.assertTrue((tmp_path / "data" / "logs").exists())
            self.assertTrue((tmp_path / "data" / "repos").exists())

    def test_tool_handlers_use_context_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            config_dir = tmp_path / "config"
            config_dir.mkdir()
            config_path = config_dir / "bridgewarden.yaml"
            config_path.write_text(
                json.dumps(
                    {
                        "profile": "balanced",
                        "approvals": {
                            "require_approval": True,
                            "allowed_web_domains": ["example.com"],
                            "allowed_repo_urls": [],
                        },
                        "network": {
                            "enabled": True,
                            "allowed_web_hosts": ["example.com"],
                            "allowed_repo_hosts": ["github.com"],
                        },
                    }
                ),
                encoding="utf-8",
            )
            context = load_context(
                config_path=config_path,
                data_dir=tmp_path / "data",
                base_dir=tmp_path,
            )
            handlers = build_tool_handlers(context)

            def fetcher(url: str, limit: int) -> str:
                return "hello"

            result = handlers["bw_web_fetch"](
                "https://example.com",
                fetcher=fetcher,
                dns_resolver=lambda host: ["93.184.216.34"],
            )
            self.assertEqual(result.decision, "ALLOW")

import json
import tempfile
from pathlib import Path
import unittest

from bridgewarden.config import ApprovalPolicy, BridgewardenConfig, ConfigError, load_config


class ConfigTests(unittest.TestCase):
    def test_load_config_defaults_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = load_config(Path(tmpdir) / "missing.yaml")
            self.assertEqual(config.profile, "balanced")
            self.assertTrue(config.approval_policy.require_approval)

    def test_load_config_parses_json_yaml(self) -> None:
        data = {
            "profile": "strict",
            "approvals": {
                "require_approval": True,
                "allowed_web_domains": ["example.com"],
                "allowed_repo_urls": ["https://github.com/org/repo"],
            },
            "network": {
                "enabled": True,
                "timeout_seconds": 5,
                "web_max_bytes": 100,
                "repo_max_bytes": 200,
                "repo_max_file_bytes": 50,
                "repo_max_files": 10,
                "allowed_web_hosts": ["example.com"],
                "allowed_repo_hosts": ["github.com"],
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "bridgewarden.yaml"
            path.write_text(json.dumps(data), encoding="utf-8")
            config = load_config(path)
            self.assertEqual(config.profile, "strict")
            self.assertEqual(config.approval_policy.allowed_web_domains, ["example.com"])
            self.assertEqual(
                config.approval_policy.allowed_repo_urls, ["https://github.com/org/repo"]
            )
            self.assertTrue(config.network.enabled)
            self.assertEqual(config.network.web_max_bytes, 100)
            self.assertEqual(config.network.allowed_repo_hosts, ["github.com"])

    def test_load_config_rejects_invalid_types(self) -> None:
        bad = {"profile": 123, "approvals": "nope"}
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "bridgewarden.yaml"
            path.write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)

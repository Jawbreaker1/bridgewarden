"""Configuration parsing and defaults for BridgeWarden."""

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import List, Optional

POLICY_VERSION = "0.1.0-dev"
DEFAULT_PROFILE = "balanced"


class ConfigError(ValueError):
    """Raised when configuration parsing or validation fails."""

    pass


@dataclass(frozen=True)
class ApprovalPolicy:
    """Policy settings for source approvals."""

    require_approval: bool = True
    allowed_web_domains: List[str] = field(default_factory=list)
    allowed_repo_urls: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class NetworkPolicy:
    """Controls network access and resource limits."""

    enabled: bool = False
    timeout_seconds: float = 10.0
    web_max_bytes: int = 1024 * 1024
    repo_max_bytes: int = 10 * 1024 * 1024
    repo_max_file_bytes: int = 256 * 1024
    repo_max_files: int = 2000
    allowed_web_hosts: List[str] = field(default_factory=list)
    allowed_repo_hosts: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class BridgewardenConfig:
    """Root configuration object for BridgeWarden."""

    profile: str = DEFAULT_PROFILE
    approval_policy: ApprovalPolicy = field(default_factory=ApprovalPolicy)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)


DEFAULT_CONFIG = BridgewardenConfig()


def load_config(path: Path) -> BridgewardenConfig:
    """Load configuration from a JSON-compatible YAML file path."""

    if not path.exists():
        return DEFAULT_CONFIG

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError("config must be JSON-compatible YAML") from exc
    if not isinstance(data, dict):
        raise ConfigError("config must be a JSON object")
    return config_from_dict(data)


def config_from_dict(data: dict) -> BridgewardenConfig:
    """Parse configuration from a Python dict."""

    profile = data.get("profile", DEFAULT_PROFILE)
    if not isinstance(profile, str):
        raise ConfigError("profile must be a string")

    approvals = data.get("approvals", {})
    if approvals is None:
        approvals = {}
    if not isinstance(approvals, dict):
        raise ConfigError("approvals must be an object")

    require_approval = approvals.get("require_approval", True)
    if not isinstance(require_approval, bool):
        raise ConfigError("approvals.require_approval must be a boolean")

    allowed_web_domains = _as_string_list(approvals.get("allowed_web_domains"))
    allowed_repo_urls = _as_string_list(approvals.get("allowed_repo_urls"))

    network = data.get("network", {})
    if network is None:
        network = {}
    if not isinstance(network, dict):
        raise ConfigError("network must be an object")

    network_enabled = network.get("enabled", False)
    if not isinstance(network_enabled, bool):
        raise ConfigError("network.enabled must be a boolean")

    timeout_seconds = _as_number(network.get("timeout_seconds", 10.0), "network.timeout_seconds")
    web_max_bytes = _as_int(network.get("web_max_bytes", 1024 * 1024), "network.web_max_bytes")
    repo_max_bytes = _as_int(network.get("repo_max_bytes", 10 * 1024 * 1024), "network.repo_max_bytes")
    repo_max_file_bytes = _as_int(
        network.get("repo_max_file_bytes", 256 * 1024), "network.repo_max_file_bytes"
    )
    repo_max_files = _as_int(network.get("repo_max_files", 2000), "network.repo_max_files")
    allowed_web_hosts = _as_string_list(network.get("allowed_web_hosts"))
    allowed_repo_hosts = _as_string_list(network.get("allowed_repo_hosts"))

    return BridgewardenConfig(
        profile=profile,
        approval_policy=ApprovalPolicy(
            require_approval=require_approval,
            allowed_web_domains=allowed_web_domains,
            allowed_repo_urls=allowed_repo_urls,
        ),
        network=NetworkPolicy(
            enabled=network_enabled,
            timeout_seconds=timeout_seconds,
            web_max_bytes=web_max_bytes,
            repo_max_bytes=repo_max_bytes,
            repo_max_file_bytes=repo_max_file_bytes,
            repo_max_files=repo_max_files,
            allowed_web_hosts=allowed_web_hosts,
            allowed_repo_hosts=allowed_repo_hosts,
        ),
    )


def _as_string_list(value: Optional[object]) -> List[str]:
    """Ensure value is a list of strings, or default to empty."""

    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError("expected a list of strings")
    return list(value)


def _as_int(value: Optional[object], name: str) -> int:
    """Validate integer limits in configuration."""

    if not isinstance(value, int):
        raise ConfigError(f"{name} must be an integer")
    if value <= 0:
        raise ConfigError(f"{name} must be positive")
    return value


def _as_number(value: Optional[object], name: str) -> float:
    """Validate numeric limits in configuration."""

    if not isinstance(value, (int, float)):
        raise ConfigError(f"{name} must be a number")
    if value <= 0:
        raise ConfigError(f"{name} must be positive")
    return float(value)

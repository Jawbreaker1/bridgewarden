#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
codex_bin="${CODEX_BIN:-codex}"
config_path="${CODEX_CONFIG:-$HOME/.codex/config.toml}"
config_dir="$(dirname "$config_path")"

if ! command -v "$codex_bin" >/dev/null 2>&1; then
  echo "codex not found in PATH. Install CodexCLI first."
  exit 1
fi

mkdir -p "$config_dir"

if [[ -f "$config_path" ]] && grep -qE "^[[:space:]]*\\[mcp_servers\\.bridgewarden\\][[:space:]]*$" "$config_path"; then
  echo "BridgeWarden is already configured in $config_path."
  exit 0
fi

if [[ -f "$config_path" ]]; then
  backup_path="${config_path}.bak"
  if [[ -e "$backup_path" ]]; then
    backup_path="${config_path}.bak.$(date +%s)"
  fi
  cp "$config_path" "$backup_path"
  echo "Backup created: $backup_path"
fi

cat <<EOF >> "$config_path"

[mcp_servers.bridgewarden]
command = "python3"
args = [
  "-m", "bridgewarden.server",
  "--config", "config/bridgewarden.yaml",
  "--data-dir", ".bridgewarden",
  "--base-dir", "."
]
cwd = "$repo_root"
enabled_tools = ["bw_web_fetch", "bw_fetch_repo", "bw_read_file", "bw_quarantine_get"]
EOF

echo "BridgeWarden MCP server added to $config_path."
echo "Verify with: $codex_bin mcp list"

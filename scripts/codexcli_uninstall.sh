#!/usr/bin/env bash
set -euo pipefail

config_path="${CODEX_CONFIG:-$HOME/.codex/config.toml}"

if [[ ! -f "$config_path" ]]; then
  echo "No CodexCLI config found at $config_path."
  exit 0
fi

if ! grep -qE "^[[:space:]]*\\[mcp_servers\\.bridgewarden\\][[:space:]]*$" "$config_path"; then
  echo "BridgeWarden entry not found in $config_path."
  exit 0
fi

backup_path="${config_path}.bak"
if [[ -e "$backup_path" ]]; then
  backup_path="${config_path}.bak.$(date +%s)"
fi
cp "$config_path" "$backup_path"
echo "Backup created: $backup_path"

tmp_file="$(mktemp)"
awk '
  BEGIN { skip=0 }
  /^[[:space:]]*\[mcp_servers\.bridgewarden\][[:space:]]*$/ { skip=1; next }
  skip && /^[[:space:]]*\[[^]]+\][[:space:]]*$/ { skip=0 }
  skip == 0 { print }
' "$config_path" > "$tmp_file"

mv "$tmp_file" "$config_path"
echo "BridgeWarden MCP server removed from $config_path."

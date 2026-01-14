# BridgeWarden

> “You shall not pass.” — (untrusted context)

**BridgeWarden** is an MCP-server and a security gateway for AI coding agents that reduces the risk of *indirect prompt injection* and other hostile text that attempts to control or manipulate an agent via README.md, issues, docs, source code comments, or tool output to perform malicious instructions.

## The problem
AI agents ingest text from many sources (repo files, web pages, tickets, command output). Attackers can hide instructions in that text to:
- override the agent’s rules/policy (“ignore previous instructions…”)
- coerce dangerous tool usage (shell, file writes, network)
- exfiltrate secrets (tokens, env vars, SSH keys)
- sabotage process (e.g., “skip tests”, “hide this change”)

## One-sentence solution
BridgeWarden acts as an **MCP guard/proxy**: all “untrusted” text flows are fetched and processed through a deterministic pipeline before reaching the agent/LLM context.

## Design principles
- **Deterministic first**: normalization, sanitization, heuristics, redaction — without relying on an LLM.
- **Policy decisions**: ALLOW / WARN / BLOCK (quarantine).
- **Auditability**: log every decision (hash, source, policy version).
- **Least privilege**: safe-by-default; minimal permissions.
- **Agent-agnostic**: integrates through MCP.

## Getting started
BridgeWarden is a Python-only project (stdlib only).

### Prerequisites
- Python 3.9+

### Quick start
```
python3 -m unittest discover -s tests
```

### Run the local demo
```
python3 demo/run_demo.py
```

### Run the MCP stdio server
```
python3 -m bridgewarden.server \
  --config config/bridgewarden.yaml \
  --data-dir .bridgewarden \
  --base-dir .
```

Example request (line-delimited JSON):
```
{"id":"1","tool":"bw_read_file","args":{"path":"README.md"}}
```

### Configuration
Configuration lives in `config/bridgewarden.yaml` (JSON-compatible YAML). Defaults are safe:
network access is disabled and approvals are required for new sources.

Key fields:
- `profile`: strict | balanced | permissive
- `approvals.require_approval`: require manual source approval
- `approvals.allowed_web_domains`: allowlist of web domains
- `approvals.allowed_repo_urls`: allowlist of repo URLs
- `network.enabled`: enable network fetchers
- `network.allowed_web_hosts`: allowlist of fetchable web hosts
- `network.allowed_repo_hosts`: allowlist of fetchable repo hosts (include `codeload.github.com`)

### Troubleshooting
- **All web/repo fetches are blocked**: ensure `network.enabled` is true and the host is in the `network.allowed_*_hosts` allowlist.
- **Approval required errors**: approve the source (web domain or repo URL) or add it to the `approvals.allowed_*` allowlist.
- **Where are logs/quarantine files?**: `.bridgewarden/logs/audit.jsonl` and `.bridgewarden/quarantine/`.

### CodexCLI setup
BridgeWarden runs as an MCP stdio server.

Manual run:
```
python3 -m bridgewarden.server \
  --config config/bridgewarden.yaml \
  --data-dir .bridgewarden \
  --base-dir .
```

Recommended: configure CodexCLI to launch BridgeWarden automatically via `~/.codex/config.toml`
using command+args and a fixed cwd so relative paths work:

```
[mcp_servers.bridgewarden]
command = "python3"
args = [
  "-m", "bridgewarden.server",
  "--config", "config/bridgewarden.yaml",
  "--data-dir", ".bridgewarden",
  "--base-dir", "."
]
cwd = "/ABSOLUTE/PATH/TO/bridgewarden-repo"
enabled_tools = ["bw_web_fetch", "bw_fetch_repo", "bw_read_file", "bw_quarantine_get"]
```

Verify Codex sees the server:
- Run: `codex mcp list`
- If needed, restart Codex after editing the config

Step-by-step via CLI (for first-time MCP setup):
1) From the repo root, add the server:
```
codex mcp add bridgewarden -- python3 -m bridgewarden.server --config config/bridgewarden.yaml --data-dir .bridgewarden --base-dir .
```
2) Edit `~/.codex/config.toml` to add a fixed cwd and tool allowlist:
```
[mcp_servers.bridgewarden]
cwd = "/ABSOLUTE/PATH/TO/bridgewarden-repo"
enabled_tools = ["bw_web_fetch", "bw_fetch_repo", "bw_read_file", "bw_quarantine_get"]
```
3) Confirm it is registered:
```
codex mcp list
```

## MVP milestone (v0.1)
- [ ] `bw_read_file(...)` → sanitized text + risk metadata
- [ ] `bw_fetch_repo(...)` → preflight scan + manifest + risk report
- [ ] `bw_web_fetch(...)` → fetch URL → extract text → sanitize + decide
- [ ] `bw_tool_proxy(...)` → optional proxy for upstream MCP tools (filtered output)
- [ ] `bw_quarantine_get(...)` → review blocked content safely

## Demo (safe + humorous)
This repo ships a local demo environment showing “with vs without BridgeWarden”.
See: [docs/DEMO.md](docs/DEMO.md)

## Documentation
- [Threat model](docs/THREAT_MODEL.md)
- [Architecture](docs/ARCHITECTURE.md)
- [MCP API](docs/MCP_API.md)
- [Test corpus](docs/TEST_CORPUS.md)

## Status
Early stage (proof-of-concept). See [ROADMAP.md](ROADMAP.md).

## License
Add LICENSE once you choose one.

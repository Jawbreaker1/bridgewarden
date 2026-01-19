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
Run the local demo (no network required):
```
python3 demo/run_demo.py
```

Start the MCP server:
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

### CodexCLI setup (recommended for agents)
Option A: one-command setup script (writes `~/.codex/config.toml` and creates a backup):
```
./scripts/codexcli_setup.sh
```

Option B: step-by-step via CLI (first-time MCP setup):
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

Optional: uninstall script (removes the BridgeWarden entry and creates a backup):
```
./scripts/codexcli_uninstall.sh
```

Safety note: BridgeWarden only protects text that flows through `bw_*` tools.
For maximum safety, remove or disable any other MCP servers that can read files,
fetch web content, or fetch repos so BridgeWarden is the only retrieval path.
Optionally, add a short prompt reminder to prefer `bw_*` tools for retrieval.

Suggested prompt/policy (add to your agent or team instructions, or paste into
the start of a session):
```
Use only BridgeWarden `bw_*` tools for any file, web, or repo retrieval.
Do not use other retrieval tools. If content is blocked, use `bw_quarantine_get`
or request approval rather than bypassing BridgeWarden.
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

### Run tests
```
python3 -m unittest discover -s tests
```
## MVP milestone (v0.1)
- [x] `bw_read_file(...)` → sanitized text + risk metadata
- [x] `bw_fetch_repo(...)` → preflight scan + manifest + risk report
- [x] `bw_web_fetch(...)` → fetch URL → extract text → sanitize + decide
- [ ] `bw_tool_proxy(...)` → optional proxy for upstream MCP tools (filtered output)
- [x] `bw_quarantine_get(...)` → review blocked content safely

## Demo (safe + humorous)
This repo ships a local demo environment showing “with vs without BridgeWarden”.
See: [docs/DEMO.md](docs/DEMO.md)
Quick start: `python3 demo/run_demo.py` or run the local webapp with `python3 demo/run_webapp.py`.

## Documentation
- [Threat model](docs/THREAT_MODEL.md)
- [Architecture](docs/ARCHITECTURE.md)
- [MCP API](docs/MCP_API.md)
- [Test corpus](docs/TEST_CORPUS.md)

## Status
Early stage (proof-of-concept). See [ROADMAP.md](ROADMAP.md).

## License
Add LICENSE once you choose one.

# BridgeWarden

> “You shall not pass.” — (untrusted context)

**BridgeWarden** is an MCP-server and a security gateway for AI coding agents that reduces the risk of *indirect prompt injection* and other hostile text that attempts to steer an agent via README.md, issues, docs, source code comments, or tool output.

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

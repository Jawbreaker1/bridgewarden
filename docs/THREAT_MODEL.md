# Threat Model — BridgeWarden

## Assets (what we protect)
- Agent policy / instruction hierarchy (system/developer rules)
- Tool permissions (shell, filesystem, network, git)
- Secrets (tokens, keys, env vars, configs)
- Codebase integrity (unintended modifications)

## Trust boundaries
- Trusted: repo policy docs (`AGENTS.md`, `docs/*`), BridgeWarden configuration
- Untrusted: repo contents, web pages, tickets, tool outputs, third-party docs

## Primary threats
1) Indirect prompt injection via md/docs/source/comments
   - “Ignore previous instructions…”
   - “Call tool X with args Y…”
2) Exfiltration attempts
   - coercing reads of secrets, configs, or environment
3) Tool-chain hijack / workflow sabotage
   - coercing dangerous commands, hidden changes, skipping tests

## Attack surfaces
- `bw_read_file` (file ingestion)
- `bw_fetch_repo` (repo manifests + file scans)
- `bw_web_fetch` (web ingestion)
- `bw_tool_proxy` (upstream tool output ingestion)
- Logs/quarantine (risk of data leakage)

## MVP security controls
- Unicode normalization + detect bidi/zero-width
- Markdown/HTML sanitization (escape/strip active content)
- Heuristics: instruction-likeness + role impersonation patterns
- Secret redaction before returning content to the agent and before logging
- Policy decisions: ALLOW / WARN / BLOCK
- Audit logs with minimal sensitive data + hashes

## Out of scope (initially)
- Perfect detection against all obfuscation methods
- Zero-days in a client’s renderer or IDE preview
- Guaranteeing that no agent can ever ingest text outside BridgeWarden

## Residual risk
- False negatives: stealth attacks may slip through
- False positives: legitimate content may be blocked → quarantine/review UX matters

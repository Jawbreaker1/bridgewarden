# Architecture — BridgeWarden

## High level
The MCP client (agent) talks to **BridgeWarden** via MCP.
BridgeWarden can:
- read files / fetch repos (directly or via controlled mechanisms)
- fetch web pages and extract text
- optionally proxy other MCP servers
- scan + sanitize all untrusted text
- decide policy outcomes and log them

## Components
1) **MCP layer**
   - tool registry + request/response handling
2) **Normalization**
   - Unicode NFKC, bidi/zero-width detection, canonical newlines
3) **Sanitizers**
   - Markdown/HTML safe rendering (strip/escape active content)
4) **Detectors**
   - instruction-likeness heuristics (regex + structural signals)
   - rule tiers by profile (strict ⊇ balanced ⊇ permissive)
   - core multilingual phrases with language-specific extensions (hinted)
   - language packs live in `bridgewarden/language_packs.py`
   - obfuscation handling (collapsed alphanumeric scan; includes multilingual phrases)
5) **Redactors**
   - mask secrets (keys/tokens/private key blocks)
6) **Decision engine**
   - thresholds + profiles (strict/balanced/permissive)
7) **Quarantine store**
   - store original + sanitized + metadata (by id, deduped by content hash)
8) **Audit log**
   - JSONL: timestamp, source, hash, score, decision, policy_version, cache_hit

## Runtime data
- Config: `config/bridgewarden.yaml` (JSON-compatible YAML)
- Data directory: `.bridgewarden/`
  - `approvals/` (source approvals)
  - `repos/` (repo cache)
  - `quarantine/` (blocked content)
  - `logs/audit.jsonl` (JSONL audit log)

## MCP server loop (stdio)
The local server speaks JSON-RPC 2.0 over stdio (one message per line). The client
initializes the session, then lists/calls tools.

Initialize request:

```
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"codex","version":"unknown"}}}
```

Initialize response:

```
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"bridgewarden","version":"0.1.0"}}}
```

Tool call request:

```
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bw_read_file","arguments":{"path":"README.md"}}}
```

Tool call response:

```
{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{...GuardResult JSON...}"}],"isError":false}}
```

## Data flow (ingest content)
untrusted_text
→ normalize
→ sanitize
→ detect
→ redact
→ decide
→ (optional) quarantine original
→ return sanitized text + metadata

## Constraints
- Deterministic behavior
- No secret leakage in logs
- Configurable, but safe defaults
- Testable: each pipeline stage isolated and unit tested

## Client UX expectations
BridgeWarden returns a `GuardResult` for every tool call. MCP clients are expected to:
- show a clear warning on `decision=WARN` with `reasons` + `risk_score`.
- block content on `decision=BLOCK` and show `reasons` + `quarantine_id`.
- offer a “Review blocked content” action that calls `bw_quarantine_get`.

## Perf baseline
Use `scripts/perf_scan.py` to record scan timings before/after optimizations.

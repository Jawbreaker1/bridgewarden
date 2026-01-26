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
The local server reads line-delimited JSON from stdin and writes responses to stdout.

Request shape:

```
{"id":"1","tool":"bw_read_file","args":{"path":"README.md"}}
```

Response shape:

```
{"id":"1","result":{...}}
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

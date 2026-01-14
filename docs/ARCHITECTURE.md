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
5) **Redactors**
   - mask secrets (keys/tokens/private key blocks)
6) **Decision engine**
   - thresholds + profiles (strict/balanced/permissive)
7) **Quarantine store**
   - store original + sanitized + metadata (by id, deduped by content hash)
8) **Audit log**
   - JSONL: timestamp, source, hash, score, decision, policy_version, cache_hit

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

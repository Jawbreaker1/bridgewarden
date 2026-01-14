# Roadmap

## v0.1 (MVP)
- [ ] MCP server exposing tools defined in `docs/MCP_API.md`
- [ ] Pipeline: normalize → sanitize → detect → redact → decide → log
- [ ] Quarantine: store original + sanitized + metadata (dedupe by content hash)
- [ ] JSONL audit log with a stable schema
- [ ] Test suite for pipeline stages + local fixtures
- [ ] Demo site + scripts to compare “with vs without BridgeWarden”

## v0.2 (Proxy & approvals)
- [ ] Proxy mode for upstream MCP servers (`bw_tool_proxy`)
- [ ] Config: allowlist/denylist of upstream tools + argument constraints
- [ ] Source approval flow (new domain/repo requires approval)
- [ ] Policy profiles (strict / balanced / permissive)

## v0.3 (Hardening)
- [ ] Performance: streaming/slicing for large files
- [ ] Reproducible risk scoring + stable reason codes
- [ ] Additional parsers (RST, AsciiDoc, CSV)
- [ ] Supply-chain hooks (pre-commit/CI) as a complement

## v1.0
- [ ] Stable API versioning
- [ ] Integration examples for common MCP clients / coding agents
- [ ] Security review + updated threat model

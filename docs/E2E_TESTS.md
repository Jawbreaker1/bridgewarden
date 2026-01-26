# E2E Tests — CodexCLI

This harness runs CodexCLI against BridgeWarden using real tool calls and
checks the GuardResult outputs. It is meant for demo validation and regressions.

## Prerequisites
- CodexCLI installed and logged in.
- BridgeWarden repo on disk (this repo).

## Quick start (demo cases)
```
./scripts/codex_e2e.py --install --uninstall
```

This will:
1) Add the BridgeWarden MCP server to `~/.codex/config.toml`
2) Run the demo E2E cases in `demo/e2e_cases.json`
3) Remove the MCP entry afterward

## Run a single case
```
./scripts/codex_e2e.py --case bw_read_file_inject_role
```

## Using your existing Codex config
If you already configured BridgeWarden with `scripts/codexcli_setup.sh`, you can
skip install/uninstall:
```
./scripts/codex_e2e.py
```

## Optional: include network cases
If you add `requires_network` cases, enable them explicitly:
```
./scripts/codex_e2e.py --include-network
```

## Notes
- The harness parses JSONL output from `codex exec --json` and looks for
  GuardResult objects. It is robust to non-JSON warnings.
- Results depend on the model obeying the prompt to call `bw_read_file`.
- For localhost web demos, `bw_web_fetch` is blocked by SSRF protection; use
  `bw_read_file` on `demo/webapp/*.html` instead.

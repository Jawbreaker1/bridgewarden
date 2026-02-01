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

## Debugging failures
If a case fails to find a GuardResult, the harness writes raw outputs to:
`demo/e2e_outputs/<case>.stdout.txt` and `.stderr.txt`.
Use `--debug` to print stdout/stderr inline.

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

### Local demo server for network cases
Network cases are designed to hit the local demo server over HTTP. You can:

1) Start the demo server in another terminal:
```
python3 demo/run_webapp.py --port 8000
```
2) Run E2E with network cases:
```
./scripts/codex_e2e.py --install --uninstall --include-network
```

Or let the harness start it for you:
```
./scripts/codex_e2e.py --install --uninstall --include-network --start-demo-server
```

### Network config
`bw_web_fetch` blocks localhost by default for SSRF protection. For local network tests,
use the provided config that explicitly allows localhost:
```
config/bridgewarden.localtest.yaml
```

When running with `--install`, the harness automatically uses that config for
network cases. If you installed manually, set it via:
```
BW_CONFIG=config/bridgewarden.localtest.yaml ./scripts/codexcli_setup.sh
```

## Notes
- The harness parses JSONL output from `codex exec --json` and looks for
  GuardResult objects. It is robust to non-JSON warnings.
- Results depend on the model obeying the prompt to call the requested `bw_*` tool.

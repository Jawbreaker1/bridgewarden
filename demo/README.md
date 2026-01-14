# BridgeWarden Demo

This directory contains a local demo environment to compare:

- raw ingestion (no guard)
- guarded ingestion via BridgeWarden

See also: `docs/DEMO.md`

## Notes
Demo injections are intentionally safe and non-operational.
They exist to validate defense behavior and raise awareness.

## Quick start
Run the local demo script (no network access required):

```
python3 demo/run_demo.py
```

## Local webapp demo
Run a temporary local web server with safe injection samples:

```
python3 demo/run_webapp.py
```

Visit `http://127.0.0.1:8000/` and use the links to test agents.
BridgeWarden blocks localhost in `bw_web_fetch` (SSRF protection),
so for guarded testing either:
- use `bw_read_file` on `demo/webapp/*.html`, or
- host the demo on a non-local domain and allowlist it in config.

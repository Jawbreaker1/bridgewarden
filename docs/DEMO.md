# Demo — BridgeWarden (With vs Without)

BridgeWarden ships with a safe, local demo to illustrate indirect prompt injection in a memorable way.

Goal:
- show how untrusted web/repo content can steer an agent
- show how BridgeWarden detects/sanitizes/quarantines that content
- compare **raw ingestion** vs **guarded ingestion**

## What the demo includes
- A local fixture corpus with:
  - benign pages
  - *safe* injected instructions (visible and hidden)
  - unicode edge-cases (bidi / zero-width)
  - markdown with role-impersonation patterns
- A local demo webapp with hidden injections inside CSS/JS/comment blocks
- A script that compares:
  - without BridgeWarden (raw)
  - via BridgeWarden (sanitized + policy decision)

## Quick start (scripted demo)
Use the local demo runner (no network access required; it uses corpus fixtures):

```
python3 demo/run_demo.py
```

## Local webapp demo
Run a temporary local web server with safe injection samples:

```
python3 demo/run_webapp.py
```

Visit `http://127.0.0.1:8000/` and use the links to test agents.
Note: `bw_web_fetch` blocks localhost by default for SSRF protection. For guarded
testing you can either read the files via `bw_read_file` or host the demo on a
non-local domain and allowlist it in config.

## Expected outcome
- Raw fetch returns the fixture text including injected content.
- BridgeWarden fetch returns a GuardResult:
  - decision: WARN or BLOCK
  - reasons (e.g., ROLE_IMPERSONATION, STEALTH_INSTRUCTION, PROCESS_SABOTAGE)
  - sanitized_text and/or quarantine_id

## Safety note
The injected content in the demo is intentionally non-operational:
- no real secrets
- no real file paths
- no real commands
- placeholders only

This demo is for defensive validation only.

# Demo — BridgeWarden (With vs Without)

BridgeWarden ships with a safe, local demo to illustrate indirect prompt injection in a memorable way.

Goal:
- show how untrusted web/repo content can steer an agent
- show how BridgeWarden detects/sanitizes/quarantines that content
- compare **raw ingestion** vs **guarded ingestion**

## What the demo includes
- A local static website with:
  - benign pages
  - pages containing *safe* injected instructions (visible and hidden)
  - unicode edge-cases (bidi / zero-width)
  - markdown with role-impersonation patterns
- Scripts that fetch:
  - without BridgeWarden (raw)
  - via BridgeWarden (sanitized + policy decision)

## Expected outcome
- Raw fetch returns the page text including injected content.
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

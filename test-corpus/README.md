# BridgeWarden Test Corpus

This directory contains local fixtures used for regression tests.

## Goals
- Validate detection of indirect prompt injection patterns
- Validate sanitization and secret redaction
- Keep false positives low on benign content

## How to add a fixture
1) Add a file under `fixtures/`
2) Name it with the expected outcome (allow/warn/block) OR add a sidecar expected json
3) Ensure it contains no real secrets or actionable exploitation steps

# Test Corpus — BridgeWarden

BridgeWarden ships with a local, safe test corpus to validate the pipeline:
normalize → sanitize → detect → redact → decide → log.

## Why ship a corpus in-repo
- Reproducible results (no internet dependency)
- Regression protection (CI can run it)
- Shared baseline for contributors

## Layout
- `test-corpus/fixtures/benign_*`:
  normal documentation/code snippets that should remain ALLOW
- `test-corpus/fixtures/injected_*`:
  safe injected patterns expected to WARN or BLOCK
- `test-corpus/fixtures/unicode_*`:
  bidi/zero-width/homoglyph-style edge cases
- `test-corpus/fixtures/*lang_*`:
  multilingual injection samples

## Expected outcomes
- benign: ALLOW
- injected: WARN or BLOCK (depending on policy profile)
- unicode: WARN at minimum, possibly BLOCK in strict mode

## Fixture metadata (recommended)
Option A (simple): encode expectation in filename:
- `benign_allow_*.md`
- `injected_warn_*.md`
- `injected_block_*.md`

Option B (richer): sidecar file:
- `example.md`
- `example.expected.json` containing:
  - expected_decision
  - expected_reasons
  - optional: expected_risk_score
  - optional: profile (e.g., "strict" for strict-only rules)

## Corpus runner
The corpus runner is exercised by `tests/test_corpus.py` and can be run via:

```
python3 -m unittest discover -s tests
```

## Security note
Fixtures are “malicious-looking” but intentionally non-operational:
- placeholders, no real secrets
- no actionable exploitation steps

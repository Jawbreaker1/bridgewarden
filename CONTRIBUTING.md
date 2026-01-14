# Contributing

## Setup
(Placeholder) Add setup steps once the first runnable version exists.

## Branch / PR process
- Keep PRs small and focused.
- Add tests for any changes in the pipeline or policy decisions.
- Update docs whenever the API/contract changes.

## Coding standards
- Security-critical code: strict parsing, explicit error handling, no silent failures.
- Never include secrets/PII in logs or test fixtures.

## Tests to include
- Unicode normalization: bidi / zero-width / suspicious characters
- Markdown/HTML sanitization
- Instruction-likeness detection (role impersonation, policy override language)
- Secret redaction (masking)
- Policy decisions (allow/warn/block) + quarantine review flow

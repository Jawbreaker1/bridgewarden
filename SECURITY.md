# Security Policy

## Supported Versions
This project is in early development and has no stable releases yet.

## Reporting a Vulnerability
If you discover a vulnerability:
1) Do NOT open a public issue with a working exploit or detailed PoC.
2) Report privately to the maintainer (add contact details later).

Please include:
- description and impact
- minimal reproduction steps
- expected vs actual behavior
- risk assessment (likelihood + impact)

## Security Goals
- Prevent untrusted text from overriding agent policy or coercing dangerous tool use.
- Prevent accidental secret exfiltration via redaction + log hygiene.
- Provide traceability via hashing, audit logs, and policy versioning.
- This project is defensive. Demo payloads are non-operational and use placeholders. Do not use this project to facilitate unauthorized access or exploitation.

## Non-Goals (initially)
- Perfect detection of all attacks (focus on a strong practical baseline).
- Fully AI-driven classification (deterministic-first approach).

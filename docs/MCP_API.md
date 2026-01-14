# MCP API — BridgeWarden (draft)

This document is the contract. Changes require versioning.

## Conventions
- Tools return a standardized `GuardResult`.
- `decision` ∈ { "ALLOW", "WARN", "BLOCK" }
- `risk_score` ∈ [0.0, 1.0]
- `content_hash` is computed from the original content (pre-sanitization).
- `sanitized_text` may be empty if BLOCK.
- `policy_version` allows cache invalidation when rules change.

## Types

### GuardResult
- decision: string
- risk_score: number
- reasons: string[]             # short reason codes (e.g. "ROLE_IMPERSONATION", "SSRF_BLOCKED")
- source: object                # e.g. { kind: "web", url: "...", domain: "...", request_id: "..." }
- content_hash: string
- sanitized_text: string
- quarantine_id?: string        # present if BLOCK, or if policy requires it
- redactions: object[]          # e.g. { kind: "API_KEY", count: 2 }
- cache_hit: boolean
- policy_version: string
- approval_id?: string          # present when blocked due to missing approval

### SourceApprovalRequest
- kind: "web_domain" | "repo_url" | "upstream_mcp_server"
- target: string                # e.g. "developer.apple.com" or "https://github.com/org/repo"
- rationale?: string            # optional human-readable reason (agent may provide)
- requested_by?: string         # optional (client id / user / agent)

### SourceApprovalStatus
- approval_id: string
- kind: string
- target: string
- status: "PENDING" | "APPROVED" | "DENIED"
- created_at: string            # ISO8601
- decided_at?: string           # ISO8601
- decided_by?: string           # optional
- notes?: string                # optional

## Tools (v0.1)

### bw_read_file
Reads a file and returns a sanitized, policy-processed result.

**Input**
- repo_id?: string              # optional; if omitted, reads from local path (policy may restrict)
- path: string
- mode?: "safe" | "raw"         # default "safe" (raw may become admin-only)

**Output**
- GuardResult

### bw_fetch_repo
Fetches a repository into a BridgeWarden-controlled store and returns a manifest + findings.
(This does not expose raw repo content by default.)

**Input**
- url: string
- ref?: string
- depth?: number
- include_paths?: string[]
- exclude_paths?: string[]
- baseline_revision?: string

**Output**
- repo_id: string
- new_revision: string
- changed_files: object[]       # { path, status } status in {added, modified, renamed}
- summary: object               # totals, warnings, blocks, cache_hits
- findings: object[]            # per file: decision + score + reasons + content_hash
- quarantine_ids: string[]

**Blocking behavior (missing approval)**
If the repo URL is not allowed and policy requires approval:
- return findings/summary indicating BLOCK and include `approval_id`.

### bw_web_fetch
Fetches a URL, extracts readable text, and returns a sanitized, policy-processed result.

**Input**
- url: string
- mode?: "readable_text" | "raw_text"     # default "readable_text"
- max_bytes?: number

**Output**
- GuardResult

**Blocking behavior**
BridgeWarden MUST block risky network targets (SSRF protections) and unapproved domains:
- If domain is not allowlisted: decision=BLOCK, reasons include "NEW_SOURCE_REQUIRES_APPROVAL", and set approval_id.
- If URL is SSRF-risk (localhost/private IP/etc): decision=BLOCK, reasons include "SSRF_BLOCKED" (no approval_id).

### bw_quarantine_get
Retrieves quarantine details for safe review.

**Input**
- id: string

**Output**
- original_excerpt: string      # limited excerpt; never full secrets
- sanitized_text: string
- metadata: object
- reasons: string[]
- risk_score: number

## Tools (Source approvals)

### bw_request_source_approval
Creates a pending approval request for a new source (domain/repo/upstream MCP server).

**Input**
- request: SourceApprovalRequest

**Output**
- SourceApprovalStatus

### bw_get_source_approval
Fetches the current status for an approval id.

**Input**
- approval_id: string

**Output**
- SourceApprovalStatus

### bw_list_source_approvals
Lists approval requests.

**Input**
- status?: "PENDING" | "APPROVED" | "DENIED"
- kind?: "web_domain" | "repo_url" | "upstream_mcp_server"
- limit?: number

**Output**
- approvals: SourceApprovalStatus[]

### bw_decide_source_approval
Approves or denies a pending request. (In v0.1 this can be “local admin only”.)

**Input**
- approval_id: string
- decision: "APPROVED" | "DENIED"
- notes?: string

**Output**
- SourceApprovalStatus

## Tools (v0.2+)

### bw_tool_proxy
Proxies an upstream MCP tool call but filters/sanitizes any untrusted text in the response.

**Input**
- server: string
- tool: string
- args: object

**Output**
- GuardResult OR a structured object where all text fields have been processed (implementation-defined)

## Policy & config (placeholder)
Add `config/bridgewarden.yaml` once the config model is defined.

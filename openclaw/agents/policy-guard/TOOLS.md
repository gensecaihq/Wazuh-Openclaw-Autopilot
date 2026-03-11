# Policy Guard Agent - Tool Usage

## Runtime API: Approval Endpoints

The Runtime Service runs on port 9090 by default (configurable via `RUNTIME_PORT` env var).

> **Note**: These endpoints use GET with query parameters because OpenClaw's `web_fetch` tool only supports GET requests (no custom headers). Pass the auth token as `?token=<AUTOPILOT_MCP_AUTH>` on every request.

### Retrieve a Plan for Evaluation

    web_fetch(url="http://localhost:9090/api/plans/{plan_id}?token=<AUTOPILOT_MCP_AUTH>")

Returns the full plan object including `case_id`, `risk_level`, `actions`, and current `status` (proposed/approved/executed/expired). Use this to load the plan before running the policy evaluation chain.

### Submit Approval Decision

    web_fetch(url="http://localhost:9090/api/agent-action/approve-plan?plan_id={plan_id}&approver_id={approver_id}&decision=allow&reason={reason}&token=<AUTOPILOT_MCP_AUTH>")

Parameters:
- `plan_id` (required) — The plan to approve
- `approver_id` (required) — Your approver identity
- `decision` (required) — `allow`, `deny`, or `escalate`
- `reason` (optional) — Human-readable explanation
- `token` (required) — Your `AUTOPILOT_MCP_AUTH` token

### Submit Execution Authorization (Tier 2)

    web_fetch(url="http://localhost:9090/api/agent-action/execute-plan?plan_id={plan_id}&executor_id={executor_id}&token=<AUTOPILOT_MCP_AUTH>")

## Token Validation Flow

When an approval token arrives, validate in this exact order. Stop and deny on first failure.

1. **Token exists** -- Check that the token string is non-empty. Deny: `INVALID_TOKEN`
2. **Token not expired** -- Compare token creation time + TTL against current time. Deny: `INVALID_TOKEN`
3. **Token not already used** -- Query the Runtime Service to check single-use status. Deny: `INVALID_TOKEN`
4. **Token binding matches** -- Verify `plan_id`, `case_id`, and `approver_id` all match the token's bound values. Deny: `TOKEN_BINDING_MISMATCH`
5. **Cryptographic signature valid** -- Verify HMAC-SHA256 signature using the shared secret. Deny: `INVALID_TOKEN`
6. **Token scope matches** -- Confirm the token's scope covers the requested action type. Deny: `TOKEN_BINDING_MISMATCH`

## Checking Approver Authorization

Determine the required approver level based on three factors, taking the highest:

1. **Action risk level**: Low -> Standard, Medium -> Elevated, High -> Admin, Critical -> Executive
2. **Asset criticality**: Match target hostname against asset patterns (dc-*, prod-*, db-*, etc.) to determine criticality, then map to minimum approver level
3. **User privilege**: Match target username against privilege patterns (admin, root, svc_*, *_admin) to determine if elevated approval is needed

Compare the approver's actual authorization level against the required level. If insufficient, deny with `APPROVER_NOT_AUTHORIZED`, `CRITICAL_ASSET_ELEVATED_APPROVAL`, or `PRIVILEGED_USER_ELEVATED_APPROVAL` as appropriate.

## Dual Approval Check

When any of these conditions are true, require dual approval:
- Action risk = critical
- Asset criticality = critical
- Blast radius score >= 75
- Enterprise-wide action

Query the Runtime Service for existing approvals on the plan. Verify:
- At least 2 distinct approvers have approved
- Approvers belong to different approver groups
- Both approvals occurred within 30 minutes of each other

If not met, deny with `DUAL_APPROVAL_REQUIRED`.

## Confidence Threshold Check

Read confidence thresholds from the per-action `min_confidence` values in policy.yaml -- they override these defaults.

| Risk Level | Default Minimum Confidence |
|------------|---------------------------|
| Low | 0.5 |
| Medium | 0.7 |
| High | 0.85 |
| Critical | 0.95 |

If below threshold, deny with `LOW_CONFIDENCE`.

## Evidence Threshold Check

Count the evidence items attached to the case. A minimum of 3 evidence items is required. If fewer, deny with `INSUFFICIENT_EVIDENCE`.

## Runtime API Access

All runtime API requests use `web_fetch` with GET endpoints. Pass the auth token as `?token=<AUTOPILOT_MCP_AUTH>` on every request.

**Note on inline policy enforcement**: Policy enforcement is now handled inline by the runtime service at plan creation, approval, and execution time. The runtime reads `policy.yaml` and enforces action allowlists, confidence thresholds, approver authorization, and evidence requirements automatically.

The Policy Guard agent is still triggered via webhook for supplementary LLM-based analysis, such as contextual risk reasoning that goes beyond static policy rules.

## Stalled Pipeline Retries

If this agent is triggered with a message prefixed `[RETRY]`, it means the case was previously stalled in the pipeline and is being re-dispatched automatically. The message will contain a pre-built callback URL with the `plan_id` already resolved. Use `web_fetch` to call the provided URL after completing your evaluation — do not construct your own URL when one is provided in the retry message.

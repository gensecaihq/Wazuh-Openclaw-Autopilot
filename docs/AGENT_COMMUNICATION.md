# Agent Communication Architecture

How OpenClaw agents communicate with the Autopilot Runtime Service.

## Why GET-Based Endpoints?

OpenClaw's `web_fetch` tool is **GET-only** — it accepts a URL and returns the page content as markdown/text. It has no `method`, `headers`, or `body` parameters:

```typescript
// web_fetch schema (from OpenClaw source)
{ url: string, extractMode?: "markdown" | "text", maxChars?: number }
```

Since agents can only make GET requests, the Runtime Service provides GET-based "agent action" endpoints that accept operations via query parameters. These endpoints call the same underlying functions as the standard REST endpoints (PUT/POST).

## Pipeline Flow

```
Alert Ingestion                    Runtime dispatches webhooks →
    ↓                              OpenClaw routes to agents via
POST /api/alerts                   hook mappings in openclaw.json
    ↓ (creates case)
webhook → Triage Agent
    ↓
GET /api/agent-action/update-case?status=triaged
    ↓ (runtime dispatches webhook)
webhook → Correlation Agent
    ↓
GET /api/agent-action/update-case?status=correlated
    ↓
webhook → Investigation Agent
    ↓
GET /api/agent-action/update-case?status=investigated
    ↓
webhook → Response Planner Agent
    ↓
GET /api/agent-action/create-plan?case_id=...&actions=...
    ↓ (runtime dispatches webhook)
webhook → Policy Guard Agent
    ↓
GET /api/agent-action/approve-plan?decision=allow
    ↓ (human Tier 2 trigger)
GET /api/agent-action/execute-plan?plan_id=...
```

Each status transition triggers a webhook that activates the next agent. The runtime orchestrates the pipeline — agents only need to read data (GET) and write back results (GET with query params).

## Available Endpoints

| Agent Action | Endpoint | Replaces |
|-------------|----------|----------|
| Update case status/data | `GET /api/agent-action/update-case` | `PUT /api/cases/:id` |
| Create response plan | `GET /api/agent-action/create-plan` | `POST /api/plans` |
| Approve/deny plan | `GET /api/agent-action/approve-plan` | `POST /api/plans/:id/approve` |
| Execute plan | `GET /api/agent-action/execute-plan` | `POST /api/plans/:id/execute` |

## Security

- Same authentication as standard endpoints (Bearer token or localhost bypass)
- Same authorization checks (`validateAuthorization(req, "write")`)
- Same input validation (`isValidCaseId`, `isValidPlanId`, `isValidIdentityId`)
- Bound to localhost only — not exposed externally
- `data` parameter is JSON-parsed inside try/catch — rejects malformed input

## Standard REST Endpoints

The original PUT/POST endpoints remain available for direct API consumers (curl, scripts, Slack integrations). The GET-based endpoints are specifically for OpenClaw agents using `web_fetch`.

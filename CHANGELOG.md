# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Stalled-pipeline detector**: Automatically detects cases stuck in transient statuses (open, triaged, correlated, etc.) for longer than a configurable threshold and re-dispatches the webhook to give the agent another attempt. Configurable via `STALLED_PIPELINE_ENABLED`, `STALLED_PIPELINE_THRESHOLD_MINUTES` (default 30), and `STALLED_PIPELINE_CHECK_INTERVAL_MS` (default 300000). New metrics: `autopilot_stalled_pipeline_detected_total`, `autopilot_stalled_pipeline_redispatched_total`.
- **Runtime enforcement for policy time_windows, rate_limits, and idempotency**: These three policy.yaml sections were previously declarative only. The runtime now enforces them:
  - **Time windows**: `policyCheckTimeWindow()` blocks `createResponsePlan()` and `executePlan()` outside configured UTC day/time windows (respects `outside_window_action: allow|deny`)
  - **Rate limits**: `policyCheckActionRateLimit()` enforces per-action and global hourly/daily rate limits inside the plan execution action loop. Counters auto-reset on window expiry.
  - **Idempotency**: `policyCheckIdempotency()` blocks duplicate action+target pairs within the configured `window_minutes` (default 60min)
  - Denied actions are skipped individually (rate limit / idempotency) or fail the entire plan (time window), with `policy_denies_total` metric incremented using reason labels `time_window_denied`, `action_rate_limited`, `global_rate_limited`, `duplicate_action`
  - Cleanup intervals evict expired rate limit and dedup state every 5 minutes
- **LLM deployment choice documentation**: README now presents three clear paths (Cloud APIs, Local Ollama, Hybrid) with the local/air-gapped path clearly stating current limitations
- 296 tests across 10 files

### Fixed
- **Stalled pipeline data corruption**: `checkStalledPipeline()` now acquires the case lock before writing `updated_at`, preventing data loss from concurrent `updateCase` calls
- **Stalled pipeline broken callback URLs**: Fixed callback URLs for `investigated` (was sending empty actions array, always rejected), `planned` and `approved` (were using literal `{plan_id}` instead of actual plan ID from evidence pack)
- **Case lock race condition**: Replaced simple `Map.has/set/delete` pattern with proper async mutex queue. The old pattern allowed a third concurrent caller to bypass the lock between delete and resolve.
- **Ollama "fetch failed" 5-minute timeout** (fixes #12, #13): OpenClaw bundles its own undici copy, and pi-ai's `http-proxy.ts` resets the global dispatcher with a default 300-second `headersTimeout`. Combined with OpenClaw silently disabling streaming for Ollama tool-calling models, any generation >5 min causes "fetch failed" with 0 tokens. The preload script now writes directly to the shared `globalThis[Symbol.for('undici.globalDispatcher.1')]` and re-applies via `setTimeout` to survive pi-ai's async overwrite. See `docs/AIR_GAPPED_DEPLOYMENT.md` for the complete fix.
- **Ollama `api` mode in air-gapped config** (fixes #11): Changed `openclaw-airgapped.json` from `"api": "openai-completions"` with `/v1` to `"api": "ollama"` with native endpoint. The OpenAI-compatible mode breaks tool calling — models output raw JSON instead of invoking tools.
- **`reasoning: false` for Ollama models** (fixes #10): Set `"reasoning": false` explicitly for standard Ollama models (Llama, Mistral, Qwen, CodeLlama). Only models with native thinking support (deepseek-r1, qwq) should have `"reasoning": true`.
- **MCP session init timeout leak**: `clearTimeout` now runs in a `finally` block for the notification step, preventing timer leaks on error paths
- **`dispatchToGateway` timeout and response leaks**: Timer is now cleared before retries and on error paths. Response body is drained on final 5xx to release connection pool sockets.
- **`createCase` silent overwrite**: Now checks if `evidence-pack.json` already exists and returns 409 Conflict instead of silently overwriting
- **False positive feedback on closed cases**: Feedback is now always appended; status change to `false_positive` is only attempted if the case isn't in a terminal state
- **Slack `SAFE_ERROR_PATTERNS` missing entries**: Added patterns for "Executor must be different" (separation of duties) and "Case already exists"
- **Log sensitive field denylist too narrow**: Expanded from 4 fields (auth, token, password, secret) to 10 fields (added api_key, apiKey, authorization, credential, bearer, session_token)
- **`uncaughtException` handler**: Now sets `isShuttingDown = true` to reject new requests during the 1-second drain window
- **`dmPolicy: "open"` in `openclaw.json`**: Changed to `"allowlist"` to match the documented security posture
- **`package.json` version**: Bumped from 2.3.0 to 2.4.3 to match the latest release
- **RUNTIME_API.md wrong Slack env var names**: Changed `SLACK_CHANNEL_ALERTS`/`SLACK_CHANNEL_APPROVALS` to `SLACK_ALERTS_CHANNEL`/`SLACK_APPROVALS_CHANNEL` to match actual code
- **RUNTIME_API.md `MCP_MAX_RETRIES` default**: Corrected from 3 to 2
- **OBSERVABILITY_EXPORT.md dead metric**: Removed `autopilot_action_plans_proposed_total` (replaced by `plans_created_total` in v2.4.2)
- **OBSERVABILITY_EXPORT.md phantom OpenTelemetry section**: Removed section describing OTEL support that was never implemented
- **SECURITY.md supported versions**: Updated from 2.0.x-2.1.x to 2.2.x-2.4.x

### Changed
- **Tested with OpenClaw v2026.3.1**: Verified compatibility with the latest OpenClaw release. The undici timeout preload script is still required — pi-ai@0.55.3 ships identical `http-proxy.ts`.

## [2.4.3] - 2026-02-27

### Fixed
- **`--skip-tailscale` set `AUTOPILOT_MODE=production`**: The `--skip-tailscale` flag didn't change `INSTALL_MODE` from `"full"`, so the generated `.env` always got `AUTOPILOT_MODE=production`. Production mode rejects Slack placeholder values in `policy.yaml`, causing the runtime to fail on startup with `"Production mode cannot use placeholder values in policy"`. Now `--skip-tailscale` implies bootstrap mode unless `--mode full` is explicitly passed.
- **Missing `gateway.mode=local`**: OpenClaw v2026.2.17 requires `gateway.mode` to be set — without it the gateway refuses to start with `"Gateway start blocked: set gateway.mode=local"`. Added `"mode": "local"` to both reference configs (`openclaw.json`, `openclaw-airgapped.json`) and the installer-generated config. Corrected previous advice in issue #1 that incorrectly recommended removing this key.

## [2.4.2] - 2026-02-27

### Fixed
- **Global `tools.allow` missing `web_fetch` and `sessions_send`**: Added both to the global `tools.allow` list in `openclaw.json`, `openclaw-airgapped.json`, and the installer. Agent-level allow lists cannot override the global policy — if `web_fetch` was missing from the global list, agents silently could not make HTTP requests, causing the pipeline to stall after triage with no error.
- **JWT exchange race condition**: Concurrent callers of `getMcpAuthToken()` received the raw Promise object instead of the resolved token string, causing `[object Promise]` to be sent as the Bearer token. Added `await` to the dedup return path.
- **MCP session init race condition**: Added dedup guard (`mcpSessionInitPromise`) to `ensureMcpSession()` to prevent concurrent callers from racing to initialize the MCP session. Uses the same pattern as the JWT exchange dedup.
- **X-Forwarded-For IP extraction**: Changed from `.pop()` (last/proxy IP) to `[0]` (first/client IP) in both auth validation and rate limiting. The previous behavior allowed attackers to spoof their IP by adding an X-Forwarded-For header, bypassing rate limiting and auth lockout.
- **Localhost bootstrap scope**: Changed `scope: "read"` to `scope: "write"` for localhost requests in bootstrap mode, matching the documented and actual behavior (write endpoints only checked `authResult.valid`, not scope).
- **`createCase()` race condition**: Wrapped in `withCaseLock()` to prevent concurrent create+update on the same case ID from causing lost updates.
- **HTTP 401 for scope-insufficient tokens**: Service tokens with read-only scope hitting write endpoints now correctly return 403 Forbidden instead of 401 Unauthorized.
- **MCP RPC error double-counts metrics**: JSON-RPC errors from successful HTTP responses no longer count as both "success" and "error" in Prometheus metrics.
- **Plan stuck in EXECUTING state**: Plans that encounter an unexpected throw during execution are now marked as FAILED in the `finally` block instead of remaining in EXECUTING state permanently.
- **`listPlans()` stale expiry state**: Now calls `getPlan()` per entry to trigger expiry checks, ensuring expired plans are correctly reflected in list responses.
- **Dead metric `action_plans_proposed_total`**: Removed unused metric that was always 0 (replaced by `plans_created_total`).
- **Installer `AUTOPILOT_MODE=bootstrap` hardcoded**: The `.env` template always set bootstrap mode regardless of install mode. Now uses a placeholder substituted based on `$INSTALL_MODE` (full → production, bootstrap/mcp-only → bootstrap).
- **Installer `mcp-only` mode crash**: `start_services()` unconditionally tried to start `wazuh-autopilot.service` which doesn't exist in mcp-only mode. Now guarded.
- **Installer missing `apt-get update`**: Added package index refresh after adding the nodesource repository, fixing Node.js install failures on Debian/Ubuntu when other dependencies were already present.
- **Installer runtime `ReadWritePaths`**: Added `$RUNTIME_DST` to the systemd service `ReadWritePaths` under `ProtectSystem=strict` so Node.js can write to its working directory.
- **Installer `check_root` ordering**: Moved root check before interactive prompts so non-root users aren't forced through the consent flow before being told they need root.
- **Installer hook mappings**: Added `"path": "/webhook"`, `messageTemplate`, and `name` to all 6 hook mappings; changed absolute paths to relative.
- **Installer agent tool permissions**: Moved `edit` from deny to allow lists for triage, correlation, investigation, and policy-guard agents to match reference templates.
- **Installer missing env vars**: Added `OPENCLAW_GATEWAY_URL` and `AUTOPILOT_RUNTIME_URL` to the generated `openclaw.json` env section.
- **Slack slash command error leak**: Replaced raw `err.message` with `safeErrorMessage()` in approve/execute/reject catch blocks to prevent internal details from being exposed in Slack.
- **Slack `safeErrorMessage` pattern mismatch**: The pattern `/^Tier 1 required/` did not match the actual error `"Plan must be approved before execution (Tier 1 required)"`. Added matching pattern.
- **Slack `formatPlansMessage` unescaped**: Added `escapeMrkdwn()` to plan title and risk level in the plans list message.
- **Slack `postCaseAlert` NaN timestamp**: Added `isNaN` guard with fallback text when `created_at` is invalid or missing.

## [2.4.1] - 2026-02-27

### Fixed
- **OpenClaw tool name format**: Changed `web.fetch` to `web_fetch` in all agent `tools.allow` lists. OpenClaw uses snake_case identifiers (`web_fetch`) in per-agent allow/deny lists — dot notation (`web.fetch`) is only valid for global config paths (e.g., `tools.web.fetch.enabled`). The incorrect format caused OpenClaw to log "unknown entries (web.fetch)" warnings and agents could not make HTTP requests.
- **Correlation agent missing `web_fetch`**: Added `web_fetch` to the correlation agent's allow list in `openclaw.json` (was present in air-gapped config but missing from reference template).
- **Installer global `web_fetch` disabled**: Changed `"fetch": {"enabled": false}` to `{"enabled": true}` in the installer-generated `openclaw.json`. Without this, the `web_fetch` tool was globally disabled even when listed in agent allow lists.

## [2.4.0] - 2026-02-26

### Fixed
- **OpenClaw webhook 400 error**: Added required `messageTemplate` and `name` fields to all 6 hook mappings in both `openclaw.json` and `openclaw-airgapped.json`. Without `messageTemplate`, the OpenClaw Gateway could not extract the message body from incoming webhook POSTs, returning `400 "hook mapping requires message"`.
- **OpenClaw webhook 401 error**: Separated `OPENCLAW_WEBHOOK_TOKEN` from `OPENCLAW_TOKEN`. OpenClaw requires a dedicated hook token for webhook endpoint validation, distinct from the gateway auth token. The runtime now uses `OPENCLAW_WEBHOOK_TOKEN` for webhook dispatch (falls back to `OPENCLAW_TOKEN` for backwards compatibility).
- **MCP JWT cache race condition**: Added promise-based deduplication to `getMcpAuthToken()` to prevent thundering herd when JWT cache expires. Multiple concurrent callers now share a single in-flight JWT exchange instead of triggering parallel requests.

### Added
- **Separate webhook token**: `OPENCLAW_WEBHOOK_TOKEN` environment variable for dedicated webhook endpoint authentication. Generated automatically by the installer and stored in `/etc/wazuh-autopilot/secrets/openclaw_webhook_token`.
- **Installer `--mode` flag**: `install.sh` now supports `--mode full|bootstrap|mcp-only`. `bootstrap` skips Tailscale (equivalent to `--skip-tailscale`). `mcp-only` installs only the MCP Server, skipping OpenClaw Gateway, Runtime Service, and Agent deployment.
- **Webhook dispatch diagnostic logging**: On 400 errors from OpenClaw Gateway, the runtime now logs payload keys, `message` field presence, and a message preview to aid troubleshooting.
- 27 new tests (255 total): Webhook payload shape validation, JWT deduplication under concurrency, and getMcpAuthToken edge cases.

### Changed
- `dispatchToGateway()` now uses `OPENCLAW_WEBHOOK_TOKEN` (with `OPENCLAW_TOKEN` fallback) instead of `OPENCLAW_TOKEN` directly
- `dispatchToGateway()` now logs detailed diagnostic info (payload keys, message presence, response body preview) on 4xx errors instead of just the status code
- `hooks.token` in both OpenClaw configs changed from `${OPENCLAW_TOKEN}` to `${OPENCLAW_WEBHOOK_TOKEN}`

## [2.3.0] - 2026-02-22

### Added
- **MCP JSON-RPC protocol**: `callMcpTool()` now supports the standard MCP JSON-RPC 2.0 protocol (`POST /mcp` with `tools/call` method) in addition to legacy REST mode. Configurable via `MCP_AUTH_MODE`.
- **JWT auth exchange**: Automatic API key → JWT exchange via `/auth/token` with in-memory caching and 401 retry logic
- **IP enrichment**: AbuseIPDB v2 integration enriches public IP entities during alert ingestion. TTL-based cache (10K max entries), configurable timeout. Enabled via `ENRICHMENT_ENABLED=true`.
- **Entity-based alert grouping**: Alerts sharing entities (IPs, users, hosts) within a configurable time window are automatically grouped into existing cases instead of creating duplicates
- **False positive feedback endpoint**: `POST /api/cases/:id/feedback` accepts analyst verdicts (`true_positive`, `false_positive`, `needs_review`). False positive verdicts mark entities in the grouping index to prevent future re-grouping.
- **Alert ID normalization**: Raw Wazuh alerts using `id` or `_id` fields are normalized to `alert_id` for consistent downstream handling
- **Wazuh integrator improvements**: `--max-time 10` for curl, `${RUNTIME_PORT}` env var, configurable alert level threshold via `WAZUH_ALERT_LEVEL`
- **New Prometheus metrics**: `enrichment_requests_total`, `enrichment_cache_hits_total`, `enrichment_errors_total`, `false_positives_total`, `feedback_submitted_total{verdict}`
- **Cleanup intervals**: Automatic expiry of stale entity index entries and enrichment cache entries
- 32 new tests (228 total): E2E pipeline test, feedback endpoint tests, enrichment unit tests, alert grouping tests, MCP auth tests
- New `.env.example` variables: `MCP_AUTH_MODE`, `ENRICHMENT_ENABLED`, `ABUSEIPDB_API_KEY`, `ALERT_GROUP_ENABLED`, `WAZUH_ALERT_LEVEL`, cache TTLs

### Changed
- `callMcpTool()` defaults to `mcp-jsonrpc` mode (JSON-RPC 2.0 at `/mcp` endpoint); set `MCP_AUTH_MODE=legacy-rest` for backwards compatibility
- Alert ingestion response now includes `grouped_into` field when an alert is grouped into an existing case
- `updateCase()` supports `feedback` array field for persisting analyst verdicts

## [2.2.0] - 2026-02-22

### Added
- **Autonomous agent pipeline**: Webhook dispatch wires agents end-to-end — runtime triggers downstream agents via OpenClaw Gateway on status changes
- **Gateway dispatch**: Fire-and-forget `dispatchToGateway()` with 10s timeout, 1 retry, and Prometheus metrics (`webhook_dispatches_total`, `webhook_dispatch_failures_total`)
- **Status-driven handoffs**: Case status changes automatically trigger the next agent (triaged → correlation, correlated → investigation, investigated → response-planner)
- **Inline policy enforcement**: Three enforcement points enforce `policy.yaml` at runtime:
  - **Plan creation**: Validates each action against allowlist, checks `enabled` and `min_confidence`
  - **Plan approval**: Validates approver against groups, checks `can_approve` and `max_risk_level`
  - **Plan execution**: Validates evidence count against `min_evidence_items`
- **7 action tools enabled** in `toolmap.yaml`: `block_ip`, `isolate_host`, `kill_process`, `disable_user`, `quarantine_file`, `firewall_drop`, `host_deny`
- **Agent Runtime API access**: All 6 agent TOOLS.md files updated with HTTP endpoint documentation
- 16 new tests for gateway dispatch and policy enforcement (196 total)
- `OPENCLAW_GATEWAY_URL` and `OPENCLAW_TOKEN` environment variables for gateway integration

### Changed
- **Policy Guard role**: Primary enforcement is now inline at the runtime level; the Policy Guard agent provides supplementary LLM-based analysis
- `web_fetch` enabled in both `openclaw.json` and `openclaw-airgapped.json` so agents can call the runtime API
- Bootstrap mode: Policy enforcement is fail-open (warns but allows) for easier testing
- Production mode: Policy enforcement is fail-closed (denies if policy cannot be loaded)

### Fixed
- **YAML parser bug**: `parseSimpleYaml` silently skipped indented list items (standard YAML style) — now correctly parses `items:\n  - first\n  - second`
- Policy configuration loaded at startup but never enforced at runtime

## [2.1.0] - 2026-02-17

### Added
- **Multi-provider LLM support**: Claude, OpenAI, Groq, Mistral, xAI, Google, Ollama, OpenRouter, Together, Cerebras
- **Centralized port configuration**: All service ports (Gateway, MCP, Runtime) configurable via environment variables
- **Pre-flight configuration validator**: Interactive validation in installer checks required settings before starting services
- **Full-stack health check script** (`scripts/health-check.sh`): Verifies Runtime, MCP, OpenClaw, Wazuh, Slack, permissions, services, disk space
- **Production-ready Dockerfile** with multi-stage build and configurable runtime port
- **Docker Compose** configuration for container deployment
- **GitHub Actions CI/CD pipeline** (lint, test, security audit, build)
- ESLint configuration for code quality

### Changed
- **Playbooks upgraded to v2.0**: All 7 incident response playbooks rewritten with TLP markings, expanded MITRE ATT&CK sub-techniques, OS-specific forensic artifacts, chain of custody requirements, regulatory compliance mappings (NIST, ISO, SANS), communication templates, and agent pipeline integration
- **Policy configuration**: Slack integration marked as optional with `slack_required: false`; API-based approval works without Slack
- **Installer**: Added `validate_configuration()` step with interactive prompts; Slack remains optional and deferrable
- Ports no longer hardcoded across files; `install/env.template` is the single source of truth
- Agent prompts note configurable runtime port (default 9090)
- Wazuh integrator in installer uses configured port variables instead of hardcoded values

### Security
- Gateway binds to localhost only (127.0.0.1:18789)
- MCP Server binds to Tailscale IP only
- Runtime Service binds to localhost only
- Docker container: read-only root filesystem, all capabilities dropped, no privilege escalation
- Pairing mode for device authorization
- Credential isolation with 600/700 permissions

## [2.0.0] - 2025-11-20

### Added
- **Two-tier approval workflow** for response plans (Approve → Execute)
- Response Plans API with full state management
  - `POST /api/plans` - Create response plan
  - `POST /api/plans/:id/approve` - Tier 1 approval
  - `POST /api/plans/:id/execute` - Tier 2 execution
  - `POST /api/plans/:id/reject` - Reject plan
- **Slack Socket Mode integration** for secure communication
  - Interactive buttons for plan approval/execution
  - Slash commands (`/wazuh status`, `/wazuh approve`, etc.)
  - Real-time case and plan notifications
- **Responder capability toggle** (`AUTOPILOT_RESPONDER_ENABLED`)
  - Disabled by default for safety
  - Human approval always required even when enabled
- Automated alert triage with entity extraction
- MITRE ATT&CK mapping extraction from Wazuh alerts
- Comprehensive security policies with approver groups
- Rate limiting and request body size limits
- Graceful shutdown handling with cleanup
- Memory management with automatic cleanup intervals

### Changed
- Service version bumped to 2.0.0
- Enhanced health endpoint with responder status
- Improved logging with JSON format support
- Security headers on all HTTP responses

### Security
- Input validation for all API endpoints
- Authorization validation for sensitive operations
- Timing-safe token comparison
- Auth failure lockout (5 attempts, 30-minute lockout)

## [1.0.0] - 2025-09-15

### Added
- Initial release
- Evidence pack management
- Case creation and updates
- Approval token management
- Prometheus metrics endpoint
- MCP client wrapper with toolmap resolution
- 7 SOC automation agents:
  - Triage Agent
  - Correlation Agent
  - Investigation Agent
  - Response Planner Agent
  - Policy Guard Agent
  - Responder Agent
  - Reporting Agent

[Unreleased]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v2.4.3...HEAD
[2.4.3]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v2.4.2...v2.4.3
[2.4.2]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v2.4.0...v2.4.2
[2.4.0]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/releases/tag/v1.0.0

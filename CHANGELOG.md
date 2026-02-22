# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- `web.fetch` enabled in both `openclaw.json` and `openclaw-airgapped.json` so agents can call the runtime API
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

[Unreleased]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v2.3.0...HEAD
[2.3.0]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/releases/tag/v1.0.0

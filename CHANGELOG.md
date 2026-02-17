# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/releases/tag/v1.0.0

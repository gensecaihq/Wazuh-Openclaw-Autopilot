# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Production-ready Dockerfile with multi-stage build
- Docker Compose configuration for local deployment
- GitHub Actions CI/CD pipeline (lint, test, security audit, build)
- ESLint configuration for code quality
- Comprehensive .env.example template

### Changed
- Fixed model name in openclaw.json (claude-opus-4-6 -> claude-sonnet-4-5)

## [2.0.0] - 2024-01-15

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
- Gateway binds to localhost only (127.0.0.1:18789)
- MCP Server binds to Tailscale IP only
- Pairing mode for device authorization
- Credential isolation with 600/700 permissions
- Input validation for all API endpoints
- Authorization validation for sensitive operations

## [1.0.0] - 2024-01-01

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

[Unreleased]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/releases/tag/v1.0.0

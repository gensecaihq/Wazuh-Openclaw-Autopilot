# Contributing to Wazuh OpenClaw Autopilot

Thank you for your interest in contributing to Wazuh OpenClaw Autopilot! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Issues

- **Bug Reports**: Use the GitHub issue tracker with the "bug" label
- **Feature Requests**: Use the GitHub issue tracker with the "enhancement" label
- **Security Issues**: Please report security vulnerabilities privately to the maintainers

When reporting bugs, please include:
- Operating system and version
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs (with secrets redacted)

### Pull Requests

1. **Fork the repository**
   ```bash
   git clone https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot.git
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed

4. **Test your changes**
   ```bash
   # Run health check
   ./scripts/health-check.sh --quick

   # Run tests
   cd runtime/autopilot-service
   npm test
   ```

5. **Commit with a clear message**
   ```bash
   git commit -m "feat: Add new feature description"
   ```

6. **Push and create a Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

### Commit Message Format

We follow conventional commits:

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

Example:
```
feat: Add Teams integration support

- Add teams agent workspace (AGENTS.md, IDENTITY.md, TOOLS.md, MEMORY.md)
- Update policy.yaml with Teams channel allowlists
- Add documentation for Teams setup
```

## Development Setup

### Prerequisites

- Ubuntu 22.04 or 24.04 (or macOS for development)
- Node.js 18+
- Docker (for testing OpenClaw integration)

### Local Development

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot.git
cd Wazuh-Openclaw-Autopilot

# Install in development mode
sudo ./install/install.sh --mode bootstrap-openclaw

# Run tests
cd runtime/autopilot-service
npm test

# Run the service locally
node index.js
```

### Testing

- All new features should include tests
- Run `npm test` before submitting PRs
- Run health check: `./scripts/health-check.sh --quick`

## Project Structure

```
Wazuh-Openclaw-Autopilot/
├── openclaw/
│   ├── openclaw.json           # Gateway & model configuration
│   └── agents/                 # 7 SOC agents (AGENTS.md, IDENTITY.md, TOOLS.md, MEMORY.md)
├── policies/                   # Security policies and tool mappings
├── playbooks/                  # Incident response playbooks (7 playbooks)
├── install/                    # Installation scripts and env template
├── scripts/                    # Health check and operational scripts
├── runtime/autopilot-service/  # Node.js runtime service
├── docs/                       # Documentation
└── README.md
```

### Key Files

| File | Purpose |
|------|---------|
| `openclaw/openclaw.json` | OpenClaw gateway & agent configuration |
| `policies/policy.yaml` | Security policy definitions |
| `policies/toolmap.yaml` | MCP tool name mappings |
| `install/install.sh` | Security-hardened installer |
| `install/env.template` | Environment variable template |
| `scripts/health-check.sh` | Full-stack health check |
| `runtime/autopilot-service/index.js` | Core runtime service |

## Adding New Agents

1. Create a new YAML file in `agents/`:
   ```yaml
   name: wazuh-new-agent
   version: "2.1.0"
   description: |
     Description of what this agent does.

   role: new_role
   autonomy_level: read-only

   allowed_tools:
     - get_alert
     - search_alerts

   denied_tools:
     - "*_execute"
   ```

2. Update documentation in `docs/` if needed

3. Add the agent to the README.md agents table

## Adding New Playbooks

1. Create a markdown file in `playbooks/`:
   - Follow the existing playbook structure
   - Include MITRE ATT&CK mappings
   - Document detection criteria
   - Include response options

2. Reference relevant Wazuh rules

## Style Guidelines

### YAML

- Use 2-space indentation
- Include comments for complex configurations
- Group related settings together

### JavaScript

- Use ES6+ features
- Include JSDoc comments for functions
- Follow existing code patterns
- No external dependencies (stdlib only)

### Shell Scripts

- Use `#!/usr/bin/env bash`
- Include `set -euo pipefail`
- Add color-coded logging
- Provide user feedback

### Documentation

- Use clear, concise language
- Include code examples
- Keep tables for structured information
- Add links to related documents

## Release Process

1. Update version numbers in relevant files
2. Update CHANGELOG (if maintained)
3. Create a GitHub release with release notes
4. Tag the release

## Questions?

- Open a GitHub Discussion for general questions
- Check existing issues before creating new ones
- Join the community discussions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Wazuh OpenClaw Autopilot!

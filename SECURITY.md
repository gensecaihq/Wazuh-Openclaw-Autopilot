# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Security Model

Wazuh OpenClaw Autopilot implements a defense-in-depth security model:

### Autonomy Levels

| Level | Description | Actions Allowed |
|-------|-------------|-----------------|
| `read-only` | Default for most agents | Query, search, read |
| `plan-only` | Response Planner | Generate plans, no execution |
| `policy-enforcement` | Policy Guard | Evaluate, allow/deny |
| `approval-gated` | Responder (disabled by default) | Execute after approval |

### Key Security Controls

1. **Responder Agent Disabled by Default**
   - Requires explicit `AUTOPILOT_ENABLE_RESPONDER=true`
   - Cannot be enabled without policy configuration

2. **Approval Tokens**
   - Single-use, cryptographically signed
   - TTL of 60 minutes (configurable)
   - Bound to specific plan, case, and approver

3. **Policy Guard Gate**
   - All actions must pass policy evaluation
   - Constitutional AI principles (immutable rules)
   - 13-step evaluation chain

4. **Network Security**
   - Production mode requires Tailscale
   - Metrics bound to localhost by default
   - No inbound connections required (Slack Socket Mode)

5. **Data Protection**
   - Secrets redacted from logs
   - No credentials stored in configuration files
   - Evidence packs exclude sensitive data

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: security@gensecai.com

Include the following information:

- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

### Response Timeline

- **24 hours**: Initial acknowledgment
- **72 hours**: Preliminary assessment
- **7 days**: Detailed response with remediation plan
- **90 days**: Public disclosure (coordinated)

## Security Best Practices for Deployment

### Production Checklist

- [ ] Enable Tailscale and use Tailnet URLs for MCP
- [ ] Configure proper approver groups in `policies/policy.yaml`
- [ ] Review and customize asset criticality patterns
- [ ] Set `AUTOPILOT_MODE=production`
- [ ] Ensure `AUTOPILOT_REQUIRE_TAILSCALE=true`
- [ ] Bind metrics to localhost only
- [ ] Configure Slack workspace/channel allowlists
- [ ] Review rate limits for your environment
- [ ] Set up log aggregation for audit trails

### Network Security

```bash
# Verify Tailscale is running
tailscale status

# Verify metrics are localhost-only
curl http://127.0.0.1:9090/metrics  # Should work
curl http://YOUR_IP:9090/metrics    # Should fail
```

### Secrets Management

Never commit secrets to the repository. Use environment variables:

```bash
# Use environment variables
export AUTOPILOT_MCP_AUTH="your-token"
export SLACK_APP_TOKEN="xapp-..."
export SLACK_BOT_TOKEN="xoxb-..."

# Or use a secrets manager
# AWS Secrets Manager, HashiCorp Vault, etc.
```

## Security Updates

Security updates are released as patch versions (e.g., 2.0.1, 2.0.2).

Subscribe to releases to receive notifications:
- Watch this repository with "Releases only"
- Check the [Releases](https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/releases) page

## Acknowledgments

We thank all security researchers who responsibly disclose vulnerabilities.

# Air-Gapped Deployment Guide

Deploy Wazuh Autopilot in a fully air-gapped environment using Ollama as the sole LLM provider.

## Prerequisites

- Wazuh Manager installed and running (4.8.0 or later)
- Ollama installed ([ollama.com](https://ollama.com))
- Server with sufficient RAM for LLM models (see hardware requirements below)
- Network connectivity between Wazuh Manager, MCP Server, and Ollama (all can be on the same server)

## Hardware Requirements

| Model | Parameters | RAM Required | GPU (Optional) |
|-------|-----------|-------------|----------------|
| `llama3.3` | 70B | ~40 GB | 24+ GB VRAM recommended |
| `llama3.1:8b` | 8B | ~8 GB | 8 GB VRAM |
| `qwen2.5` | 7B/72B | ~8 GB / ~40 GB | Scales with model size |
| `mistral` | 7B | ~8 GB | 8 GB VRAM |
| `codellama` | 13B | ~16 GB | 16 GB VRAM |

**Minimum configuration**: 16 GB RAM with `llama3.1:8b` (primary) + `mistral` (fast/heartbeat)

**Recommended configuration**: 48+ GB RAM with `llama3.3` (primary) + `mistral` (fast/heartbeat)

---

## Step 1: Pre-Pull Ollama Models

Pull models **before** disconnecting from the internet:

```bash
# Required models
ollama pull llama3.3        # Primary reasoning model (70B)
ollama pull mistral         # Fast model for heartbeats/reporting (7B)

# Optional models
ollama pull codellama       # Technical analysis, log parsing (13B)
ollama pull llama3.1:8b     # Lighter alternative to llama3.3 (8B)
ollama pull qwen2.5         # Multilingual support (7B)

# For future embedding support (when available)
ollama pull nomic-embed-text
```

If your hardware cannot support the 70B model, use the lighter configuration:

```bash
ollama pull llama3.1:8b     # Primary (8B — lighter alternative)
ollama pull mistral         # Fast model (7B)
```

Verify models are available:

```bash
ollama list
```

---

## Step 2: Install with --skip-tailscale

Tailscale requires internet access and is not needed in air-gapped environments. Skip it:

```bash
sudo ./install/install.sh --skip-tailscale
```

Or use the environment variable:

```bash
export AUTOPILOT_MODE=bootstrap
sudo ./install/install.sh
```

The installer will:
- Skip Tailscale installation and authentication
- Bind all services to `127.0.0.1` (localhost)
- Omit the `Requires=tailscaled.service` systemd dependency

---

## Step 3: Replace OpenClaw Configuration

After installation, replace the generated `openclaw.json` with the air-gapped version:

```bash
# Backup the default config
cp ~/.openclaw/openclaw.json ~/.openclaw/openclaw.json.default

# Copy the air-gapped config
cp openclaw/openclaw-airgapped.json ~/.openclaw/openclaw.json
chmod 600 ~/.openclaw/openclaw.json
```

The air-gapped config (`openclaw/openclaw-airgapped.json`) sets:
- Ollama as the sole LLM provider
- All cloud providers (Anthropic, OpenAI, Google, etc.) disabled
- Memory/embeddings disabled (no cloud embedding API)
- `llama3.3` as the primary model, `mistral` for heartbeats/reporting
- Web search disabled
- No external network calls required

### Customizing Models

If using lighter models, edit `~/.openclaw/openclaw.json`:

```json
{
  "models": {
    "default": "ollama/llama3.1:8b",
    "fallbackChain": [
      "ollama/llama3.1:8b",
      "ollama/mistral"
    ]
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "ollama/llama3.1:8b",
        "fallback": "ollama/mistral",
        "fast": "ollama/mistral"
      }
    }
  }
}
```

---

## Step 4: Verify Ollama is Running

```bash
# Check Ollama service
systemctl status ollama

# Or if running manually
ollama serve &

# Test a model
ollama run mistral "Hello, respond with OK"
```

Ensure Ollama is accessible at `http://127.0.0.1:11434`:

```bash
curl http://127.0.0.1:11434/api/tags
```

---

## Step 5: Restart Services

```bash
# Restart OpenClaw to load the new config
docker restart openclaw
# or
sudo systemctl restart openclaw

# Restart the runtime service
sudo systemctl restart wazuh-autopilot
```

---

## Step 6: Verify

```bash
# Check runtime health
curl http://127.0.0.1:9090/health

# Check MCP connectivity
curl http://127.0.0.1:8080/health

# Run diagnostics
./install/doctor.sh
```

---

## Model Recommendations

### For Full SOC Pipeline (48+ GB RAM)

| Agent | Model | Why |
|-------|-------|-----|
| Triage | `ollama/llama3.3` | Complex severity assessment, entity extraction |
| Correlation | `ollama/llama3.3` | Pattern detection across multiple alerts |
| Investigation | `ollama/llama3.3` | Deep analysis, evidence gathering |
| Response Planner | `ollama/llama3.3` | Action plan generation with risk scoring |
| Policy Guard | `ollama/llama3.3` | Constitutional enforcement, policy evaluation |
| Responder | `ollama/llama3.3` | Action execution with safeguards |
| Reporting | `ollama/mistral` | Summary generation (lighter model sufficient) |
| Heartbeats | `ollama/mistral` | Periodic sweeps (lighter model sufficient) |

### For Resource-Constrained (16 GB RAM)

| Agent | Model | Why |
|-------|-------|-----|
| All agents | `ollama/llama3.1:8b` | Best 8B reasoning model |
| Reporting + Heartbeats | `ollama/mistral` | Lighter tasks |

---

## Memory / Embeddings

Memory is **disabled** in the air-gapped config because the default embedding provider (OpenAI) requires internet access.

If OpenClaw adds Ollama embedding support in the future, you can re-enable memory:

```json
{
  "memory": {
    "enabled": true,
    "search": {
      "provider": "ollama",
      "model": "nomic-embed-text",
      "hybrid": true
    }
  },
  "agents": {
    "defaults": {
      "memory": {
        "enabled": true
      }
    }
  }
}
```

Until then, all core SOC functions (triage, correlation, investigation, response planning, reporting) work normally without memory. You only lose cross-session context recall.

---

## Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AIR-GAPPED SERVER                         │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Wazuh   │  │   MCP    │  │ OpenClaw │  │  Ollama  │   │
│  │ Manager  │──│ :8080    │──│ :18789   │──│ :11434   │   │
│  │ :55000   │  │          │  │          │  │          │   │
│  └──────────┘  └──────────┘  └────┬─────┘  └──────────┘   │
│                                    │                        │
│                              ┌─────┴─────┐                 │
│                              │  Runtime   │                 │
│                              │  :9090     │                 │
│                              └───────────┘                  │
│                                                              │
│            All services bound to 127.0.0.1                  │
│            No external network access required              │
└─────────────────────────────────────────────────────────────┘
```

---

## Troubleshooting

### Ollama not responding

```bash
# Check if Ollama is running
systemctl status ollama

# Check if models are loaded
ollama list

# Test model directly
ollama run mistral "test"
```

### Slow responses

Local models are slower than cloud APIs. Expected latencies:

| Model | Hardware | Tokens/sec |
|-------|----------|-----------|
| `mistral` (7B) | CPU only | ~5-10 |
| `mistral` (7B) | GPU (8GB) | ~30-50 |
| `llama3.3` (70B) | CPU only | ~1-3 |
| `llama3.3` (70B) | GPU (24GB+) | ~15-25 |

Increase the Ollama timeout in `openclaw.json` if needed:

```json
"providers": {
  "ollama": {
    "timeout": 600000
  }
}
```

### Model not found

If agents report model errors, verify the exact model name:

```bash
ollama list
# Use the exact name from this output in openclaw.json
```

### Out of memory

If the server runs out of RAM:

1. Switch to smaller models (`llama3.1:8b` instead of `llama3.3`)
2. Run fewer concurrent agents
3. Increase heartbeat intervals to reduce load

---

## Related Documentation

- [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server)
- [Ollama Documentation](https://ollama.com)
- [Agent Configuration](./AGENT_CONFIGURATION.md)
- [Troubleshooting](./TROUBLESHOOTING.md)

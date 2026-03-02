# Air-Gapped Deployment Guide

Deploy Wazuh Autopilot in a fully air-gapped environment using Ollama as the sole LLM provider.

> **Current Status: Functional with known limitations.**
>
> Local Ollama deployment works but requires a workaround for OpenClaw's internal 5-minute HTTP timeout. This is due to OpenClaw's bundled undici library resetting the global HTTP dispatcher with a 300-second `headersTimeout`, combined with streaming being silently disabled for tool-calling models. A Node.js preload script (included in this guide) overrides the timeout. We are working with the community to resolve this upstream.
>
> **Before proceeding, be aware of these requirements:**
> - A preload script must be installed to fix the HTTP timeout (Step 4a below)
> - Ollama's context window must be explicitly set to 32768+ tokens (Step 4)
> - The native Ollama API (`"api": "ollama"`) is required — the OpenAI-compatible mode breaks tool calling
> - Significant hardware is needed: 16 GB RAM minimum, 48+ GB recommended
> - Inference is slower than cloud APIs — expect 1–10 tokens/sec on CPU
>
> If you want a stable, zero-configuration experience, consider using [cloud LLM APIs](../README.md#path-a-cloud-llm-apis-recommended) instead.

## Prerequisites

- Wazuh Manager installed and running (4.8.0 or later)
- Node.js 20+ (Node.js 22+ recommended by OpenClaw)
- Ollama 0.17 or later ([ollama.com](https://ollama.com))
- OpenClaw v2026.3.1 or later (`npm install -g openclaw@latest`)
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
| `embeddinggemma-300M` (GGUF) | 300M | ~0.6 GB | Not needed |

**Minimum configuration**: 16 GB RAM with `llama3.1:8b` (primary) + `mistral` (fast/heartbeat)

**Recommended configuration**: 48+ GB RAM with `llama3.3` (primary) + `mistral` (fast/heartbeat)

---

## Step 1: Pre-Pull Ollama Models

Pull models **before** disconnecting from the internet:

```bash
# Required models
ollama pull llama3.3        # Primary reasoning model (70B)
ollama pull mistral         # Fast model for heartbeats/reporting (7B)

# Optional LLM models
ollama pull codellama       # Technical analysis, log parsing (13B)
ollama pull llama3.1:8b     # Lighter alternative to llama3.3 (8B)
ollama pull qwen2.5         # Multilingual support (7B)

# Optional: Pre-download local embedding model for memory search (~0.6 GB)
# This auto-downloads on first use, but pre-staging avoids the initial delay
mkdir -p ~/.cache/node-llama-cpp/models
wget -O ~/.cache/node-llama-cpp/models/embeddinggemma-300M.gguf \
  https://huggingface.co/ggml-org/embeddinggemma-300M-GGUF/resolve/main/embeddinggemma-300M.gguf
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

## Step 2: Install with --mode bootstrap

Tailscale requires internet access and is not needed in air-gapped environments. Use the `--mode` flag:

```bash
sudo ./install/install.sh --mode bootstrap
```

Or equivalently, use the legacy flag:

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

### MCP-Only Mode

If you only need the MCP Server (e.g., you already have OpenClaw running separately), use `mcp-only` mode:

```bash
sudo ./install/install.sh --mode mcp-only
```

This installs only the Wazuh MCP Server, skipping OpenClaw Gateway, Runtime Service, and Agent deployment.

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
- Ollama as the sole LLM provider via the **native Ollama API** (`"api": "ollama"`)
- All cloud providers (Anthropic, OpenAI, Google, etc.) disabled
- Memory enabled with local GGUF embeddings (no cloud API needed)
- `llama3.3` as the primary model, `mistral` for heartbeats/reporting
- Web search disabled
- No external network calls required

> **Important:** The Ollama provider must use `"api": "ollama"` with `"baseUrl": "http://127.0.0.1:11434"` (no `/v1` suffix). Using `"api": "openai-completions"` with the `/v1` endpoint breaks tool calling — models output raw tool JSON as plain text instead of invoking tools like `web_fetch`, causing the agent pipeline to stall.

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

## Step 4: Configure and Verify Ollama

### Critical: Set Context Window

Ollama defaults to **2048 tokens** for context, but OpenClaw injects ~12,000 tokens of system prompt (tool definitions, safety guidelines, agent instructions). Without increasing the context window, the system prompt gets **silently truncated** — the model receives garbage input, hangs, and times out with `"fetch failed"`.

```bash
# For systemd-managed Ollama:
sudo systemctl edit ollama
```

Add:
```ini
[Service]
Environment="OLLAMA_NUM_CTX=32768"
Environment="OLLAMA_KEEP_ALIVE=24h"
Environment="OLLAMA_FLASH_ATTENTION=1"
Environment="OLLAMA_KV_CACHE_TYPE=q8_0"
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart ollama
```

> **Note:** `OLLAMA_NUM_CTX` set in your shell profile is NOT inherited by the systemd service. You must set it in the systemd unit override.

### Verify Ollama is Running

```bash
# Check Ollama service
systemctl status ollama

# Or if running manually
OLLAMA_NUM_CTX=32768 OLLAMA_KEEP_ALIVE=24h ollama serve &

# Test a model
ollama run mistral "Hello, respond with OK"
```

Ensure Ollama is accessible at `http://127.0.0.1:11434`:

```bash
curl http://127.0.0.1:11434/api/tags
```

Verify the context window is applied:

```bash
ollama ps
# The CONTEXT column should show your configured value (32768), not 2048
```

---

## Step 4a: Install the HTTP Timeout Fix (Required)

OpenClaw's internal HTTP library has a 5-minute timeout that kills Ollama connections during long generations. **This step is mandatory for Ollama deployments.** Without it, agents will fail with `"fetch failed"` and 0 tokens after exactly 5 minutes.

Create the preload script and inject it into the OpenClaw gateway service. The script and full systemd configuration are in the [Troubleshooting section below](#fetch-failed-with-0-tokens-5-minute-timeout). For Ollama-only deployments, set `OPENCLAW_LLM_MODE=local`.

Quick summary:

```bash
# 1. Install undici globally
npm install -g undici

# 2. Create the preload script (see Troubleshooting section for full script)
cat > /root/undici-timeout-fix.cjs << 'SCRIPT'
# ... see "fetch failed" troubleshooting section below for the complete script ...
SCRIPT

# 3. Configure the gateway service
systemctl edit --user openclaw-gateway
# Add:
# [Service]
# Environment="NODE_OPTIONS=--require /root/undici-timeout-fix.cjs"
# Environment="NODE_PATH=/usr/lib/node_modules"
# Environment="OPENCLAW_LLM_MODE=local"
# UnsetEnvironment=http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy

# 4. Reload and restart
systemctl --user daemon-reload && systemctl --user restart openclaw-gateway
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
curl http://127.0.0.1:3000/health

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

Memory is **enabled** in the air-gapped config using OpenClaw's local GGUF embedding provider. No cloud API calls are needed.

### How It Works

OpenClaw supports a `"local"` embedding provider that runs a lightweight GGUF model via `node-llama-cpp` directly — no Ollama, no internet. The air-gapped config uses `embeddinggemma-300M` (~0.6 GB), which provides semantic search over agent memory files without any external API calls.

The memory system has two layers:
1. **File-based memory** (always works) — agents read/write `MEMORY.md` files in their workspace. This provides cross-session context recall.
2. **Memory search** (requires embeddings) — builds a vector index over memory files for semantic search. The local GGUF provider handles this entirely on-device.

### Configuration

The air-gapped config (`openclaw-airgapped.json`) sets:

```json
{
  "memory": {
    "enabled": true,
    "search": {
      "provider": "local",
      "local": {
        "modelPath": "hf:ggml-org/embeddinggemma-300M-GGUF/embeddinggemma-300M.gguf"
      },
      "hybrid": true,
      "bm25Weight": 0.4,
      "vectorWeight": 0.6
    }
  }
}
```

| Setting | Value | Purpose |
|---------|-------|---------|
| `provider` | `local` | Use node-llama-cpp GGUF embeddings (no cloud API) |
| `modelPath` | `hf:ggml-org/...` | Auto-downloads ~0.6 GB GGUF model on first use |
| `hybrid` | `true` | Combines vector similarity + BM25 keyword search |
| `bm25Weight` | `0.4` | Weight for keyword matching (good for alert IDs, rule numbers) |
| `vectorWeight` | `0.6` | Weight for semantic similarity (good for pattern recall) |

### Pre-Staging the Embedding Model (Fully Air-Gapped)

If the server has **no internet access at all**, pre-download the GGUF model on a connected machine and transfer it:

```bash
# On a connected machine:
# Download the embedding model (~0.6 GB)
wget https://huggingface.co/ggml-org/embeddinggemma-300M-GGUF/resolve/main/embeddinggemma-300M.gguf

# Transfer to the air-gapped server
scp embeddinggemma-300M.gguf admin@air-gapped-server:/tmp/

# On the air-gapped server:
mkdir -p ~/.cache/node-llama-cpp/models
mv /tmp/embeddinggemma-300M.gguf ~/.cache/node-llama-cpp/models/

# Update openclaw.json to use the local path instead of hf: URI
# Change modelPath to: "/home/YOUR_USER/.cache/node-llama-cpp/models/embeddinggemma-300M.gguf"
```

### Disabling Memory (Optional)

If you prefer to disable memory (e.g., to save RAM), set both locations in `openclaw.json`:

```json
{
  "memory": { "enabled": false },
  "agents": { "defaults": { "memory": { "enabled": false } } }
}
```

All core SOC functions (triage, correlation, investigation, response planning, reporting) work normally without memory. You only lose cross-session context recall.

### Alternative: Ollama Embeddings

OpenClaw does **not** natively support Ollama as an embedding provider. The supported providers are: OpenAI, Gemini, Voyage, and Local (GGUF). A community fork ([memory-lancedb-local](https://github.com/48Nauts-Operator/memory-lancedb-local)) routes embeddings through Ollama's OpenAI-compatible endpoint, but it is not yet merged upstream.

---

## Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AIR-GAPPED SERVER                         │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Wazuh   │  │   MCP    │  │ OpenClaw │  │  Ollama  │   │
│  │ Manager  │──│ :3000    │──│ :18789   │──│ :11434   │   │
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

### OpenClaw webhook returns 400 "hook mapping requires message"

The OpenClaw Gateway requires `messageTemplate` in each hook mapping to extract the message from the POST body. Verify your `~/.openclaw/openclaw.json` hook mappings include both `messageTemplate` and `name`:

```json
{
  "match": { "path": "wazuh-alert" },
  "action": "agent",
  "agentId": "wazuh-triage",
  "messageTemplate": "{{message}}",
  "name": "Wazuh Alert Triage"
}
```

After updating, restart OpenClaw:
```bash
sudo systemctl restart openclaw
# or
docker restart openclaw
```

### Ollama context window too small (2048 default)

Ollama defaults to a **2048 token** context window regardless of the model's capability. OpenClaw requires at least 16,000 tokens (it injects ~12K of system prompt). With 2048 tokens, the system prompt is silently truncated and agents produce garbage or hang.

**Important:** Setting `OLLAMA_NUM_CTX` in your shell profile does NOT affect the systemd service. You must set it in the systemd unit:

```bash
sudo systemctl edit ollama
# Add: Environment="OLLAMA_NUM_CTX=32768"
sudo systemctl daemon-reload && sudo systemctl restart ollama
```

Or for manual runs:
```bash
OLLAMA_NUM_CTX=32768 ollama serve
```

Verify with `ollama ps` — the CONTEXT column should show your configured value.

### Tool calls not working / agents output raw JSON text

If agents produce output but never invoke `web_fetch` (or other tools), the most likely cause is using the OpenAI-compatible API mode instead of the native Ollama API.

**Symptoms:**
- Triage agent produces tokens but pipeline stalls after triage
- Agent output contains raw JSON like `{"name": "web_fetch", "arguments": {...}}` as plain text
- No webhook dispatches in runtime logs

**Fix:** In `~/.openclaw/openclaw.json`, change the Ollama provider config:

```json
"ollama": {
  "baseUrl": "http://127.0.0.1:11434",
  "api": "ollama",
  ...
}
```

Do **not** use `"api": "openai-completions"` or `"baseUrl": "http://127.0.0.1:11434/v1"`. The `/v1` OpenAI-compatible endpoint does not reliably support tool calling.

After updating, restart OpenClaw:
```bash
sudo systemctl restart openclaw
```

### 400 "does not support thinking"

If agent sessions fail with `400 "llama3.1:8b" does not support thinking`, the model is registered with `"reasoning": true` in `openclaw.json`. OpenClaw sends a `thinking_level` parameter to models marked as reasoning-capable, but standard Ollama models (Llama 3.x, Mistral, Qwen 2.5, CodeLlama) don't support this.

**Fix:** Set `"reasoning": false` for all standard models in the `models.providers.ollama.models` array:

```json
{ "id": "llama3.1:8b", "name": "Llama 3.1 8B", "reasoning": false, ... }
{ "id": "llama3.3", "name": "Llama 3.3 70B", "reasoning": false, ... }
```

Only set `"reasoning": true` for models that actually support structured thinking output: `deepseek-r1`, `qwq`, and similar reasoning-specific models.

After updating, restart OpenClaw:
```bash
sudo systemctl restart openclaw
```

### "fetch failed" with 0 tokens (5-minute timeout)

If agents fail with `error=fetch failed` and `input: 0, output: 0` after exactly 5 minutes, there are usually **three compounding issues**. You need to fix all of them.

**Symptoms:**
- Session logs show `"errorMessage": "fetch failed"` with `"output": 0`
- Exactly 5 minutes between request and error (e.g., 05:29:06 → 05:34:06)
- Gateway journal shows `embedded run agent end: ... error=fetch failed`
- `ollama ps` shows the model is loaded and `curl http://127.0.0.1:11434/api/tags` works fine

#### Cause 1: Ollama context window too small (most common)

Ollama defaults to **2048 tokens** context (`OLLAMA_NUM_CTX`). OpenClaw injects ~12,000 tokens of system prompt. With a 2048 window, the prompt gets **silently truncated** — the model receives garbage, hangs, and times out. Setting `OLLAMA_NUM_CTX` in your shell does NOT affect the systemd service.

```bash
sudo systemctl edit ollama
# Add:
# [Service]
# Environment="OLLAMA_NUM_CTX=32768"
# Environment="OLLAMA_KEEP_ALIVE=24h"
# Environment="OLLAMA_FLASH_ATTENTION=1"
# Environment="OLLAMA_KV_CACHE_TYPE=q8_0"

sudo systemctl daemon-reload && sudo systemctl restart ollama
```

Verify: `ollama ps` should show your configured context value, not 2048.

See [openclaw/openclaw#24068](https://github.com/openclaw/openclaw/issues/24068), [openclaw/openclaw#7725](https://github.com/openclaw/openclaw/issues/7725).

#### Cause 2: Proxy environment variables + undici timeout

OpenClaw's gateway uses undici's `EnvHttpProxyAgent` as its global HTTP dispatcher. This agent reads `http_proxy`, `https_proxy`, `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` from the process environment. If ANY of these are set (even inherited from a desktop session or previous configuration), **all HTTP requests — including to localhost Ollama — are routed through that proxy**. If the proxy is unreachable, the connection hangs for 300 seconds (undici's hardcoded `headersTimeout`) and fails with "fetch failed".

Unlike curl, undici does NOT automatically bypass localhost. You must explicitly clear proxy vars or set `NO_PROXY`.

Additionally, `timeoutSeconds` in OpenClaw config controls agent session duration, NOT HTTP call timeouts. There is no OpenClaw config to change the HTTP timeout.

**Fix — create a preload script that overrides OpenClaw's HTTP dispatcher timeouts:**

OpenClaw's internal library (`@mariozechner/pi-ai`) resets the undici global dispatcher at startup by calling `setGlobalDispatcher(new EnvHttpProxyAgent())` with **no timeout options** — inheriting undici's default 300-second `headersTimeout`. This happens asynchronously via a dynamic `import("undici").then(...)`, so it runs after any `--require` preload.

**Additional hidden cause:** OpenClaw silently disables streaming for Ollama tool-calling models. Despite docs saying streaming works, the runtime injects `streaming: false` when tools are configured (always for agent sessions). This means Ollama waits for **full generation** before sending ANY HTTP response headers — and if generation takes >5 minutes, undici's `headersTimeout` kills the connection with 0 tokens received.

**Important:** OpenClaw bundles its **own copy** of undici inside `/usr/lib/node_modules/openclaw/node_modules/undici/`. The preload's `require("undici")` resolves to the **globally installed** copy (via `NODE_PATH`). These are two separate module instances — monkey-patching `setGlobalDispatcher` on one does NOT affect the other. However, all copies share the **same dispatcher storage** via `globalThis[Symbol.for('undici.globalDispatcher.1')]`. The fix writes directly to this shared Symbol.

> **Choose your deployment mode.** The preload script supports two modes depending on whether you use local Ollama, cloud APIs, or both. Set `OPENCLAW_LLM_MODE` to control behavior:
>
> | Mode | `OPENCLAW_LLM_MODE` | Proxy vars | Timeouts | Best for |
> |------|---------------------|-----------|----------|----------|
> | **Local only** | `local` | Deleted (not needed) | 30 min headers, no body timeout | Air-gapped / Ollama-only |
> | **Hybrid / Cloud** | `cloud` or unset | Preserved; `NO_PROXY` set for localhost | 10 min headers, 10 min body, 60s connect | Cloud APIs + optional local Ollama |

```bash
cat > /root/undici-timeout-fix.cjs << 'SCRIPT'
"use strict";
// ============================================================================
// OpenClaw undici timeout fix — works for BOTH local Ollama and cloud LLM APIs
// ============================================================================
// Set OPENCLAW_LLM_MODE=local  → air-gapped / Ollama-only (aggressive timeouts)
// Set OPENCLAW_LLM_MODE=cloud  → cloud APIs or hybrid (conservative timeouts)
// Default (unset)              → cloud mode (safe for all deployments)
// ============================================================================

const mode = (process.env.OPENCLAW_LLM_MODE || "cloud").toLowerCase();

if (mode === "local") {
  // Air-gapped: no proxy needed, delete all proxy vars
  delete process.env.http_proxy;
  delete process.env.https_proxy;
  delete process.env.HTTP_PROXY;
  delete process.env.HTTPS_PROXY;
  delete process.env.ALL_PROXY;
  delete process.env.all_proxy;
} else {
  // Cloud/hybrid: preserve proxy vars for cloud API access,
  // but exempt localhost so Ollama requests bypass the proxy
  const existing = process.env.NO_PROXY || process.env.no_proxy || "";
  const exemptions = "127.0.0.1,localhost,::1";
  if (!existing.includes("127.0.0.1")) {
    process.env.NO_PROXY = existing ? existing + "," + exemptions : exemptions;
    process.env.no_proxy = process.env.NO_PROXY;
  }
}

const undici = require("undici");

// Timeouts based on deployment mode
const TIMEOUT_OPTS = mode === "local"
  ? {
      headersTimeout: 30 * 60 * 1000,  // 30 min — Ollama may take long to generate
      bodyTimeout: 0,                   // disabled — no streaming, single response
      connect: { timeout: 30 * 60 * 1000 },  // 30 min — cold model loading
    }
  : {
      headersTimeout: 10 * 60 * 1000,  // 10 min — generous for cloud + local
      bodyTimeout: 10 * 60 * 1000,     // 10 min — detect stalled streams
      connect: { timeout: 60 * 1000 }, // 60s — cloud APIs connect fast
    };

// The Symbol where ALL undici copies store the global dispatcher.
// Symbol.for() returns the same Symbol across ALL modules/copies.
const SYM = Symbol.for("undici.globalDispatcher.1");

function applyDispatcher() {
  globalThis[SYM] = new undici.Agent(TIMEOUT_OPTS);
}

// Apply immediately, then re-apply after pi-ai's async overwrite.
// pi-ai's http-proxy.ts does: import("undici").then(m => setGlobalDispatcher(...))
// This resolves to OpenClaw's bundled undici (separate module instance),
// so we can't intercept it — we just overwrite after it runs.
applyDispatcher();
setTimeout(applyDispatcher, 0);
setTimeout(applyDispatcher, 50);
setTimeout(applyDispatcher, 200);
setTimeout(applyDispatcher, 1000);
setTimeout(applyDispatcher, 3000);
setTimeout(applyDispatcher, 8000);
SCRIPT
```

> **How this works:** All undici copies share dispatcher storage at `globalThis[Symbol.for('undici.globalDispatcher.1')]`. The preload sets this immediately, then pi-ai's async `import("undici").then(...)` overwrites it. The `setTimeout` callbacks re-apply our dispatcher after pi-ai's overwrite. No LLM requests fire until the gateway is fully started, so the brief overwrite window has no impact.

> **Why two modes?** Deleting proxy vars breaks corporate environments where cloud APIs (api.anthropic.com, api.openai.com) are only reachable through an HTTP proxy. The `cloud` mode preserves proxy vars and uses `NO_PROXY` to exempt localhost instead. The `local` mode deletes proxy vars entirely (safe when everything is on localhost). Setting `bodyTimeout: 0` in local mode is needed because Ollama sends the entire response as a single chunk after generation completes. In cloud mode, `bodyTimeout: 10min` detects stalled streams without killing legitimate long responses.

> **Why not monkey-patch `setGlobalDispatcher`?** OpenClaw bundles its own undici copy. The preload's `require("undici")` and pi-ai's `import("undici")` resolve to **different module instances**. Patching one doesn't affect the other. The [ClawKit guide](https://getclawkit.com/docs/troubleshooting/ollama-timeout-errors) recommends this approach, but it doesn't work with bundled undici.

> **Why not `writable:false` / Symbol lock?** pi-ai's `.then()` has no `.catch()`, so a `TypeError` would crash the gateway.

**Important:** The preload script requires undici as a module. If you get `Cannot find module 'undici'`, install it globally and set NODE_PATH:

```bash
npm install -g undici
```

Inject into the gateway systemd service:

```bash
systemctl edit --user openclaw-gateway
```

**For air-gapped / Ollama-only deployments:**
```ini
[Service]
Environment="NODE_OPTIONS=--require /root/undici-timeout-fix.cjs"
Environment="NODE_PATH=/usr/lib/node_modules"
Environment="OPENCLAW_LLM_MODE=local"
UnsetEnvironment=http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
```

**For cloud API or hybrid (cloud + Ollama) deployments:**
```ini
[Service]
Environment="NODE_OPTIONS=--require /root/undici-timeout-fix.cjs"
Environment="NODE_PATH=/usr/lib/node_modules"
Environment="OPENCLAW_LLM_MODE=cloud"
```

> **Note:** In `cloud` mode, do NOT add `UnsetEnvironment` for proxy vars — your cloud API requests may need them. The script automatically sets `NO_PROXY=127.0.0.1,localhost,::1` so local Ollama requests bypass the proxy.

```bash
systemctl --user daemon-reload && systemctl --user restart openclaw-gateway
```

**Verify the preload is working** — gateway should start without errors:
```bash
journalctl --user -u openclaw-gateway.service --since "1 min ago" | head -20
```

**Diagnostic — check if proxy vars are inherited:**
```bash
systemctl --user show-environment | grep -i proxy
```

See [openclaw/openclaw#28368](https://github.com/openclaw/openclaw/issues/28368), [openclaw/openclaw#13336](https://github.com/openclaw/openclaw/issues/13336), [openclaw/openclaw#29120](https://github.com/openclaw/openclaw/issues/29120).

#### Cause 3: Provider cooldown after timeout

After the first timeout, OpenClaw incorrectly treats it as a rate limit and puts Ollama into exponential cooldown (1m → 5m → 25m → 1hr). All subsequent requests fail with 0 tokens instantly.

```bash
# Check for stale cooldown state
find ~/.openclaw -name "auth-profiles.json" -exec grep -l "disabledUntil" {} \;
# If found, edit the file and remove the usageStats/disabledUntil sections

# Restart gateway to clear in-memory cooldown state
openclaw gateway restart
```

> **Note:** The `models.providers.ollama.retry` config key is NOT supported by OpenClaw's zod schema (as of v2026.3.1). The only way to clear cooldown is to edit `auth-profiles.json` directly and restart the gateway.

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

# vLLM Deployment Guide

Run Wazuh OpenClaw Autopilot with self-hosted open-source models via [vLLM](https://github.com/vllm-project/vllm). Zero cloud API costs, full data sovereignty.

## Quick Start

### 1. Start vLLM with Tool Calling

**Qwen3 32B** (recommended — best open-source tool calling):

```bash
vllm serve Qwen/Qwen3-32B \
  --served-model-name qwen3-32b \
  --api-key "your-secure-key" \
  --port 8000 \
  --enable-auto-tool-choice \
  --tool-call-parser hermes \
  --max-model-len 131072 \
  --gpu-memory-utilization 0.95
```

**Llama 3.3 70B** (strong general reasoning):

```bash
vllm serve meta-llama/Llama-3.3-70B-Instruct \
  --served-model-name llama3.3-70b \
  --api-key "your-secure-key" \
  --port 8000 \
  --enable-auto-tool-choice \
  --tool-call-parser llama3_json \
  --tensor-parallel-size 2 \
  --max-model-len 131072 \
  --gpu-memory-utilization 0.95
```

### 2. Install the Config

```bash
cp openclaw/openclaw-vllm.json ~/.openclaw/openclaw.json
```

Edit `~/.openclaw/openclaw.json`:
- Update `models.providers.vllm.baseUrl` if vLLM is on a different host/port
- Set `VLLM_API_KEY` to match `--api-key` from step 1
- Adjust `agents.defaults.model.primary` to match the model you're running

### 3. Refresh the Model Catalog (MANDATORY)

```bash
openclaw models scan
```

> **This step is critical.** OpenClaw's `openai-completions` provider only sends tool definitions to models that have `toolUse: true` in its capability catalog. Custom providers (like vLLM) are not in the catalog by default. Running `openclaw models scan` probes your vLLM endpoint and populates the metadata. **Without this step, ALL agents will silently fail** — they output tool calls as plain text with `stopReason: "stop"` instead of actually invoking tools like `web_fetch`.

### 4. Verify

```bash
# Check vLLM is serving
curl http://localhost:8000/v1/models -H "Authorization: Bearer your-secure-key"

# Start OpenClaw
openclaw start
openclaw status --all
```

## Recommended Models

| Model | Params | VRAM (FP16) | Tool Parser | Best For |
|-------|--------|-------------|-------------|----------|
| **Qwen3 32B** | 32B | ~64 GB | `hermes` | Primary agent model — excellent tool calling |
| **Llama 3.3 70B** | 70B | ~140 GB | `llama3_json` | Complex investigation/reasoning tasks |
| **DeepSeek-R1 70B** | 70B | ~140 GB | `deepseek_v32` | Chain-of-thought reasoning |
| **Mistral Large** | 123B | ~246 GB | `mistral` | Multi-language environments |
| **Qwen3 8B** | 8B | ~14 GB | `hermes` | Budget/testing — single consumer GPU |

Any model on [HuggingFace](https://huggingface.co/models) that vLLM supports can be used. The table above lists models tested with Wazuh Autopilot's multi-step tool calling pipeline.

### Model Selection Tips

- **For Wazuh Autopilot**: Qwen3 32B is the sweet spot — reliable tool calling (hermes format), strong reasoning, fits on ~64 GB VRAM.
- **For investigation-heavy workloads**: Llama 3.3 70B provides deeper analysis but needs ~140 GB VRAM (multi-GPU).
- **For reasoning models** (DeepSeek-R1): Add `--reasoning-parser` flag and set `"reasoning": true` in the config.
- **Avoid 7B models for production** — they struggle with multi-step tool calling chains required by the investigation and response planner agents.

## Critical vLLM Flags

| Flag | Required | Purpose |
|------|----------|---------|
| `--enable-auto-tool-choice` | **Yes** | Enables tool/function calling support |
| `--tool-call-parser <parser>` | **Yes** | Maps model's tool output format to OpenAI API |
| `--served-model-name <name>` | Recommended | Must match the model `"id"` in openclaw config |
| `--tensor-parallel-size N` | For multi-GPU | Split model across N GPUs |
| `--max-model-len <tokens>` | Recommended | Match to `"contextWindow"` in config |
| `--gpu-memory-utilization 0.95` | Recommended | Use most of available VRAM |
| `--reasoning-parser <parser>` | For reasoning models | Extracts chain-of-thought from output |
| `--trust-remote-code` | Some models | Required by certain HuggingFace models with custom code |

### Tool Call Parsers by Model Family

```
hermes        → Qwen3, Qwen2.5, NousResearch/Hermes
llama3_json   → Llama 3.1, Llama 3.2, Llama 3.3
mistral       → Mistral, Mixtral
deepseek_v32  → DeepSeek-V3, DeepSeek-R1
minimax_m2    → MiniMax-M2.1
internlm      → InternLM 2.5+
jamba          → AI21 Jamba
```

## Hardware Requirements

vLLM supports both NVIDIA (CUDA) and AMD (ROCm) GPUs. The key constraint is total VRAM — pick a model that fits your available GPU memory:

| Model Size | VRAM Needed (FP16) | Example Hardware |
|------------|-------------------|------------------|
| 7-8B | ~14 GB | Single consumer GPU (24 GB) |
| 14B | ~28 GB | Single data center GPU (40 GB) |
| 32B | ~64 GB | Single high-end GPU (80 GB) |
| 70B | ~140 GB | 2 GPUs with `--tensor-parallel-size 2` |
| 130B+ | ~192 GB+ | Multi-GPU or high-VRAM accelerators |

**Quantized models** (AWQ, GPTQ) halve VRAM requirements at the cost of some tool-calling accuracy. Use `--quantization awq` to load quantized variants.

### Platform-Specific Install

**NVIDIA (CUDA):**
```bash
pip install vllm
```

**AMD (ROCm):**
```bash
pip install vllm==0.15.0+rocm700 --extra-index-url https://wheels.vllm.ai/rocm/0.15.0/rocm700
```

### Free GPU Cloud Credits

Several cloud providers offer free credits for GPU instances suitable for running vLLM. Check your preferred provider's developer program for available offers.

## Docker Deployment

### Single GPU

```bash
docker run -d \
  --gpus '"device=0"' \
  --name vllm-autopilot \
  -p 8000:8000 \
  -v /models:/models \
  vllm/vllm-openai:latest \
  --model Qwen/Qwen3-32B \
  --served-model-name qwen3-32b \
  --api-key "${VLLM_API_KEY}" \
  --enable-auto-tool-choice \
  --tool-call-parser hermes \
  --max-model-len 131072 \
  --gpu-memory-utilization 0.95
```

### Multi-GPU (70B models)

```bash
docker run -d \
  --gpus all \
  --name vllm-autopilot \
  -p 8000:8000 \
  --shm-size 16g \
  -v /models:/models \
  vllm/vllm-openai:latest \
  --model meta-llama/Llama-3.3-70B-Instruct \
  --served-model-name llama3.3-70b \
  --api-key "${VLLM_API_KEY}" \
  --enable-auto-tool-choice \
  --tool-call-parser llama3_json \
  --tensor-parallel-size 2 \
  --max-model-len 131072 \
  --gpu-memory-utilization 0.95
```

> **AMD ROCm**: Use `vllm/vllm-openai-rocm:latest` image with `--device=/dev/kfd --device=/dev/dri --group-add video` instead of `--gpus`. Same vLLM flags apply.

## Air-Gapped Deployment

For environments without internet access, pre-download models and run offline.

### Pre-download Models (on a machine with internet)

```bash
pip install huggingface-hub
huggingface-cli download Qwen/Qwen3-32B --local-dir /models/qwen3-32b
```

### Run Offline

```bash
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1

vllm serve /models/qwen3-32b \
  --served-model-name qwen3-32b \
  --api-key "${VLLM_API_KEY}" \
  --port 8000 \
  --enable-auto-tool-choice \
  --tool-call-parser hermes \
  --max-model-len 131072 \
  --gpu-memory-utilization 0.95
```

Combine with `openclaw-vllm.json` (which has no cloud dependencies) for a fully air-gapped setup. See [AIR_GAPPED_DEPLOYMENT.md](AIR_GAPPED_DEPLOYMENT.md) for the full air-gapped guide.

## Production Recommendations

### systemd Service

```ini
[Unit]
Description=vLLM Inference Server for Wazuh Autopilot
After=network.target

[Service]
Type=simple
User=vllm
Environment=VLLM_API_KEY=your-secure-key
Environment=HF_HOME=/opt/models
ExecStart=/opt/vllm/bin/vllm serve Qwen/Qwen3-32B \
  --served-model-name qwen3-32b \
  --api-key ${VLLM_API_KEY} \
  --port 8000 \
  --enable-auto-tool-choice \
  --tool-call-parser hermes \
  --max-model-len 131072 \
  --gpu-memory-utilization 0.95
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
```

### Performance Tuning

- **`--gpu-memory-utilization 0.95`**: Use 95% of VRAM. Increase to 0.99 if not sharing the GPU.
- **`--max-model-len`**: Set to actual context you need. Lower = more concurrent requests.
- **`--dtype auto`**: vLLM auto-selects BF16/FP16. Use `--dtype float16` for older GPUs without BF16.
- **`--quantization awq`**: Load AWQ-quantized models to halve VRAM. Some tool-calling accuracy loss.
- **`--enforce-eager`**: Disables CUDA graph compilation. Slower steady-state but faster startup.

### Health Checks

```bash
# vLLM health
curl -f http://localhost:8000/health

# Model loaded and responding
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer ${VLLM_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen3-32b","messages":[{"role":"user","content":"ping"}],"max_tokens":5}'
```

## Troubleshooting

### "Tool web_fetch not found" or agents output tool calls as text

vLLM was started without `--enable-auto-tool-choice --tool-call-parser <parser>`. Restart vLLM with both flags.

### 404 "Model not found"

The model `"id"` in `openclaw-vllm.json` doesn't match `--served-model-name`. They must be identical.

### Out of memory (OOM)

- Reduce `--max-model-len` (e.g., 32768 instead of 131072)
- Reduce `--gpu-memory-utilization` (e.g., 0.90)
- Use a quantized model variant (AWQ/GPTQ)
- Add more GPUs with `--tensor-parallel-size`

### Slow inference / timeouts

- Increase `timeoutSeconds` in config (default 900, try 1200 for 70B+ models)
- Reduce `maxConcurrent` to 1 if running a single vLLM instance
- Monitor GPU utilization: `nvidia-smi -l 1` or `rocm-smi`

### "reasoning" errors

If you see `model does not support thinking`, set `"reasoning": false` in the model config. Only models started with `--reasoning-parser` support reasoning mode.

### OpenClaw says model has no tool support / agents output tool calls as text

This is the most common vLLM deployment issue. OpenClaw's `openai-completions` provider only sends tool definitions if the model has `toolUse: true` in its internal capability catalog. Custom providers like vLLM are not in the catalog by default.

**Fix**: Run `openclaw models scan` to probe your vLLM endpoint and populate the catalog. This must be done after every config change that adds or modifies models. If the gateway is already running, restart it after the scan.

## Running Multiple Models

You can run multiple vLLM instances on different ports or GPUs:

```bash
# GPU 0: Qwen3 32B for most agents
CUDA_VISIBLE_DEVICES=0 vllm serve Qwen/Qwen3-32B \
  --served-model-name qwen3-32b --port 8000 ...

# GPU 1-2: Llama 3.3 70B for investigation agent
CUDA_VISIBLE_DEVICES=1,2 vllm serve meta-llama/Llama-3.3-70B-Instruct \
  --served-model-name llama3.3-70b --port 8001 --tensor-parallel-size 2 ...
```

Then configure two providers in your config:

```json5
"models": {
  "providers": {
    "vllm-small": {
      "baseUrl": "http://127.0.0.1:8000/v1",
      "api": "openai-completions",
      "apiKey": "${VLLM_API_KEY}",
      "models": [{ "id": "qwen3-32b", ... }]
    },
    "vllm-large": {
      "baseUrl": "http://127.0.0.1:8001/v1",
      "api": "openai-completions",
      "apiKey": "${VLLM_API_KEY}",
      "models": [{ "id": "llama3.3-70b", ... }]
    }
  }
}
```

Then assign per-agent: `"model": { "primary": "vllm-large/llama3.3-70b" }` for the investigation agent.

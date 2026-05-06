# Local LLM Benchmark for SOC Triage — Final Report

Run date: 2026-05-06. Source repo: `sec_eval/`.

This report consolidates two independent benchmarks of locally-hosted LLMs
for SOC Tier-1 triage work, plus a hardware recommendation for production
deployment.

## TL;DR

### Best models (Q4_K_M, playbook bench)

- **Best overall: `gemma4:latest` — 100% composite.** New from Google;
  MoE with 8 B active params, 9.6 GB on disk. Perfect across every
  sub-score: 10/10 verdict, 10/10 severity, 10/10 MITRE, 10/10 tool
  selection. Native `tools` and `thinking` capability. **Fits Mac mini
  16 GB** unlike gemma3:27b. Latency 14.4 s p50 on a 4090 (thinking
  mode is on by default; expect ~30-60 s on M-series Macs).
- **Best for latency: `llama3.1:8b` — 90% at 3.3 s p50** in
  harness-executed mode. Roughly 4× faster than gemma4. Never wrong on
  verdict or severity (10/10/10/10).
- **Smallest viable: `Foundation-Sec-8B` — 88% at 2.1 s p50** in
  harness-executed mode. Cyber pre-training closes the MITRE gap. ~5
  GB on disk.
- **Best 24 GB option without thinking-mode latency: `gemma3:27b` — 96%**
  in harness-executed mode at 9.3 s p50. Lower latency than gemma4
  with similar accuracy; 17 GB on disk so needs Tier 2 hardware.
- **Avoid**: `Lily-Cybersecurity-7B` (verdict logic is inverted, 0/10);
  `llama3.1:8b` in native tool-calling mode (15% — Q4_K_M can't emit
  valid OpenAI `tool_calls` payloads — use harness-executed instead).

### Machine selection

**Tier 1 — 16 GB total memory (~$300-$1100).** **`gemma4:latest` (9.6 GB,
the 100% top model) fits.** Also runs `llama3.1:8b` (90%) and
`Foundation-Sec-8B` (88%) without thinking-mode latency. Cannot run
`gemma3:27b` (needs 17 GB). Mac mini 16 GB is no longer a quality
compromise — it just trades latency (~30-60 s/case with gemma4 thinking
on, ~6-8 s with llama3.1) for the budget delta.

- **Mac mini 16 GB M4 base** — ~$599 (the user's candidate)
- **Mac mini 16 GB M2** — ~$499 refurbished or used
- **MacBook Air 16 GB M3** — ~$1099 (works if a laptop is needed)
- **Used desktop with RTX 3060 12 GB or RTX 4060 16 GB** — ~$200-$400 GPU
  (8 B Q4 models still fit; 14 B borderline)
- **Mini PC (Beelink / Minisforum) with 16 GB RAM and Ryzen iGPU** —
  ~$300-$500 (slowest of the tier; ~10-20 t/s on 8 B Q4)

**Tier 2 — 24 GB total memory ($700-$2200).** The sweet spot. Runs
**every model in this benchmark, including `gemma3:27b` at 96%**.

- **Used RTX 3090 24 GB desktop** — ~$700 used GPU, $1000 full build
  (fastest at this tier; 350 W TDP)
- **Mac mini 24 GB M4 Pro** — ~$1399 (quiet, 60 W idle, lower memory
  bandwidth than the M-Max bus)
- **MacBook Pro 14" 24 GB M4 Pro** — ~$1799 (laptop form factor)
- **Mac Studio 32 GB M4 Max** — ~$1999 (best Apple Silicon memory
  bandwidth; 4 extra GB of headroom)
- **New build with RTX 4090 24 GB** — ~$1800 GPU, $2500 full build
  (fastest on the planet for these models)

**Tier 3 — 32-64+ GB ($2000+).** Thinking-model territory. Required for
32-B reasoning models (Qwen3-32B, DeepSeek-R1-Distill-32B) without
CPU spillover, and for fp16 / Q8 quantizations of mid-size models.

- **Mac Studio 64 GB M4 Max** — ~$3499 (sweet spot for thinking models)
- **Mac Studio 128 GB M4 Ultra** — ~$5599 base (massive headroom; can
  hold multiple models hot)
- **RTX 5090 32 GB desktop** — ~$2500 GPU, $3500 full build
- **Dual RTX 3090 (48 GB combined)** — ~$1400 used cards, $2200 build
  (best $/GB; tensor-parallel for 32-B models)

**The accuracy gap between Tier 1 and Tier 2 has flipped.** With
`gemma4:latest`, Tier 1 reaches 100% composite — higher than gemma3:27b
on Tier 2 (96%). The remaining gap is latency: gemma4 takes 14 s p50 on
a 4090 and ~30-60 s on Apple Silicon (thinking mode is on by default).
Tier 2 + gemma3:27b runs about 4× faster than Tier 1 + gemma4. Pick
based on whether you can absorb the latency.

### Thinking / reasoning models

- **They need more memory than non-thinking models of the same size**
  because the KV cache holds the `<think>` trace, not just the visible
  answer.
- **They help on multi-step deliberation, hurt on speed and recall.**
  This bench: Qwen3-14B with thinking on scored 1/10 on MITRE in the
  classification bench (the technique ID got truncated when the
  reasoning trace ate the token budget), but 80% in playbook
  tool-calling mode (the only model that drove native MCP calls
  end-to-end).
- **Don't run thinking models on Tier 1 (16 GB).** P50 latency exceeds
  30 s per alert.
- **Tier 2 (24 GB) handles Qwen3-14B with thinking on** for queued or
  end-of-shift workflows, not for live triage.
- **Tier 3 (32+ GB) is the right home for Qwen3-32B,
  DeepSeek-R1-Distill-32B, GLM-4-32B.** Use these when a human reviewer
  needs to read and defend the model's reasoning chain.

## Executive summary

**Best overall: `gemma3:27b`.** Wins both benchmarks. 88% on the 32-case
classification bench, 96% on the 10-case playbook bench with mock MCP
tools. Needs ~17 GB of GPU/unified memory.

**Best for latency-sensitive deployments: `llama3.1:8b`.** 90% on the
playbook bench at 3.3 s p50 latency — under one-third the time of
gemma3:27b — and never wrong on verdict or severity. Fits comfortably on
a Mac mini 16 GB.

**Smallest viable footprint: `Foundation-Sec-8B`.** 88% on the playbook
bench at 2.1 s p50, the fastest model that still scores in the top tier.
Cyber pre-training closes the MITRE recall gap to gemma3:27b.

The two benchmarks agree on the top model and disagree on second place
(Llama-3.1 wins second on the playbook bench because it doesn't have to
drive tools natively — the harness does that). Llama-3.1 in native
tool-calling mode collapses to 15% because the Q4_K_M quant can't emit
valid OpenAI `tool_calls` payloads — a format failure, not a reasoning
failure. The harness-executed mode in the playbook bench corrects for
that and shows the model's true capability.

## What was measured

Two benchmarks, both in this repository, both single-machine, both
Q4_K_M quantization, both temperature 0.

**Benchmark 1 — Classification bench (32 cases).** Single-shot
prompts, no tools. Four sections:

1. Incident recognition (7 binary cases): incident vs benign on
   natural-language scenarios.
2. Threat-type classification (7 multi-class): ransomware / phishing
   / SQLi / XSS / credential dumping / DoS / supply chain.
3. MITRE ATT&CK mapping (10 cases): the model returns one or more
   technique IDs.
4. Syslog triage (8 cases × 2 modes): raw multi-line log snippets,
   binary verdict. Tested with and without a `drain3` template
   summary appended to the prompt.

**Benchmark 2 — Playbook bench (10 cases).** The model receives a
SKILL.md-style incident-response playbook (`incident_playbook.md`)
and access to five mock MCP servers — openvas, siem, threat_intel,
cmdb, edr. For each alert, the model must call enrichment tools,
read the results, and return a structured JSON verdict containing
`verdict`, `severity`, `mitre`, `tools_used`, `rationale`. The 10
scenarios are derived from the 32-case bench with consistent
expected verdicts.

The playbook bench supports three execution modes:

- **Tool-calling**: the model drives tool dispatch via OpenAI
  `tool_calls` payloads. Only works for Ollama models that
  advertise the `tools` capability.
- **Harness-executed**: the model returns a JSON tool plan; the
  harness dispatches each entry against the real MCP servers via
  `MCPServerStdio.direct_call_tool`; results are sent back; the
  model writes the final verdict. Works for every model regardless
  of native `tools` capability. **This is the apples-to-apples
  measurement.**
- **Describe-only**: single-shot, no execution. The model lists the
  tools it would call, no tool actually runs.

Scoring per playbook case: verdict 35%, MITRE 25%, tool selection
25%, severity 15%. Format failures zero the entire case.

## Test hardware

All benchmark runs were performed on:

- **GPU**: NVIDIA RTX 4090 (24 GB VRAM, 450 W TDP)
- **CPU**: AMD EPYC 7352 (24 cores / 48 threads)
- **RAM**: 251 GB DDR4
- **OS**: Linux 6.8
- **Inference**: Ollama 0.23.1, Q4_K_M quantization for all models

All models loaded fully on GPU; none spilled to CPU RAM during
inference. Latency numbers below assume this hardware. Mac and
slower-GPU expectations are in the *Hardware recommendations*
section.

## Models tested

Seven models, all installed via Ollama:

| Model | Family | Params | Q4_K_M size | Capabilities |
|---|---|---|---|---|
| `gemma4:latest` | Google Gemma 4 (MoE) | 8 B active | 9.6 GB | completion, vision, audio, tools, thinking |
| `gemma3:27b` | Google Gemma 3 | 27 B | ~17 GB | completion, vision (no tools) |
| `llama3.1:8b` | Meta Llama 3.1 | 8 B | ~5 GB | completion, tools |
| Foundation-Sec-8B | Cyber-tuned (Llama 3.1 base) | 8 B | ~5 GB | completion only |
| `qwen3:14b` | Alibaba Qwen 3 | 14 B | ~9 GB | completion, tools, thinking |
| ZySec-7B-v1 | Cyber-tuned | 7 B | ~4.5 GB | completion only |
| Lily-Cybersecurity-7B | Cyber-tuned | 7 B | ~4.5 GB | completion only |

Qwen3:32b was tested but excluded — its 32K-context KV cache pushed
the 4090 into 17/83 % CPU/GPU split, dropping inference to ~3 t/s.

## Classification bench results (32 cases)

Six models, same prompts, same scoring.

### Accuracy

| Section | Foundation-Sec | Llama-3.1 | ZySec | Lily | Qwen3-14B | Gemma3-27B | Gemma4-latest |
|---|---|---|---|---|---|---|---|
| Incident recognition (7) | 4 (57%) | 7 (100%) | 6 (86%) | 5 (71%) | 5 (71%) | **7 (100%)** | **7 (100%)** |
| Threat classification (7) | 7 (100%) | 7 (100%) | 4 (57%) | 6 (86%) | 5 (71%) | **7 (100%)** | **7 (100%)** |
| MITRE ATT&CK (10) | 7 (70%) | 2 (20%) | 2 (20%) | 4 (40%) | 1 (10%) | **7 (70%)** | **7 (70%)** |
| Syslog raw (8) | 5 (62%) | 8 (100%) | 5 (62%) | 7 (88%) | 5 (62%) | **8 (100%)** | 7 (88%) |
| Syslog drain3 (8) | 5 (62%) | 7 (88%) | 5 (62%) | 1 (12%) | 6 (75%) | 7 (88%) | 7 (88%) |
| **Overall / 32** | **23 (72%)** | **23 (72%)** | **17 (53%)** | **16 (50%)** | **17 (53%)** | **28 (88%)** | **28 (88%)** |

`Gemma4-latest` was run with `--num-predict 1200` (vs the default 400). At
the default, the thinking-mode trace consumes the entire token budget on
long syslog prompts and the visible answer is empty — scoring the model
artificially low (23/32, 72%). With 1200 tokens the answer always lands.
Same caveat applies to any other thinking-mode model on this bench.

### Latency (avg per call, 4090)

| Model | Avg s | p95 s | Peak GPU MB |
|---|---|---|---|
| Lily-Cyber-7B | 0.47 | 1.23 | ~17,700 |
| ZySec-7B-v1 | 0.55 | 1.26 | ~18,100 |
| Foundation-Sec-8B | 0.70 | 0.85 | ~9,300 |
| Llama-3.1-8B | 0.80 | 0.91 | ~18,500 |
| Gemma3-27B | 1.60 | 1.79 | ~20,500 |
| Gemma4-latest (`-n 1200`) | 3.26 | 5.75 | ~10,612 |
| Qwen3-14B | 4.53 | 5.14 | ~14,300 |

### Key findings — classification

1. **Gemma3-27B leads by 5 cases.** It's the only model that doesn't
   have a section it loses badly on — perfect on three of five,
   tied with Foundation-Sec on MITRE.
2. **Foundation-Sec's MITRE moat is gone.** Gemma3-27B matches its
   7/10 from a generalist baseline, so the cyber pre-training that
   justified Foundation-Sec on previous runs no longer outweighs
   its incident-bias weakness (4/7 on incident recognition, 0/3 on
   benign cases).
3. **Thinking-mode models need a larger `num_predict` budget on this
   bench.** At the default 400 tokens, both Qwen3-14B and Gemma4 burn
   most of the budget inside `<think>...</think>` and the answer is
   truncated. Qwen3-14B scores 1/10 on MITRE for this reason. Gemma4
   collapses on syslog (2/8) at the default but recovers to 7/8 with
   `--num-predict 1200`. The `--num-predict` flag (added for this
   reason) is the right knob to set whenever a thinking-capable model
   shows up in this bench.
4. **drain3 augmentation is model-dependent.** It helps Qwen3-14B
   (+1 case), unchanged on Foundation-Sec/ZySec, costs Llama-3.1
   and Gemma3 1 case each, and collapses Lily (7→1). Don't ship
   drain3 as a universal pre-filter.
5. **The "SOC fine-tuned 7B" tier loses.** A larger generalist
   beats all three SOC-tuned models on every section except MITRE.
   Model scale buys more than cyber fine-tuning on this workload.

## Playbook bench results (10 cases)

The model loads `incident_playbook.md` as its system prompt, then
triages each alert by calling MCP tools and returning a structured
JSON verdict.

### Headline: top scores per model

`gemma4:latest` was added late in the run and has native `tools` and
`thinking` capability, so its best mode is the native tool-calling
loop. The other models are reported in their best-performing mode
(harness-executed for the rest, since most don't advertise `tools`).

| Model | Mode | Composite | Verdict | Severity | MITRE | Tools | p50 latency | Disk size |
|---|---|---|---|---|---|---|---|---|
| **gemma4:latest** | tool-calling | **100%** | 10/10 | 10/10 | 10/10 | 10/10 | 14.4 s | 9.6 GB |
| gemma3:27b | harness-executed | 96% | 10/10 | 9/10 | 9/10 | 10/10 | 9.3 s | 17 GB |
| llama3.1:8b | harness-executed | 90% | 10/10 | 10/10 | 6/10 | 10/10 | 3.3 s | 5 GB |
| Foundation-Sec-8B | harness-executed | 88% | 10/10 | 10/10 | 7/10 | 8/10 | 2.1 s | 5 GB |
| qwen3:14b | tool-calling | 80% | 9/10 | 9/10 | 7/10 | 7/10 | 13.8 s | 9 GB |
| ZySec-7B | harness-executed | 68% | 9/10 | 9/10 | 2/10 | 7/10 | 1.7 s | 4.5 GB |
| Lily-Cyber-7B | harness-executed | 14% | 0/10 | 6/10 | 2/10 | 0/10 | 4.4 s | 4.5 GB |

**`gemma4:latest` is the first model in this benchmark to score
perfectly on every sub-metric.** It's also the smallest model in the
top three (9.6 GB at Q4_K_M), small enough to fit on a Mac mini
16 GB. The latency cost is real: 14.4 s p50 on the 4090 (vs 9.3 s for
gemma3:27b, vs 3.3 s for llama3.1:8b), driven by the always-on
thinking mode.

### Three-mode comparison

How each model fares depending on who drives the tool loop. The
"refused" cells are where Ollama's OpenAI-compat endpoint blocks
the request because the model doesn't advertise `tools` capability.

| Model | Tool-calling | Harness-executed | Describe-only |
|---|---|---|---|
| **gemma4:latest** | **100%** | not run | not run |
| gemma3:27b | refused | **96%** | 90% |
| llama3.1:8b | 15% (format-fail) | **90%** | 85% |
| Foundation-Sec-8B | refused | **88%** | 80% |
| qwen3:14b | **80%** | 72% | not run |
| ZySec-7B | refused | 68% | 71% |
| Lily-Cyber-7B | refused | 14% | 11% |

### Key findings — playbook

1. **Harness-executed beats describe-only for every reasoning-capable
   model.** Gemma3 90% → 96%, Llama-3.1 85% → 90%, Foundation-Sec 80%
   → 88%. The lift is mostly on MITRE — when the model receives the
   real SIEM `summary` text and threat-intel `tags`, it picks the
   right technique IDs at a higher rate than from priors alone.

2. **Llama-3.1's tool-calling collapse was format, not reasoning.**
   At Q4_K_M, Llama-3.1:8b emits text that looks like a tool call
   (`{"name":..,"parameters":..}` in the response body) instead of a
   structured `tool_calls` payload. The OpenAI shim doesn't
   recognise it; no tool ever dispatches; the model answers blind.
   Score: 15%. Same weights, harness-executed: **90%**. The model
   understood the playbook all along — it just couldn't speak the
   wire format reliably.

3. **Qwen3:14b is the inverse case.** It's the only model that
   genuinely drives the OpenAI tool_calls protocol from start to
   finish (80% in tool-calling mode). Forced through the
   harness-executed JSON-plan flow, it regresses 8 points and pays
   a 5× latency tax for thinking tokens. **For Qwen3, prefer native
   tool-calling.**

4. **Lily's verdict logic is inverted.** It returns valid JSON,
   lists tools, follows the protocol — but it calls incidents
   benign and benign incidents. 0/10 on verdict in any mode.

## Cross-benchmark interpretation

Comparing each model's standing across both benchmarks:

| Model | Classification (32) | Playbook (10) |
|---|---|---|
| Gemma4-latest | 1st tie (88%, `-n 1200`) | **1st (100% tool-calling)** |
| Gemma3-27B | 1st tie (88%) | 2nd (96% harness-executed) |
| Llama-3.1-8B | 3rd tie (72%) | 3rd (90% harness-executed) |
| Foundation-Sec-8B | 3rd tie (72%) | 4th (88% harness-executed) |
| Qwen3-14B | 5th tie (53%) | 5th (72% / 80% native) |
| ZySec-7B | 5th tie (53%) | 6th (68% harness-executed) |
| Lily-Cyber-7B | 7th (50%) | 7th (14%) |

The top is stable but the leader has shifted: **Gemma4-latest ties for
first on classification (28/32) and wins outright on the playbook
(100%)**. Gemma3-27B remains right behind it on classification and is
2nd on the playbook (96%). Gemma4 wins the dual-bench title at a
fraction of the size (9.6 GB vs 17 GB).

Second place swaps: in the classification bench Foundation-Sec wins
on MITRE while Llama-3.1 wins on triage; in the playbook bench
Llama-3.1 produces the right verdict and severity on every single
case (10/10/10/10) while Foundation-Sec loses one tool-selection
case. Foundation-Sec also gives up its MITRE moat — both score
6-7/10 with real tool data. **Llama-3.1's playbook-bench performance
is strictly the better choice** if you can spare the extra parameters
and 0.6 s of latency.

Lily-Cyber gets dramatically worse on the playbook bench (50% →
14%) because its verdict logic is inverted and the multi-step
protocol amplifies that failure across more sub-scores.

## Hardware recommendations

Three deployment tiers, ordered by budget. Inference speed
estimates assume Ollama at Q4_K_M; "fits" is "model weights +
typical KV cache stay in memory at the model's default context
length without spilling to CPU".

### Tier 1: 16 GB total memory — $300-$1100

Usable memory after OS overhead is roughly 10-11 GB on macOS, ~12-14
GB on Linux. This limits you to 7-8 B dense models at Q4_K_M, **plus
`gemma4:latest`** (9.6 GB MoE — fits on Mac mini 16 GB and scores 100%
in the playbook bench). Cannot run `gemma3:27b` (17 GB).

Concrete machines in this tier:

| Machine | Memory | Approx. cost | Inference speed (8 B Q4) | Notes |
|---|---|---|---|---|
| Mac mini 16 GB M4 base | 16 GB unified | $599 new | ~30-50 t/s | The user's candidate. Quiet, ~10 W idle. |
| Mac mini 16 GB M2 (refurb / used) | 16 GB unified | $499 | ~25-40 t/s | Slower GPU than M4 but cheaper. |
| MacBook Air 16 GB M3 | 16 GB unified | $1099 new | ~30-45 t/s | If a laptop is required. |
| Custom desktop, RTX 4060 Ti 16 GB | 16 GB VRAM | $400 GPU + $700 build | ~70-90 t/s | Fastest in tier; gaming GPU. |
| Custom desktop, used RTX 3060 12 GB | 12 GB VRAM | $200 used GPU + $600 build | ~50-70 t/s | Cheapest discrete-GPU path; 14 B doesn't fit. |
| Mini PC (Beelink SER8 / Minisforum UM790) | 16-32 GB DDR5 | $300-500 | ~10-20 t/s on iGPU | Slowest of the tier; runs ollama on AMD iGPU. |

| Model | Fits 16 GB Mac mini? | Notes |
|---|---|---|
| gemma3:27b | No | Needs ~17 GB |
| llama3.1:8b | Yes | ~5 GB |
| Foundation-Sec-8B | Yes | ~5 GB |
| qwen3:14b | Borderline / no | ~9 GB weights + KV cache pushes over |
| ZySec-7B | Yes | ~4.5 GB |
| Lily-Cyber-7B | Yes | ~4.5 GB |

Expected inference speed on M4 base for an 8 B Q4_K_M model:
~25-50 tokens/s (compared to ~80-120 tokens/s on a 4090). For the
playbook bench's typical reply length (~250 tokens), this means
roughly 5-10 s per single-shot call. Two-round harness-executed
flow doubles that to 10-20 s p50.

**Best deployment options on Tier 1:**

- **For accuracy**: `gemma4:latest` in tool-calling mode. 100%
  composite, perfect across all sub-scores. **Latency caveat: 14.4 s
  p50 on a 4090, expect ~30-60 s on M4 base** because thinking mode
  is on by default and Apple Silicon memory bandwidth is ~3-4× lower.
- **For speed**: `llama3.1:8b` in harness-executed mode. 90%
  composite, ~6-8 s p50 on M4 base.
- **For smallest footprint**: `Foundation-Sec-8B` in harness-executed
  mode. 88% composite, ~4-6 s p50 on M4 base.

**The Mac mini 16 GB is no longer a quality compromise.** Gemma 4
gives Tier 1 access to the highest-scoring model in this benchmark —
the only thing Tier 2 buys at this point is lower latency on the same
or lower-quality model.

### Tier 2: 24 GB total memory — $700-$2200

Concrete machines in this tier, ordered by cost:

| Machine | Memory | Approx. cost | Inference speed (gemma3:27b) | Notes |
|---|---|---|---|---|
| Used RTX 3090 in custom desktop | 24 GB VRAM | $700 GPU + $1000 build | ~50-70 t/s, ~12-15 s p50 | Fastest at this tier; 350 W TDP; needs 750 W PSU |
| Mac mini 24 GB M4 Pro | 24 GB unified | $1399 new | ~25-40 t/s, ~10-15 s p50 | Quietest; ~30 W idle; lower bandwidth than M-Max |
| MacBook Pro 14" 24 GB M4 Pro | 24 GB unified | $1799 new | ~25-40 t/s, ~10-15 s p50 | If a laptop is required. |
| Mac Studio 32 GB M4 Max | 32 GB unified | $1999 new | ~40-60 t/s, ~7-10 s p50 | Best Apple Silicon bandwidth; 4 GB headroom for thinking |
| New build with RTX 4090 | 24 GB VRAM | $1800 GPU + $2500 build | ~80-110 t/s, ~5-7 s p50 | Reference machine for this bench (4090) |

All three run every model in this benchmark, **including
gemma3:27b**. Expected gemma3:27b latency for the playbook bench:

- RTX 4090 (the test machine): 9.3 s p50 (measured)
- RTX 3090: ~12-15 s p50 (slower memory bandwidth, same VRAM)
- Mac mini 24 GB M4 Pro: ~10-15 s p50
- Mac Studio M4 Max: ~7-10 s p50

**Best deployment**: gemma3:27b for quality (96%), llama3.1:8b for
speed (90% at ~5 s p50). You can A/B both depending on the
workload.

**Verdict**: Tier 2 is the **sweet spot** for production. Full
bench accessible, headroom for one larger model side-by-side with
a smaller one for fallback.

### Tier 3: 32-64+ GB unified memory or 4090/5090 — $2000+

Required for thinking models without compromise (qwen3:32b,
DeepSeek-R1-Distill-32B, GLM-4-32B), for higher-quality
quantizations (Q6/Q8 or fp16) of mid-size models, and for
running multiple models simultaneously without unloads.

| Machine | Memory | Approx. cost | Notes |
|---|---|---|---|
| Mac Studio 64 GB M4 Max | 64 GB unified | $3499 new | Sweet spot for thinking models; ~410 GB/s memory bandwidth |
| Mac Studio 128 GB M4 Ultra | 128 GB unified | $5599 new (base) | Massive headroom; can hold multiple models hot in memory |
| MacBook Pro 16" 64 GB M4 Max | 64 GB unified | $4699 new | Laptop alternative to the Studio 64 GB |
| Custom build with RTX 5090 | 32 GB VRAM | $2500 GPU + $3500 build | 32 GB is the missing piece for 32-B thinking models |
| Dual RTX 3090 in custom build | 48 GB VRAM total | $1400 used GPUs + $2200 build | Best $/GB; needs tensor-parallel inference (vllm or TGI) |
| Used RTX 4090 desktop | 24 GB VRAM | $1500 used GPU + $2000 build | Tight on 32-B thinking models but full quality on 27 B |

**Best deployment**: Pick by workload. For pure quality:
gemma3:27b at Q6_K or Q8 (slight quality bump, ~1.4× memory).
For thinking models: qwen3:32b with deliberate reasoning, or
DeepSeek-R1-Distill-32B for slow-but-rigorous triage.

**Verdict**: Tier 3 is for **specialized workloads** — thinking
models, multi-model orchestration, or quality-maximizing single
calls. Most SOC Tier-1 triage doesn't need it.

### Tier comparison summary

| Tier | Hardware | Top model accessible | Top playbook score | p50 latency for top model |
|---|---|---|---|---|
| 1 | Mac mini 16 GB | **gemma4:latest** | **100%** | ~30-60 s on M4, 14 s on 4090 |
| 2 | RTX 3090 / Mac mini 24 GB / Studio M4 Max 32 GB | gemma4:latest or gemma3:27b | 96-100% | ~7-30 s |
| 3 | Studio 64 GB / 5090 / dual 3090 | qwen3:32b thinking, fp16 27 B | not benchmarked | depends |

**The accuracy gap between Tier 1 and Tier 2 has flipped.** Gemma 4
runs on Tier 1 hardware and scores higher than gemma3:27b on Tier 2.
The remaining tradeoff is latency: thinking-mode gemma4 takes 30-60 s
per case on M-series silicon, vs ~9 s for gemma3:27b on a 4090. Pick
based on whether your workflow can absorb the latency.

## Thinking-model considerations

Reasoning-mode (or "thinking") models — Qwen3, DeepSeek-R1,
GLM-4-Reasoner, etc. — generate an internal `<think>...</think>`
trace before answering. The trace is invisible to the user but
counts against the token budget and the KV cache.

**Why thinking models need more memory.** The KV cache grows
linearly with context length, including the thinking trace. A
model that generates 4000 thinking tokens before answering needs
KV cache headroom for those tokens. On a 16 GB Mac mini, this can
push you out of available memory mid-generation, especially on a
14B-or-larger thinking model.

**When they help.** Thinking models tend to win on multi-step
reasoning that benefits from explicit deliberation — RCA-style
triage where the model needs to weigh several signals. They tend
to lose on tasks where speed matters or where the answer is mostly
recall (MITRE ID lookup, threat classification).

**What this benchmark showed.** Qwen3-14B with thinking on by
default scored 1/10 on MITRE in the classification bench because
the model burned its 400-token budget inside `<think>` and
truncated before reaching the technique ID. In the playbook
bench's tool-calling mode it scored 80% (the only model to drive
native MCP tools end-to-end), but at 13.8 s p50 it was 4-7× slower
than every other model that scored above 70%.

**Recommended thinking-model picks for Tier 3 hardware.**

| Model | Memory at Q4 | Recommended hardware | Notes |
|---|---|---|---|
| qwen3:14b (thinking) | ~9 GB + KV | Tier 2+ | Already in this bench; native tool-calling |
| qwen3:32b (thinking) | ~20 GB + KV | Tier 3 | Excluded from bench due to 4090 spillover |
| DeepSeek-R1-Distill-32B | ~20 GB + KV | Tier 3 | Strong on multi-step reasoning |
| GLM-4-32B | ~20 GB + KV | Tier 3 | Newer; competitive with DeepSeek on reasoning |

Practical guidance:

- **Don't run thinking models on Tier 1.** The combination of
  thin memory and high token-per-answer cost makes p50 latency
  unworkable (30 s+ per alert).
- **For Tier 2 (24 GB), Qwen3-14B with thinking on is workable
  for non-realtime triage** (queued workflows, end-of-shift
  reviews) but not for incident-as-it-happens.
- **Tier 3 unlocks Qwen3-32B and DeepSeek-R1-Distill** without
  spillover. These are the right picks if you need a model that
  can defend its reasoning to a human reviewer with an explicit
  chain.

## Decision tree: which model on which hardware

Read top to bottom; first matching row wins.

1. **Want the highest accuracy and can absorb 14-60 s per alert?**
   → `gemma4:latest` in tool-calling mode (auto). 100% composite,
   fits **on Tier 1 hardware (Mac mini 16 GB)**.

2. **Want top-tier accuracy at lower latency, have ≥ 24 GB memory?**
   → `gemma3:27b` in harness-executed mode. 96% composite, ~9 s p50
   on a 4090.

3. **Need sub-5-second latency, accuracy ≥ 90%?**
   → `llama3.1:8b` in harness-executed mode. 90% composite at 3.3 s
   p50 (4090). Pass `--mode harness-executed` explicitly.

4. **Need smallest model in the top tier?**
   → `Foundation-Sec-8B` in harness-executed mode. 88% at 2.1 s
   p50 (4090). Cyber pre-training closes the MITRE gap.

5. **Need native MCP tool_calls (existing OpenAI-compatible agent
   runtime that doesn't support harness-driven plans)?**
   → `gemma4:latest` (100%) or `qwen3:14b` (80%). Both drive native
   tool_calls reliably; gemma4 is the better pick.

6. **Need explicit chain-of-thought visible to a human reviewer, on
   Tier 3 hardware?**
   → Try `qwen3:32b` or `deepseek-r1-distill-32b` (not benchmarked
   here; out of 4090 budget).

7. **Avoid in any production workload**: `Lily-Cybersecurity-7B`
   (verdict logic inverted), `Llama-3.1:8b in tool-calling mode`
   (format failure — use harness-executed instead).

## Caveats

- **Sample size.** Classification bench is 32 cases; playbook bench
  is 10. These are small. Treat the rankings as "what won on these
  cases" rather than "what is best in general". Replicate with a
  larger case set before betting production accuracy on this.
- **Single quantization.** All models tested at Q4_K_M. A higher
  quant (Q6 / Q8 / fp16) could narrow some gaps, especially on
  format-sensitive tasks like Llama-3.1's tool-calling failure.
- **Single hardware.** The 4090 latency numbers anchor the
  ranking; tier-1 and tier-2 estimates are extrapolated from
  memory-bandwidth ratios, not measured. Validate before
  committing.
- **Mock MCP fixtures are deterministic.** Real MCP-tool latency,
  rate limits, and partial-failure modes don't show up in this
  measurement. Production deployments should add a wrapper layer
  with timeouts and retries before exposing real tools.
- **Qwen3 with thinking on by default.** The classification bench
  result is a lower bound; with `/no_think`, MITRE recall would
  improve. The playbook bench tool-calling result already shows
  what the model can do when the protocol fits.

## Appendix A: Per-case results — playbook bench, harness-executed

V = verdict, S = severity, M = MITRE, T = tool selection. Each cell
is the four sub-scores for that case.

| Case | gemma3:27b | llama3.1 | Foundation-Sec | qwen3:14b | ZySec | Lily |
|---|---|---|---|---|---|---|
| PB-1 (benign — normal login) | PASS PASS PASS PASS | PASS PASS PASS PASS | PASS PASS PASS PASS | PASS PASS PASS PASS | PASS PASS PASS PASS | FAIL PASS PASS FAIL |
| PB-2 (foreign-IP RDP burst) | PASS PASS PASS PASS | PASS PASS PASS PASS | PASS PASS PASS PASS | PASS PASS FAIL PASS | PASS PASS FAIL PASS | FAIL PASS FAIL FAIL |
| PB-3 (wp-login bruteforce) | PASS PASS PASS PASS | PASS PASS FAIL PASS | PASS PASS PASS PASS | PASS PASS PASS PASS | PASS PASS FAIL PASS | FAIL PASS FAIL FAIL |
| PB-4 (Word→PowerShell stager) | PASS PASS PASS PASS | PASS PASS PASS PASS | PASS PASS PASS FAIL | PASS PASS FAIL FAIL | PASS PASS FAIL PASS | FAIL FAIL FAIL FAIL |
| PB-5 (DNS exfil) | PASS PASS PASS PASS | PASS PASS FAIL PASS | PASS PASS FAIL PASS | PASS PASS FAIL PASS | PASS PASS FAIL FAIL | FAIL FAIL FAIL FAIL |
| PB-6 (SSH bruteforce → ubuntu) | PASS PASS FAIL PASS | PASS PASS PASS PASS | PASS PASS FAIL PASS | PASS PASS PASS PASS | PASS PASS FAIL PASS | FAIL FAIL FAIL FAIL |
| PB-7 (benign — pubkey login) | PASS PASS PASS PASS | PASS PASS PASS PASS | PASS PASS PASS PASS | PASS PASS PASS PASS | PASS PASS PASS PASS | FAIL PASS PASS FAIL |
| PB-8 (SQLi probes) | PASS PASS PASS PASS | PASS PASS FAIL PASS | PASS PASS PASS PASS | PASS PASS FAIL PASS | PASS PASS FAIL PASS | FAIL PASS FAIL FAIL |
| PB-9 (sudo escalation 03:17) | PASS PASS PASS PASS | PASS PASS FAIL PASS | PASS PASS FAIL FAIL | FAIL FAIL FAIL PASS | PASS PASS FAIL FAIL | FORMAT-FAIL |
| PB-10 (kiosk → DC bruteforce) | PASS FAIL PASS PASS | PASS PASS PASS PASS | PASS PASS PASS PASS | FAIL FAIL FAIL PASS | FAIL FAIL FAIL FAIL | FAIL PASS FAIL FAIL |

## Appendix B: Per-case results — classification bench (MITRE section, 10 cases)

The MITRE section is the most discriminating section of the
classification bench. Per-case PASS/FAIL by model:

| Case | Behavior | Foundation-Sec | Llama-3.1 | ZySec | Lily | Qwen3-14B | Gemma3-27B |
|---|---|---|---|---|---|---|---|
| ATT-1 | Macro-doc spearphish | PASS | FAIL | FAIL | FAIL | FAIL | PASS |
| ATT-2 | Mimikatz LSASS dump | PASS | PASS | PASS | PASS | FAIL | PASS |
| ATT-3 | Scheduled task persistence | FAIL | FAIL | FAIL | FAIL | PASS | FAIL |
| ATT-4 | AD enumeration | PASS | PASS | FAIL | PASS | FAIL | PASS |
| ATT-5 | HKCU\Run persistence | PASS | FAIL | FAIL | PASS | FAIL | PASS |
| ATT-6 | DNS TXT C2 | PASS | FAIL | FAIL | FAIL | FAIL | PASS |
| ATT-7 | PsExec lateral | FAIL | FAIL | FAIL | PASS | FAIL | FAIL |
| ATT-8 | vssadmin shadow delete | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL |
| ATT-9 | EncodedCommand obfuscation | PASS | FAIL | PASS | FAIL | FAIL | PASS |
| ATT-10 | Password-protected RAR | PASS | FAIL | FAIL | FAIL | FAIL | PASS |
| **Total** | | **7/10** | **2/10** | **2/10** | **4/10** | **1/10** | **7/10** |

## Files in the repository

- `benchmark.py`, `playbook_bench.py` — both benchmark harnesses
- `incident_playbook.md` — SKILL.md-style triage playbook
- `playbook_cases.py` — 10 playbook scenarios
- `mcp_servers/` — 5 mock MCP servers (openvas, siem, threat_intel, cmdb, edr)
- `results-*.md` — per-model classification-bench transcripts
- `results-playbook-*-harness.md` — per-model playbook-bench transcripts
- `comparison.md`, `playbook-comparison.md` — full per-bench breakdowns
- `conclusion.md` — narrative conclusion across both benches

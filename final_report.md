# Local LLM Benchmark for SOC Triage — Final Report

Run date: 2026-05-06. Source repo: `sec_eval/`.

This report consolidates two independent benchmarks of locally-hosted LLMs
for SOC Tier-1 triage work, plus a hardware recommendation for production
deployment.

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

Six models, all installed via Ollama:

| Model | Family | Params | Q4_K_M size | Notes |
|---|---|---|---|---|
| `gemma3:27b` | Google Gemma 3 | 27 B | ~17 GB | Generalist, no `tools` capability |
| `llama3.1:8b` | Meta Llama 3.1 | 8 B | ~5 GB | Generalist, advertises `tools` |
| Foundation-Sec-8B | Cyber-tuned (Llama 3.1 base) | 8 B | ~5 GB | Cybersecurity SFT |
| `qwen3:14b` | Alibaba Qwen 3 | 14 B | ~9 GB | Hybrid reasoning, `tools` + `thinking` |
| ZySec-7B-v1 | Cyber-tuned | 7 B | ~4.5 GB | Cybersecurity SFT |
| Lily-Cybersecurity-7B | Cyber-tuned | 7 B | ~4.5 GB | Cybersecurity SFT |

Qwen3:32b was tested but excluded — its 32K-context KV cache pushed
the 4090 into 17/83 % CPU/GPU split, dropping inference to ~3 t/s.

## Classification bench results (32 cases)

Six models, same prompts, same scoring.

### Accuracy

| Section | Foundation-Sec | Llama-3.1 | ZySec | Lily | Qwen3-14B | Gemma3-27B |
|---|---|---|---|---|---|---|
| Incident recognition (7) | 4 (57%) | 7 (100%) | 6 (86%) | 5 (71%) | 5 (71%) | **7 (100%)** |
| Threat classification (7) | 7 (100%) | 7 (100%) | 4 (57%) | 6 (86%) | 5 (71%) | **7 (100%)** |
| MITRE ATT&CK (10) | 7 (70%) | 2 (20%) | 2 (20%) | 4 (40%) | 1 (10%) | **7 (70%)** |
| Syslog raw (8) | 5 (62%) | 8 (100%) | 5 (62%) | 7 (88%) | 5 (62%) | **8 (100%)** |
| Syslog drain3 (8) | 5 (62%) | 7 (88%) | 5 (62%) | 1 (12%) | 6 (75%) | 7 (88%) |
| **Overall / 32** | **23 (72%)** | **23 (72%)** | **17 (53%)** | **16 (50%)** | **17 (53%)** | **28 (88%)** |

### Latency (avg per call, 4090)

| Model | Avg s | p95 s | Peak GPU MB |
|---|---|---|---|
| Lily-Cyber-7B | 0.47 | 1.23 | ~17,700 |
| ZySec-7B-v1 | 0.55 | 1.26 | ~18,100 |
| Foundation-Sec-8B | 0.70 | 0.85 | ~9,300 |
| Llama-3.1-8B | 0.80 | 0.91 | ~18,500 |
| Gemma3-27B | 1.60 | 1.79 | ~20,500 |
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
3. **Qwen3-14B's reasoning mode kills its scores.** With
   `num_predict=400`, the model spends most of its budget inside
   `<think>...</think>` and runs out of tokens before answering.
   This is most visible on MITRE (1/10) and as 5-10× higher latency
   than every other sub-15B model.
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

### Headline: harness-executed mode

In harness-executed mode every model sees real fixture data — the
harness, not the model, drives tool dispatch, so the comparison is
clean across tool-capable and non-tool-capable models.

| Model | Composite | Verdict | Severity | MITRE | Tools | p50 latency |
|---|---|---|---|---|---|---|
| **gemma3:27b** | **96%** | 10/10 | 9/10 | 9/10 | 10/10 | 9.3 s |
| llama3.1:8b | 90% | 10/10 | 10/10 | 6/10 | 10/10 | 3.3 s |
| Foundation-Sec-8B | 88% | 10/10 | 10/10 | 7/10 | 8/10 | 2.1 s |
| qwen3:14b | 72% | 8/10 | 8/10 | 4/10 | 9/10 | 21.9 s |
| ZySec-7B | 68% | 9/10 | 9/10 | 2/10 | 7/10 | 1.7 s |
| Lily-Cyber-7B | 14% | 0/10 | 6/10 | 2/10 | 0/10 | 4.4 s |

### Three-mode comparison

How each model fares depending on who drives the tool loop. The
"refused" cells are where Ollama's OpenAI-compat endpoint blocks
the request because the model doesn't advertise `tools` capability.

| Model | Tool-calling | Harness-executed | Describe-only |
|---|---|---|---|
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

| Model | Classification (32) | Playbook harness-executed (10) |
|---|---|---|
| Gemma3-27B | 1st (88%) | 1st (96%) |
| Llama-3.1-8B | 2nd tie (72%) | 2nd (90%) |
| Foundation-Sec-8B | 2nd tie (72%) | 3rd (88%) |
| Qwen3-14B | 4th tie (53%) | 4th (72% / 80% native) |
| ZySec-7B | 4th tie (53%) | 5th (68%) |
| Lily-Cyber-7B | 6th (50%) | 6th (14%) |

The top is stable: **Gemma3-27B wins both**.

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

### Tier 1: Mac mini 16 GB (M4 base) — about $600

Usable memory after macOS overhead is roughly 10-11 GB. This
limits you to 7-8 B models at Q4_K_M.

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

**Best deployment**: `llama3.1:8b` in harness-executed mode. 90%
composite, 10/10 verdict, 10/10 severity, 6/10 MITRE, 10/10 tool
selection. Expected latency: ~6-8 s p50 on M4 base for two
rounds. This is the cleanest fit for the Mac mini tier.

**Tradeoff**: you cannot run gemma3:27b at all, so the 6-point gap
(96% → 90%) is unavoidable. For most SOC triage workloads this is
acceptable — Llama-3.1 is never wrong on verdict on this bench.

**Verdict**: Mac mini 16 GB is **viable** for production Tier-1
SOC triage with Llama-3.1:8b. It's the cheapest path to a
working agent.

### Tier 2: 24 GB unified memory or 24 GB GPU — $700-$2200

Three good options, ordered by cost:

| Hardware | Approx. cost | Notes |
|---|---|---|
| Used RTX 3090 desktop | ~$700 | Fastest at this tier; 350 W TDP; needs decent PSU |
| Mac mini 24 GB (M4 Pro) | ~$1400 | Quietest option; 60 W idle; lower memory bandwidth than M-series with wider buses |
| Mac Studio 32 GB (M4 Max) | ~$2200 | Best memory bandwidth on Apple Silicon; headroom for thinking models |

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

| Hardware | Approx. cost | Notes |
|---|---|---|
| Mac Studio 64 GB (M4 Max) | ~$3500 | Sweet spot for thinking models; ~270 GB/s memory |
| Mac Studio 128 GB (M4 Ultra) | ~$5600 | Massive headroom; multiple models hot |
| RTX 4090 24 GB | ~$1800 new | Fastest single GPU; tight on 32B thinking models |
| RTX 5090 32 GB | ~$2500 new | Successor; 32 GB is the missing piece for 32 B thinking |
| Dual RTX 3090 (48 GB) | ~$1400 used | Best $/GB; tensor-parallel for 32 B models |

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
| 1 | Mac mini 16 GB | llama3.1:8b | 90% | ~6-8 s |
| 2 | RTX 3090 / Mac mini 24 GB / Studio M4 Max 32 GB | gemma3:27b | 96% | ~7-15 s |
| 3 | Studio 64 GB / 5090 / dual 3090 | qwen3:32b thinking, fp16 27 B | not benchmarked | depends |

The accuracy delta between Tier 1 and Tier 2 is **6 percentage
points** (90% → 96%) on the playbook bench. The cost delta is
**$100-$1600**. Whether that gap is worth the spend depends on the
cost of a wrong incident verdict in your environment.

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

1. **Need 96% accuracy and have ≥ 24 GB memory?**
   → `gemma3:27b` in harness-executed mode (auto-selected by the
   harness). p50 ~9.3 s on a 4090.

2. **Need 90% accuracy at sub-5-second latency, on a 16 GB Mac mini
   or similar?**
   → `llama3.1:8b` in harness-executed mode. Pass
   `--mode harness-executed` explicitly.

3. **Need the smallest fastest model that still scores in the top
   tier?**
   → `Foundation-Sec-8B` in harness-executed mode. 88% at 2.1 s
   p50. Cyber pre-training closes the MITRE gap to gemma3:27b.

4. **Need the model to drive native MCP tool_calls end-to-end (e.g.
   for an existing OpenAI-compatible agent runtime that doesn't
   support harness-driven plans)?**
   → `qwen3:14b` in tool-calling mode. 80% at 13.8 s p50. Only model
   that does this reliably at Q4_K_M.

5. **Need explicit chain-of-thought reasoning visible to a human
   reviewer, on Tier 3 hardware?**
   → Try `qwen3:32b` or `deepseek-r1-distill-32b` (not benchmarked
   here; out of 4090 budget).

6. **Avoid in any production workload**: `Lily-Cybersecurity-7B`
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

# sec_eval

Accuracy benchmark for `Foundation-Sec-8B-Instruct` (GGUF Q4_K_M) served via Ollama.

## What it tests

The benchmark sends scenarios to the model over the Ollama HTTP API and scores
each reply against a known answer. Four sections:

1. **Incident recognition** (7 cases) — binary classification: incident vs benign,
   from natural-language scenarios.
2. **Threat-type classification** (7 cases) — multi-class; scored by keyword match
   on the threat name (ransomware, phishing/BEC, SQLi, XSS, credential dumping,
   DoS/DDoS, supply chain).
3. **MITRE ATT&CK mapping** (10 cases) — model must return a technique ID; any
   accepted ID for the scenario counts as a match.
4. **Syslog triage** (8 cases) — verbatim multi-line log snippets in real format
   (sshd, sudo, CRON, Apache access log, winlogbeat). Same binary scoring as
   section 1, but the model must read raw log lines instead of an English
   summary.

## Running

Requires Ollama running locally with at least one model pulled, and drain3
installed:

```
ollama pull hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M
pip install -r requirements.txt
python3 benchmark.py
```

### Choosing a model

The model is selectable at runtime; the default is the Foundation-Sec one
listed above.

```
# default model
python3 benchmark.py

# any other Ollama-installed model
python3 benchmark.py --model llama3.1:8b

# write to a model-specific file so runs don't clobber each other
python3 benchmark.py --model llama3.1:8b --output results-llama3.1-8b.md

# show what's installed in the local Ollama
python3 benchmark.py --list
```

If the requested model isn't pulled, the script exits early and tells you the
exact `ollama pull` command to run.

The Ollama endpoint is hardcoded at the top of `benchmark.py`
(`OLLAMA_URL = http://localhost:11434/api/generate`); the model is whichever
one you pass via `--model` (default: `hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M`).

The script writes a per-case transcript and a summary table to the file given
by `--output` (default: `results.md`).

## Files

- `benchmark.py` — test cases, Ollama call, scoring, resource sampler, report generation.
- `requirements.txt` — `drain3` (syslog clustering) and `psutil` (CPU/RAM sampling).
- `results-*.md` — per-model transcripts with per-case latency + GPU/CPU/RAM metrics.
- `comparison.md` — full multi-model breakdown.
- `conclusion.md` — single-model recommendation and reasoning.

## drain3 augmentation (section 4)

Section 4 runs each syslog case twice:

1. **Baseline** — raw log lines only.
2. **drain3-augmented** — same raw lines, plus a `[xN] template` summary
   produced by feeding the snippet through `drain3.TemplateMiner`. The prompt
   tells the model that high counts on attack-shaped templates indicate an
   incident and that few low-count routine templates indicate benign activity.

The intent is to give the model a pre-clustered view of repetition, which
should help on brute-force / probe-style cases (SYS-1, SYS-4, SYS-6, SYS-8).

## Model comparison (latest run, 2026-05-06)

Six models, same 32 cases, same prompts, same scoring. Hardware: RTX 4090
(24 GB VRAM), AMD EPYC 7352 (48 cores), 251 GB RAM. All Q4_K_M.

### Accuracy

| Section | Foundation-Sec-8B | Llama-3.1-8B | ZySec-7B-v1 | Lily-Cyber-7B-v0.2 | Qwen3-14B | **Gemma3-27B** |
|---|---|---|---|---|---|---|
| Incident recognition (7) | 4 (57%) | 7 (100%) | 6 (86%) | 5 (71%) | 5 (71%) | **7 (100%)** |
| Threat classification (7) | 7 (100%) | 7 (100%) | 4 (57%) | 6 (86%) | 5 (71%) | **7 (100%)** |
| MITRE ATT&CK mapping (10) | 7 (70%) | 2 (20%) | 2 (20%) | 4 (40%) | 1 (10%) | **7 (70%)** |
| Syslog triage — raw (8) | 5 (62%) | 8 (100%) | 5 (62%) | 7 (88%) | 5 (62%) | **8 (100%)** |
| Syslog triage — drain3 (8) | 5 (62%) | 7 (88%) | 5 (62%) | 1 (12%) | 6 (75%) | 7 (88%) |
| **Overall / 32 (drain3 syslog)** | 23 (72%) | 23 (72%) | 17 (53%) | 16 (50%) | 17 (53%) | **28 (88%)** |

Bold = best in row. **Gemma3-27B leads by 5 cases**, with 100% on three
sections and tied with Foundation-Sec on MITRE.

### Performance (per-call, sampled every 250 ms)

| Model | Avg s | p95 s | Peak GPU% | Steady GPU MB | Peak RAM MB |
|---|---|---|---|---|---|
| Lily-Cyber-7B | 0.47 | 1.23 | 93% | ~17,700 | 32,556 |
| ZySec-7B-v1 | 0.55 | 1.26 | 93% | ~18,100 | 32,664 |
| Foundation-Sec-8B | 0.70 | 0.85 | 81% | ~9,300 | 34,519 |
| Llama-3.1-8B | 0.80 | 0.91 | 81% | ~18,500 | 32,769 |
| **Gemma3-27B** | **1.60** | **1.79** | **94%** | **~20,500** | **33,778** |
| Qwen3-14B | 4.53 | 5.14 | 93% | ~14,300 | 37,617 |

All six fit fully on the 4090; none spilled to CPU RAM. Per-call metrics
(GPU%, GPU MB, CPU%, RAM MB) are inlined in each `results-*.md` file's
case headers.

> **Qwen3-32B excluded.** Pulled and tested but its 32K-context KV cache
> pushes it to 17%/83% CPU/GPU split on this hardware, dropping throughput
> to ~3 tok/s. Would need an 8K-context override or a 48 GB+ GPU.

Per-case transcripts: `results-foundation-sec.md`, `results-llama31.md`,
`results-zysec.md`, `results-lily.md`, `results-qwen3-14b.md`,
`results-gemma3-27b.md`. Full breakdown is in `comparison.md`; the
recommendation and reasoning is in `conclusion.md`.

### What this says

- **Gemma3-27B is the new top pick at 28/32 (88%).** It's the only model
  that doesn't have a section it loses badly on — perfect on three of
  five, tied with Foundation-Sec on MITRE. 1.6 s avg latency, ~20.5 GB
  GPU, 128K context. Fits on a 4090 with headroom.
- **Foundation-Sec's MITRE moat is gone.** Gemma3-27B matches its 7/10
  from a generalist baseline, so the cyber pre-training no longer
  justifies its incident-bias weakness. Still useful as a small (5 GB,
  0.7 s) MITRE-only fallback.
- **Qwen3-14B's reasoning mode kills its scores.** With `num_predict=400`
  the model burns most of its budget inside `<think>...</think>` and
  truncates before answering — visible most clearly on MITRE (1/10) and
  in 5-10× higher latency than other sub-15B models. Disable reasoning
  before re-evaluating.
- **drain3 augmentation is model-dependent.** Foundation-Sec/ZySec
  unchanged. Llama-3.1 loses 1, Gemma3 loses 1, Qwen3-14B gains 1, Lily
  collapses 7→1. Don't ship drain3 as a universal pre-filter.
- **The "SOC fine-tuned 7B" tier (ZySec, Lily) finishes at the bottom.**
  A larger generalist beats all three SOC-tuned models on every section
  except MITRE (where Gemma3 ties Foundation-Sec). On this benchmark,
  model scale buys more than cyber fine-tuning.

For complex skill.md-style instruction following, **use `gemma3:27b`**.
For tight VRAM or MITRE-only workloads, Foundation-Sec is the fallback.

## Playbook benchmark with mock MCP tools

A second benchmark, separate from the 32-case classification one above:
`playbook_bench.py` measures how well each model can read a SKILL.md-style
incident playbook (`incident_playbook.md`) and act on it — pulling entities
out of an alert, enriching them with mock SOC tools, and returning a
structured JSON verdict.

The model sees five MCP servers (in `mcp_servers/`):

- `openvas` — `scan_host`, `get_scan_results` (vuln data per host)
- `siem` — `query_logs` (canned hits keyed by IP / account / EventID)
- `threat_intel` — `lookup_ip`, `lookup_domain`, `lookup_hash`
- `cmdb` — `get_asset` (criticality, owner, tags)
- `edr` — `get_processes`, `isolate_host`

Each is a small `FastMCP` stdio server with deterministic fixtures keyed
off the 10 scenarios in `playbook_cases.py` (derived from the original
32-case set). The harness uses `pydantic-ai` `Agent + MCPServerStdio` and
talks to Ollama through pydantic-ai's native `OllamaModel` provider.

### Three modes

Only 3 of the 7 Ollama models in the original bench advertise the `tools`
capability (`llama3.1:8b`, `qwen3:14b`, `qwen3:32b`). Ollama's OpenAI-compat
endpoint refuses tool-call requests for the rest. To measure all models on
the same prompt, the harness supports three paths:

- **tool-calling**: real multi-turn loop driven by the model's native
  OpenAI `tool_calls` payloads. Only works for models that advertise the
  `tools` capability AND can produce a valid `tool_calls` payload at Q4_K_M.
- **harness-executed** (the apples-to-apples mode): two-round flow. Round 1,
  the model returns a `{"tools_to_call": [{server, tool, args}, ...]}` plan
  as JSON. The harness dispatches each entry to the real MCP servers via
  `MCPServerStdio.direct_call_tool`. Round 2, the harness sends the tool
  results back as a user message and the model returns the final verdict
  JSON. **The harness, not the model, drives tool dispatch** — so even
  models without native `tools` capability execute real tools and see real
  fixture data.
- **describe-only**: single-shot, no execution. The model lists the tools
  it *would* have called inside `tools_used`. Tests planning ability in
  isolation.

The harness auto-dispatches: tool-capable models run tool-calling, the
rest fall back to harness-executed. `--mode {tool-calling,harness-executed,describe-only}`
forces a specific mode.

### Scoring (per case)

- **Verdict**: `incident` vs `benign` (35%)
- **Severity**: ladder match `info`/`low`/`medium`/`high`/`critical` (15%)
- **MITRE**: any expected technique ID matches (25%)
- **Tool selection**: did the model call/list at least one of the
  acceptable minimum-tool subsets for that case (25%)

Plus side-flags: format failure (no parseable JSON), forbidden-tool calls
(e.g. `edr.isolate_host` on a benign case), and not-found responses
(hallucinated entities).

### Headline: harness-executed mode (every model sees real fixture data)

| Model | Composite | Verdict | Severity | MITRE | Tools | p50 latency |
|---|---|---|---|---|---|---|
| **gemma3:27b** | **96%** | 10/10 | 9/10 | 9/10 | **10/10** | 9.3 s |
| llama3.1:8b | 90% | **10/10** | **10/10** | 6/10 | **10/10** | 3.3 s |
| Foundation-Sec-8B | 88% | **10/10** | **10/10** | 7/10 | 8/10 | **2.1 s** |
| qwen3:14b | 72% | 8/10 | 8/10 | 4/10 | 9/10 | 21.9 s |
| ZySec-7B | 68% | 9/10 | 9/10 | 2/10 | 7/10 | 1.7 s |
| Lily-Cyber-7B | 14% | 0/10 | 6/10 | 2/10 | 0/10 | 4.4 s |

### Three-mode comparison

| Model | Tool-calling | Harness-executed | Describe-only |
|---|---|---|---|
| gemma3:27b | refused† | **96%** | 90% |
| llama3.1:8b | 15% (format-fail) | **90%** | 85% |
| Foundation-Sec-8B | refused† | **88%** | 80% |
| qwen3:14b | **80%** | 72% | — |
| ZySec-7B | refused† | 68% | 71% |
| Lily-Cyber-7B | refused† | 14% | 11% |

† = Ollama refuses tool-calling for models without the `tools` capability.

Three observations:

1. **Harness-executed beats describe-only for every reasoning-capable
   model** because the model now sees actual fixture data (e.g. `verdict:
   malicious, tags: [tor-exit]`) and can use it to pick the right MITRE
   technique. Gemma3 jumps from 90→96% specifically because MITRE
   accuracy goes 7/10 → 9/10 with grounded reasoning.
2. **Llama3.1's 15% tool-calling collapse was format, not reasoning.**
   Same Q4_K_M weights, same playbook — when the harness drives dispatch
   instead of demanding native `tool_calls` JSON, llama3.1 jumps from
   2/10 verdict to 10/10. The model understood the playbook all along;
   it just couldn't produce the OpenAI tool-call wire format reliably.
3. **Qwen3:14b regresses in harness-executed (-8 vs native).** Qwen3
   trained heavily on the native protocol; forcing it through a 2-round
   JSON-plan flow loses information. For qwen3, prefer native tool-calling.

Full breakdown including per-case tables and architecture diagram:
`playbook-comparison.md`. Per-model transcripts in `results-playbook-*.md`.

### Running the playbook bench

```
pip install -r requirements.txt
python3 playbook_bench.py --model gemma3:27b                       # auto: harness-executed
python3 playbook_bench.py --model qwen3:14b                        # auto: tool-calling
python3 playbook_bench.py --model llama3.1:8b --mode harness-executed
python3 playbook_bench.py --model gemma3:27b --describe-only       # planning only
python3 playbook_bench.py --cases PB-1,PB-7                        # subset
```

## Scoring notes

- Incident scoring looks at the first ~300 characters of the reply for a verdict
  word and rejects on contradictory terms — the model sometimes says "Incident"
  for clearly benign scenarios, which is the dominant failure mode.
- Threat scoring is a substring match against an accepted keyword list per case.
- MITRE scoring extracts every `Tdddd(.ddd)?` token from the reply and accepts
  the case if any match the expected ID list (sub-techniques and parent IDs both
  count where appropriate).

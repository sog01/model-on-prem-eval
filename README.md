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

## Scoring notes

- Incident scoring looks at the first ~300 characters of the reply for a verdict
  word and rejects on contradictory terms — the model sometimes says "Incident"
  for clearly benign scenarios, which is the dominant failure mode.
- Threat scoring is a substring match against an accepted keyword list per case.
- MITRE scoring extracts every `Tdddd(.ddd)?` token from the reply and accepts
  the case if any match the expected ID list (sub-techniques and parent IDs both
  count where appropriate).

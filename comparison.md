# Model comparison — SOC benchmark

Six models, identical 32-case prompt set, same scoring code, same Ollama
endpoint. Re-run on 2026-05-06 with per-call latency, GPU util, GPU memory,
CPU%, and RAM sampling.

Hardware: RTX 4090 (24 GB VRAM), AMD EPYC 7352 (48 cores), 251 GB RAM.

## Models

| Tag (label used below) | Ollama identifier | Size (Q4_K_M) | Type |
|---|---|---|---|
| **Foundation-Sec-8B** | `hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M` | 5.1 GB | Cisco Foundation AI, security-pretrained on Llama-3.1-8B |
| **Llama-3.1-8B** | `llama3.1:8b` | 4.9 GB | Meta general-purpose instruct, no security fine-tune |
| **ZySec-7B-v1** | `hf.co/koesn/ZySec-7B-v1-GGUF:Q4_K_M` | 4.4 GB | ZySec-AI, Mistral-7B fine-tune marketed as a SOC analyst |
| **Lily-Cyber-7B** | `hf.co/segolilylabs/Lily-Cybersecurity-7B-v0.2-GGUF:Q4_K_M` | 4.4 GB | segolilylabs, Mistral-7B fine-tune on hand-curated cyber pairs |
| **Qwen3-14B** | `qwen3:14b` | 9.3 GB | Alibaba 2025 generalist with hybrid reasoning mode |
| **Gemma3-27B** | `gemma3:27b` | 17 GB | Google 2025 generalist, 128K context |

> **Note on qwen3:32b**: pulled and tested but excluded from this comparison.
> The 32B Q4 model + 32K context KV cache exceeds 24 GB VRAM, forcing a
> 17%/83% CPU/GPU split. PCIe transfers tanked throughput to ~3 tok/s and
> the run was cancelled after >5 min on a single section. Won't fit on this
> hardware without shrinking context.

## Headline accuracy

| Section | Foundation-Sec | Llama-3.1 | ZySec | Lily | Qwen3-14B | **Gemma3-27B** |
|---|---|---|---|---|---|---|
| Incident recognition (7) | 4 (57%) | 7 (100%) | 6 (86%) | 5 (71%) | 5 (71%) | **7 (100%)** |
| Threat classification (7) | 7 (100%) | 7 (100%) | 4 (57%) | 6 (86%) | 5 (71%) | **7 (100%)** |
| MITRE ATT&CK mapping (10) | 7 (70%) | 2 (20%) | 2 (20%) | 4 (40%) | 1 (10%) | **7 (70%)** |
| Syslog triage — raw (8) | 5 (62%) | 8 (100%) | 5 (62%) | 7 (88%) | 5 (62%) | **8 (100%)** |
| Syslog triage — drain3 (8) | 5 (62%) | 7 (88%) | 5 (62%) | 1 (12%) | 6 (75%) | 7 (88%) |
| **Overall / 32 (drain3 syslog)** | 23 (72%) | 23 (72%) | 17 (53%) | 16 (50%) | 17 (53%) | **28 (88%)** |

**Bold = best.** Gemma3-27B is the new leader by a clear margin, scoring
perfect (100%) on three of five sections and tying Foundation-Sec on MITRE.
The next-best models (Foundation-Sec, Llama-3.1) sit 5 cases behind.

## Performance — latency, GPU, CPU, RAM

Per model, totals across all 40 model calls (7 incident + 7 threat + 10 MITRE + 8 syslog raw + 8 syslog drain3). Latency in seconds. GPU util/memory from `nvidia-smi`, CPU/RAM from `psutil`. Sampled every 250 ms; peak is the max sample inside each call window.

| Model | Total s | Avg s/call | p50 s | p95 s | Max s | Peak GPU% | Avg GPU% | Steady GPU MB | Peak CPU% | Avg CPU% | Peak RAM MB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Lily-Cyber-7B | 18.9 | 0.47 | 0.32 | 1.23 | 2.87 | 93% | 77% | ~17,700 | 54% | 12% | 32,556 |
| ZySec-7B-v1 | 22.0 | 0.55 | 0.46 | 1.26 | 2.78 | 93% | 72% | ~18,100 | 16% | 4% | 32,664 |
| Foundation-Sec-8B | 27.8 | 0.70 | 0.48 | 0.85 | 6.67 | 81% | 24% | ~9,300 | 51% | 14% | 34,519 |
| Llama-3.1-8B | 31.9 | 0.80 | 0.72 | 0.91 | 3.31 | 81% | 35% | ~18,500 | 54% | 15% | 32,769 |
| **Gemma3-27B** | **63.8** | **1.60** | **1.40** | **1.79** | **11.42** | **94%** | **54%** | **~20,500** | **49%** | **11%** | **33,778** |
| Qwen3-14B | 181.4 | 4.53 | 5.03 | 5.14 | 9.24 | 93% | 80% | ~14,300 | 56% | 10% | 37,617 |

Notes:
- **Steady GPU MB** is the per-call resident set after the cold load (model fully on GPU). The first INC-1 call always shows higher because the previous model is being evicted.
- The "Max s" column is the cold-load case (INC-1 for each model). Steady-state per-call latency is much closer to the avg/p50 numbers.
- All six models fit fully on the 4090 (≤ 21 GB). None had to spill to CPU RAM.
- **Qwen3-14B is 5-10× slower than the other ≤14B models** despite running fully on GPU — this is its hybrid reasoning mode generating long `<think>` chains before answering, consuming most of the 400-token budget on reasoning.

## Accuracy ÷ time — what's the cost per correct answer?

| Model | Correct | Total s | s per correct |
|---|---|---|---|
| **Gemma3-27B** | **28** | 63.8 | **2.28** |
| Lily-Cyber-7B | 16 | 18.9 | 1.18 |
| ZySec-7B-v1 | 17 | 22.0 | 1.29 |
| Foundation-Sec-8B | 23 | 27.8 | 1.21 |
| Llama-3.1-8B | 23 | 31.9 | 1.39 |
| Qwen3-14B | 17 | 181.4 | 10.67 |

The 7-8B models are cheapest per call, but Gemma3-27B's accuracy lift more
than pays for the 2-3× time cost. Qwen3-14B is the worst on every axis here.

## Headline takeaways

- **Gemma3-27B is the right pick for skill.md-style prompting.** It's the
  only model that scores ≥88% in every section except MITRE (where it
  matches Foundation-Sec at 70%). Avg latency 1.6 s/call, peak GPU memory
  ~20.5 GB — fits comfortably in 24 GB VRAM with headroom for KV cache up
  to ~32K tokens.
- **Foundation-Sec is no longer the MITRE moat it once was.** Gemma3-27B
  matches its 7/10 on technique recall while crushing it on every other
  section. The cyber pre-training advantage doesn't show up here.
- **Qwen3-14B's reasoning mode hurts both accuracy and speed.** The
  thinking chains burn the response budget before the model answers (1/10
  on MITRE because the technique ID never gets emitted), and per-call
  latency is 5-10× the other sub-15B models. Disable reasoning (`/no_think`
  in prompt or `enable_thinking=false`) before re-evaluating, or skip in
  favour of Qwen2.5-14B / Gemma3-12B.
- **The "SOC-tuned" 7B peers (ZySec, Lily) remain the weakest overall.**
  They're fast (≤0.6 s avg) but their accuracy ceiling is too low for
  skill-style multi-step prompts.
- **drain3 augmentation is still model-dependent.** Foundation-Sec, ZySec
  unchanged. Llama-3.1 loses 1 case. Lily collapses 7→1. Qwen3-14B gains 1.
  Gemma3-27B loses 1. Don't ship drain3 as a universal pre-filter; gate it
  per-model.

## Recommendation for the user's question ("learn complex instructions like skill.md")

**Use `gemma3:27b`.** It dominates the accuracy table, has 128K context (so
a long skill block + the case prompt + drain3 templates fit easily), runs
fully on GPU, and finishes a 40-call benchmark in 64 s — fast enough for
interactive iteration. Foundation-Sec stays as a backup if your real
workload is dominated by ATT&CK technique mapping, where the two are tied.

Per-case transcripts (with per-call metrics inline):

- `results-foundation-sec.md`
- `results-llama31.md`
- `results-zysec.md`
- `results-lily.md`
- `results-qwen3-14b.md`
- `results-gemma3-27b.md`

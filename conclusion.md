# Conclusion — best model on this benchmark

**Best overall: Gemma3-27B (Google).**

Wins outright at 28 / 32 (88%) — five cases ahead of the next-best, with
clean 100% on three of five sections (incident recognition, threat
classification, raw syslog) and tied with Foundation-Sec on MITRE (7/10).
No ambiguity in the ranking this time.

## How the six models finish

| Rank | Model | Overall | Avg latency | Decisive strength | Decisive weakness |
|---|---|---|---|---|---|
| 1 | **Gemma3-27B** | 28 / 32 (88%) | 1.60 s | 100% on 3 sections + 7/10 MITRE | drain3 prompt costs 1 case (8→7) |
| 2 (tie) | Foundation-Sec-8B | 23 / 32 (72%) | 0.70 s | MITRE 7/10 — only sub-15B model with this | Incident-bias: 0/3 on benign cases |
| 2 (tie) | Llama-3.1-8B | 23 / 32 (72%) | 0.80 s | Triage 15/15 + raw syslog 8/8 | MITRE 2/10 — domain recall is weak |
| 4 (tie) | Qwen3-14B | 17 / 32 (53%) | 4.53 s | Best drain3-syslog gain (5→6) | Reasoning mode kills MITRE (1/10) and is 5-10× slower |
| 4 (tie) | ZySec-7B-v1 | 17 / 32 (53%) | 0.55 s | Incident triage 6/7 | Threat typing 4/7, MITRE 2/10 |
| 6 | Lily-Cyber-7B | 16 / 32 (50%) | 0.47 s | Threat typing 6/7 | drain3 prompt format breaks it (7/8 → 1/8) |

## Why Gemma3-27B is the new top pick

**It dominates every section that the smaller models split between
themselves.** The previous 4-model run had Foundation-Sec winning MITRE
and Llama-3.1 winning binary triage, with no model good at both. Gemma3
takes the union: it ties Foundation-Sec's 7/10 on MITRE *and* matches
Llama-3.1's perfect scores on incident recognition (7/7), threat
classification (7/7), and raw syslog (8/8). There's no section it loses
by more than 1 case to any other model, and it leads or ties on all five.

The cost is latency: 1.60 s/call vs. 0.70 s for Foundation-Sec, and a
larger 17 GB model footprint. Both are still cheap on a 4090 — total
runtime for 40 calls is 64 seconds — and the accuracy gap (88% vs 72%)
more than pays for the 2× slowdown for any workload that consumes the
output.

## Why Foundation-Sec dropped to second

Foundation-Sec's 7/10 on MITRE is no longer unique. Gemma3-27B matches
it from a generalist baseline, which means the cyber pre-training that
justified Foundation-Sec on the previous run is no longer the moat. Once
something else can recall ATT&CK technique IDs at the same rate,
Foundation-Sec's incident-section weakness (4/7, 0/3 on benign) is no
longer recoverable — Gemma3 doesn't have that bias to begin with.

Foundation-Sec is still useful as a small-footprint fallback (5.1 GB,
0.7 s/call) when GPU is contested or when MITRE technique mapping is the
only thing you need.

## Why Qwen3-14B underperforms

Qwen3's hybrid reasoning mode is on by default. With `num_predict=400`,
the model spends most of its budget inside `<think>...</think>` blocks
and runs out of tokens before emitting the actual answer. This is
visible most clearly on MITRE (1/10) — the technique ID is what gets
truncated. Disabling reasoning (`/no_think` in the prompt or
`enable_thinking=false` server-side) is required before re-evaluating.

It's also 5-10× slower per call than every other model that fits on the
GPU, for the same reason — the reasoning chain consumes far more output
tokens.

## Why ZySec, Lily, Foundation-Sec at the SOC-tuned tier remain weak choices

The "SOC fine-tune at the 7-8B class" hypothesis no longer holds up.
ZySec and Lily finish at the bottom of the table; Foundation-Sec only
keeps its second-place tie because of one section. A larger generalist
(Gemma3-27B) outperforms all three SOC-tuned models on every section
except MITRE (where it ties). The premium you pay for "SOC fine-tuning"
is not buying you accuracy on this workload — model scale is.

## Performance and resource notes

All six models fit fully on the 4090 (≤ 21 GB VRAM at Q4_K_M). None
spilled to CPU RAM. Peak system RAM stayed under 38 GB across every run
(plenty of headroom on 251 GB DDR4).

Qwen3-32B was tested but excluded — its 32K-context KV cache pushed it
to 17%/83% CPU/GPU split on this hardware, dropping inference to ~3
tok/s. It would need either an 8K-context override or a 48 GB+ GPU.

Latency ranking (avg s/call): Lily 0.47 < ZySec 0.55 < Foundation-Sec
0.70 < Llama-3.1 0.80 < **Gemma3-27B 1.60** < Qwen3-14B 4.53. For
context, "accuracy per second" puts Gemma3 at 2.28 s/correct vs.
Foundation-Sec at 1.21 s/correct — Foundation-Sec is cheaper per right
answer if accuracy doesn't matter, but for skill-style workloads where
every wrong answer is a real cost, Gemma3 wins.

## Caveats

- **n = 32.** Small custom benchmark, not a production evaluation. Treat
  the verdict as "what won on these 32 cases", not "what is best in
  general". The MITRE section (10 cases) is the most fragile result.
- **All models tested at Q4_K_M.** A higher-quant or fp16 run could
  narrow some gaps.
- **Qwen3-14B was tested with default reasoning on.** Its result is a
  lower bound; with `/no_think`, scores and latency would both improve.
- **drain3 augmentation didn't help most models.** Surface this because
  it's in the repo, but it shouldn't factor into "which model is best".

## One-line recommendation

Use **`gemma3:27b`** as the default for this workload. Keep
**Foundation-Sec-8B** as the small-footprint fallback for MITRE-mapping
workloads or when VRAM is scarce.

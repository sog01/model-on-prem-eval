# Conclusion — best model on these benchmarks

This conclusion now covers two benchmarks in the repo:

1. **Classification bench** (32 cases): incident recognition, threat
   classification, MITRE mapping, raw syslog triage. Single-shot
   prompts, no tool calls. Details below.
2. **Playbook bench** (10 cases): the model is given a SKILL.md-style
   incident-response playbook and 5 mock MCP servers (openvas, siem,
   threat_intel, cmdb, edr) and must triage each alert end-to-end —
   call enrichment tools, interpret results, return a structured JSON
   verdict. See `playbook-comparison.md` and the *Playbook bench*
   section below.

**Both benchmarks pick the same model: Gemma3-27B (Google).** It wins
the classification bench at 28/32 (88%) and the playbook bench at 96%
in harness-executed mode.

---

## Classification bench (32 cases)

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

---

## Playbook bench (10 cases, mock MCP tools)

**Best overall: Gemma3-27B again, at 96% composite.** Same model wins
both benchmarks, but the gap to the small models narrows considerably
once tool execution is wired in — and the second-place picture changes.

### Final ranking (harness-executed mode)

In harness-executed mode the model returns a `tools_to_call` plan as
JSON, the harness dispatches each entry against the real MCP servers,
and the model writes the final verdict from the actual fixture data it
gets back. Every model uses the same path, so the numbers are directly
comparable.

| Rank | Model | Composite | Verdict | Sev | MITRE | Tools | p50 | Decisive strength | Decisive weakness |
|---|---|---|---|---|---|---|---|---|---|
| 1 | **Gemma3-27B** | **96%** | 10/10 | 9/10 | 9/10 | 10/10 | 9.3 s | Highest MITRE (9/10) and tool selection (10/10); zero format failures | Slowest of the strong models |
| 2 | Llama-3.1-8B | 90% | 10/10 | 10/10 | 6/10 | 10/10 | 3.3 s | Perfect verdict + severity at 1/3 the latency of Gemma3 | MITRE 6/10 — same domain-recall weakness as classification bench |
| 3 | Foundation-Sec-8B | 88% | 10/10 | 10/10 | 7/10 | 8/10 | **2.1 s** | Fastest model at 88% — best perf/quality ratio | Tool-selection 8/10; one missed enrichment plan |
| 4 | Qwen3-14B | 72% | 8/10 | 8/10 | 4/10 | 9/10 | 21.9 s | The *only* model that genuinely drives native OpenAI tool_calls (80% in tool-calling mode) | Loses 8 points when forced through harness JSON-plan flow; thinking-mode latency tax |
| 5 | ZySec-7B-v1 | 68% | 9/10 | 9/10 | 2/10 | 7/10 | 1.7 s | Verdicts and severity strong | MITRE 2/10 — by far the worst of the working models |
| 6 | Lily-Cyber-7B | 14% | 0/10 | 6/10 | 2/10 | 0/10 | 4.4 s | — | Verdict logic is inverted; tool plans never compile |

### Three-mode comparison

How each model fares depending on who drives the tool loop. Same
prompt, same fixtures — only the dispatcher changes.

| Model | Tool-calling (model drives) | Harness-executed (harness drives) | Describe-only (no execution) |
|---|---|---|---|
| Gemma3-27B | refused† | **96%** | 90% |
| Llama-3.1-8B | 15% (format-fail) | **90%** | 85% |
| Foundation-Sec-8B | refused† | **88%** | 80% |
| Qwen3-14B | **80%** | 72% | — |
| ZySec-7B | refused† | 68% | 71% |
| Lily-Cyber-7B | refused† | 14% | 11% |

† = Ollama refuses tool-calling for models without the `tools` capability.

### Why the harness-executed result is the one that matters

Harness-executed is the apples-to-apples mode: every model runs the
same flow (plan → dispatch → conclude), every model sees the same
fixture data, and the only thing that varies is how well the model
reads the playbook and reasons over the results.

Three findings from comparing harness-executed against the other
modes:

1. **Real fixture data lifts MITRE accuracy on every reasoning-capable
   model.** Gemma3 7/10 → 9/10. Foundation-Sec 7/10 (same count,
   different cases — now grounded in actual `summary` text, not
   priors). Llama-3.1 5/10 → 6/10. The harness-executed lift is mostly
   "the model can name the right technique because it now sees the
   SIEM's `Password Spraying` summary" — not improved priors.

2. **Llama-3.1's tool-calling collapse was format, not reasoning.**
   In native tool-calling mode at Q4_K_M, llama3.1:8b emits text that
   *looks* like a tool call (`{"name":..,"parameters":..}` in the
   response body) instead of a structured `tool_calls` payload. The
   OpenAI shim doesn't recognize it; no tool ever runs; the model
   answers blind. Score: 15%. Same weights, harness-executed: **90%**.
   This is exactly the format-vs-reasoning split the bench was
   designed to surface — and it dramatically changes how to deploy
   llama3.1 for SOC work.

3. **Qwen3:14b is the inverse case.** It's the only model that
   genuinely drives the OpenAI tool_calls protocol from start to
   finish (80% in tool-calling mode). Forcing it through the
   harness-executed JSON-plan flow regresses it 8 points — the model
   was trained for the native protocol and loses information when the
   protocol is replaced with a multi-round JSON conversation. **For
   qwen3, prefer native tool-calling.** It also pays a 5-10× latency
   tax for `<think>` tokens, same as in the classification bench.

### How the rankings shift between benchmarks

Comparing each model's standing across both benches:

| Model | Classification bench | Playbook bench (harness-executed) |
|---|---|---|
| Gemma3-27B | 1st (88%) | 1st (96%) |
| Llama-3.1-8B | 2nd tie (72%) | 2nd (90%) |
| Foundation-Sec-8B | 2nd tie (72%) | 3rd (88%) |
| Qwen3-14B | 4th tie (53%) | 4th (72% harness, 80% native) |
| ZySec-7B-v1 | 4th tie (53%) | 5th (68%) |
| Lily-Cyber-7B | 6th (50%) | 6th (14%) |

Llama-3.1 and Foundation-Sec swap the silver/bronze placement: in the
classification bench Foundation-Sec wins on MITRE and Llama-3.1 wins
on triage; in the playbook bench Llama-3.1 produces the right verdict
and severity on every single case (10/10/10/10) while Foundation-Sec
loses one tool-selection case. Foundation-Sec also gives up its MITRE
moat — both score 6-7/10. **Llama-3.1's playbook-bench performance is
strictly the better choice** if you can spare the extra parameters and
0.6 s of latency.

Lily-Cyber gets dramatically worse on the playbook bench (50% → 14%)
because its verdict logic is inverted and the multi-step protocol
amplifies that. ZySec drops one place because its MITRE recall
(2/10) is exposed when the playbook explicitly asks for techniques
per case.

### What this means for deployment

For an actual SOC Tier-1 agent that runs a SKILL.md-style playbook
end-to-end with the kind of tools real teams have (vuln scanner, SIEM,
threat intel, CMDB, EDR):

- **Default**: `gemma3:27b` in harness-executed mode. 96% composite,
  perfect tool selection, fits on a 4090 with headroom. The 9.3 s p50
  is the only real cost — fine for any workflow where the human is
  not on the wire.
- **Latency-sensitive**: `llama3.1:8b` in harness-executed mode. 90%
  composite at 3.3 s p50, **never wrong on verdict or severity**.
  Strong choice for "alert came in, route within 5 seconds" workflows.
- **Smallest footprint**: `Foundation-Sec-8B` at 2.1 s p50, 88%
  composite. Cyber pre-training gives it MITRE recall comparable to
  Llama-3.1 with smaller parameters and ~30% lower latency.
- **Native tool-driver**: `qwen3:14b` in tool-calling mode. The only
  model that handles the full multi-turn OpenAI tool_calls loop
  reliably. Use if your runtime expects the model to drive dispatch
  end-to-end. Expect 5-10× the latency of the alternatives.
- **Avoid**: Lily-Cyber (verdict logic broken), and llama3.1 in
  tool-calling mode (use harness-executed instead).

### Caveats specific to the playbook bench

- **n = 10.** The playbook bench is smaller than the classification
  bench (32 cases) and the rankings could move with more data.
- **Fixtures are deterministic.** Real MCP-tool latency,
  rate-limiting, and error modes don't show up in this measurement —
  only reasoning over canned results does.
- **Mode auto-dispatch.** The harness picks tool-calling for models
  with the `tools` capability and harness-executed otherwise. To
  compare a single model across modes, pass `--mode {tool-calling,
  harness-executed,describe-only}` explicitly.

## Final recommendation across both benchmarks

Both benchmarks pick **`gemma3:27b`** as the default. The only twist
is that the playbook bench rehabilitates **`llama3.1:8b`** — once you
let the harness drive tool dispatch instead of demanding native
`tool_calls`, llama3.1 jumps from also-ran (or worse: 15% in
tool-calling mode) to a strong second at 90%, with the lowest latency
of any model that breaks 85%. **Use Gemma3-27B unless latency forces
the trade, in which case Llama-3.1 in harness-executed mode is the
right pick.**

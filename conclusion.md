# Conclusion — best model on this benchmark

**Best overall: Foundation-Sec-8B-Instruct (Cisco Foundation AI).**

Tied for top score (23 / 32) with stock Llama-3.1-8B, but Foundation-Sec
wins on tiebreak because **the section it dominates (MITRE ATT&CK) is the
one a SOC LLM is specifically supposed to be good at, and it is the only
section any model meaningfully won on.**

## How the four models finish

| Rank | Model | Overall | Decisive strength | Decisive weakness |
|---|---|---|---|---|
| 1 (tie) | **Foundation-Sec-8B** | 23 / 32 (72%) | MITRE 7/10 — only model above 4/10 | Incident-bias: 0/3 on benign incident cases |
| 1 (tie) | Llama-3.1-8B | 23 / 32 (72%) | Triage 15/15 + raw syslog 8/8 | MITRE 2/10 — domain recall is weak |
| 3 | Lily-Cyber-7B-v0.2 | 16 / 32 (50%) | Threat typing 6/7 | Drain3 prompt format breaks it (1/8) |
| 4 | ZySec-7B-v1 | 17 / 32 (53%) | Incident triage 6/7 | Threat typing 4/7, MITRE 2/10 |

## Why Foundation-Sec wins the tiebreak over Llama-3.1

Both score 23/32, so the choice comes down to *what kind of failure is
recoverable*.

**Foundation-Sec's failures are correctable in production.** Its three
incident-section misses (INC-1, INC-4, INC-6) and three syslog misses
(SYS-2, SYS-3, SYS-7) are all benign-classified-as-incident. That's an
over-flagging bias, which can be reduced by a stricter prompt, a
two-pass review, or a calibrated threshold on top of the model. False
positives are noisy; they are not architecturally hard to suppress.

**Llama-3.1's failures are the kind a SOC LLM exists to prevent.** It
misses 8 of 10 MITRE cases — the section that actually tests
cyber-specific knowledge recall. That's not a prompt-tuning problem;
it's a *what the model knows* problem. The generalist answer is "bolt on
RAG against an ATT&CK corpus", at which point the LLM's own cyber
training matters less. If you were going to do that anyway, you could
use any 8B model and you wouldn't have run this benchmark.

A 7/10 on MITRE is the only result in this run that says "this model
encodes useful cyber-domain knowledge that a generalist of the same
size does not have." That's exactly the property the model is supposed
to have, and it's what justifies picking Foundation-Sec as the best.

## When you should pick Llama-3.1 instead

If your workload is dominated by binary triage on natural-language
scenarios or raw syslog (the SOC tier-1 alert-review job), Llama-3.1 is
the better pick on this benchmark. It is perfect on incident recognition
(7/7), perfect on threat classification (7/7), and perfect on raw syslog
(8/8). Foundation-Sec is below it on all three. If MITRE technique IDs
aren't part of your output, the SOC fine-tune does not earn its keep
here.

## When you should not pick ZySec or Lily

Both finish below the un-tuned generalist. There's no section they win
that the generalist or Foundation-Sec doesn't already cover at least as
well. Lily additionally degrades catastrophically when the prompt
includes the drain3 template block (7/8 → 1/8), so it's brittle to
prompt-format variation. ZySec was tested at v1 because the v2 GGUF
mirror wouldn't pull cleanly — a v2 retest could change the picture, but
on the available evidence neither is a serious option.

## Caveats

- **n = 32.** This is a small custom benchmark, not a production
  evaluation. Treat the verdict as "what won on these 32 cases", not "what
  is best in general". The relative ordering on MITRE (10 cases) is the
  most fragile result.
- **All models tested at Q4_K_M.** Lower-quant models can be hit harder
  than others. A higher-quant or fp16 run of the bottom two could narrow
  the gap.
- **ZySec was v1, not v2.** The current ZySec release is v2; v2 GGUF
  mirrors didn't pull in this run. The v1 score is a lower bound on what
  the lineage can do.
- **drain3 augmentation didn't help any model.** Worth surfacing because
  it's part of this repo, but it should not factor into "which model is
  best" — only Lily reacts to it strongly (and negatively).

## One-line recommendation

Use **Foundation-Sec-8B** as the default for this workload. Keep
**Llama-3.1-8B** as the fallback for triage-only deployments where
ATT&CK mapping is out of scope.

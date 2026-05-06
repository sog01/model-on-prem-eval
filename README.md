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

- `benchmark.py` — test cases, Ollama call, scoring, report generation.
- `requirements.txt` — `drain3` (used to cluster syslog snippets into templates).
- `results.md` — output of the most recent run (overwritten each run).

## drain3 augmentation (section 4)

Section 4 runs each syslog case twice:

1. **Baseline** — raw log lines only.
2. **drain3-augmented** — same raw lines, plus a `[xN] template` summary
   produced by feeding the snippet through `drain3.TemplateMiner`. The prompt
   tells the model that high counts on attack-shaped templates indicate an
   incident and that few low-count routine templates indicate benign activity.

The intent is to give the model a pre-clustered view of repetition, which
should help on brute-force / probe-style cases (SYS-1, SYS-4, SYS-6, SYS-8).

## Model comparison (latest run)

Four models, same 32 cases, same prompts, same scoring.

| Section | Foundation-Sec-8B | Llama-3.1-8B (generalist) | ZySec-7B-v1 | Lily-Cyber-7B-v0.2 |
|---|---|---|---|---|
| Incident recognition (7) | 4 (57%) | **7 (100%)** | 6 (86%) | 5 (71%) |
| Threat classification (7) | **7 (100%)** | **7 (100%)** | 4 (57%) | 6 (86%) |
| MITRE ATT&CK mapping (10) | **7 (70%)** | 2 (20%) | 2 (20%) | 4 (40%) |
| Syslog triage — raw (8) | 5 (62%) | **8 (100%)** | 5 (62%) | 7 (88%) |
| Syslog triage — drain3 (8) | 5 (62%) | **7 (88%)** | 5 (62%) | 1 (12%) |
| **Overall (with drain3) / 32** | **23 (72%)** | **23 (72%)** | 17 (53%) | 16 (50%) |

Per-case transcripts: `results-foundation-sec.md`, `results-llama31.md`,
`results-zysec.md`, `results-lily.md`. Full breakdown — including per-case
tables for every section, the drain3 effect by model, and failure-mode
notes — is in `comparison.md`. The single-model recommendation and
tiebreaker reasoning is in `conclusion.md`.

### What this says

- **Foundation-Sec earns its keep on MITRE ATT&CK (7/10), and only there.**
  Every other model is ≤4/10. Cisco's curated cyber pre-training shows up
  most clearly on technique-ID recall, which is the task most dependent on
  domain-specific memorisation.
- **Foundation-Sec and stock Llama-3.1-8B tie overall (23/32)** but the
  shape is opposite: the generalist crushes binary triage (15/15 across
  incident + threat, plus 8/8 raw syslog) while bombing MITRE. So the SOC
  fine-tune trades binary-classification headroom for ATT&CK fluency.
- **The "SOC-tuned" peers (ZySec, Lily) are the weakest overall.** Same size
  class as Foundation-Sec, worse on every section except where they happen
  to outdo it on incident classification.
- **drain3 augmentation is model-dependent.** Foundation-Sec and ZySec
  are unchanged by it, Llama-3.1 loses 1 case, and Lily collapses from
  7/8 → 1/8 — the added structured block confuses it badly. drain3 is not
  a universal lift; it's a hint some models can use.

If your real workload is MITRE technique mapping or any task that rewards
specific cyber knowledge recall, Foundation-Sec is the right pick. If your
workload is binary "is this an incident" decisioning on raw logs, an
un-tuned Llama-3.1-8B is matching or beating all three SOC fine-tunes here.

## Scoring notes

- Incident scoring looks at the first ~300 characters of the reply for a verdict
  word and rejects on contradictory terms — the model sometimes says "Incident"
  for clearly benign scenarios, which is the dominant failure mode.
- Threat scoring is a substring match against an accepted keyword list per case.
- MITRE scoring extracts every `Tdddd(.ddd)?` token from the reply and accepts
  the case if any match the expected ID list (sub-techniques and parent IDs both
  count where appropriate).

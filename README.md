# sec_eval

Accuracy benchmark for `Foundation-Sec-8B-Instruct` (GGUF Q4_K_M) served via Ollama.

## What it tests

The benchmark sends scenarios to the model over the Ollama HTTP API and scores
each reply against a known answer. Three sections:

1. **Incident recognition** (7 cases) — binary classification: incident vs benign.
2. **Threat-type classification** (7 cases) — multi-class; scored by keyword match
   on the threat name (ransomware, phishing/BEC, SQLi, XSS, credential dumping,
   DoS/DDoS, supply chain).
3. **MITRE ATT&CK mapping** (10 cases) — model must return a technique ID; any
   accepted ID for the scenario counts as a match.

## Running

Requires Ollama running locally with the model pulled:

```
ollama pull hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M
python3 benchmark.py
```

Endpoint and model are hardcoded at the top of `benchmark.py`:

- `OLLAMA_URL = http://localhost:11434/api/generate`
- `MODEL = hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M`

The script writes a per-case transcript and a summary table to `results.md`.

## Files

- `benchmark.py` — test cases, Ollama call, scoring, report generation.
- `results.md` — output of the most recent run (overwritten each run).

## Latest run

| Section | Accuracy |
|---|---|
| Incident recognition | 4 / 7 (57%) |
| Threat classification | 7 / 7 (100%) |
| MITRE ATT&CK mapping | 7 / 10 (70%) |
| **Overall** | **18 / 24 (75%)** |

See `results.md` for per-case replies.

## Scoring notes

- Incident scoring looks at the first ~300 characters of the reply for a verdict
  word and rejects on contradictory terms — the model sometimes says "Incident"
  for clearly benign scenarios, which is the dominant failure mode.
- Threat scoring is a substring match against an accepted keyword list per case.
- MITRE scoring extracts every `Tdddd(.ddd)?` token from the reply and accepts
  the case if any match the expected ID list (sub-techniques and parent IDs both
  count where appropriate).

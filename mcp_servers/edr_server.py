"""Mock EDR MCP server.

Tools:
    get_processes(host)  -> recent process tree on the host
    isolate_host(host)   -> quarantine action (no-op; returns a ticket ID)
"""

from mcp.server.fastmcp import FastMCP

from fixtures import ASSETS, EDR_PROCESSES, lookup_ci

mcp = FastMCP("edr")


@mcp.tool()
def get_processes(host: str) -> dict:
    """Return the recent process tree on a host as observed by the EDR agent.

    Each entry has pid, name, parent process, and command line. Use this to
    investigate what executed on a host that has been flagged — pay special
    attention to suspicious parent/child pairs (Office apps spawning shells,
    shells spawning curl/powershell with remote URLs).
    """
    procs = lookup_ci(EDR_PROCESSES, host)
    if procs is None:
        return {"host": host, "found": False,
                "notes": "Host has no EDR agent or is offline."}
    return {"host": host, "found": True, "processes": procs}


@mcp.tool()
def isolate_host(host: str, reason: str) -> dict:
    """Quarantine a host from the network (containment action).

    This is a containment action, not an investigative one — only call it
    after you have decided the host is compromised and the asset criticality
    allows automated isolation. Returns a ticket ID. The mock does not
    actually quarantine anything.
    """
    asset = lookup_ci(ASSETS, host)
    crit = asset["criticality"] if asset else "unknown"
    return {
        "host": host,
        "criticality": crit,
        "reason": reason,
        "action": "would_isolate",
        "ticket_id": f"ISOL-{abs(hash(host)) % 10000:04d}",
        "notes": "Mock action — no real network change applied.",
    }


if __name__ == "__main__":
    mcp.run()

"""Mock OpenVAS MCP server.

Tools:
    scan_host(ip)              -> scan_id (queues a scan)
    get_scan_results(scan_id)  -> list of CVEs and severities
"""

from mcp.server.fastmcp import FastMCP

from fixtures import OPENVAS_SCANS, lookup_ci

mcp = FastMCP("openvas")

# Built once at startup so get_scan_results can find scans by ID regardless
# of which key (IP or hostname) was used in scan_host.
SCAN_BY_ID = {entry["scan_id"]: entry["vulns"] for entry in OPENVAS_SCANS.values()}


@mcp.tool()
def scan_host(ip_or_host: str) -> dict:
    """Queue an OpenVAS scan for a host or IP and return the scan_id.

    Call this when you need to know whether a target is vulnerable to the
    behavior you observed — for example, after seeing SQLi probes you would
    scan the targeted host to see if any SQLi-related CVEs are open. Pair
    with get_scan_results(scan_id).
    """
    rec = lookup_ci(OPENVAS_SCANS, ip_or_host)
    if rec is None:
        return {"target": ip_or_host, "queued": False,
                "notes": "No scan profile for this target."}
    return {"target": ip_or_host, "queued": True, "scan_id": rec["scan_id"],
            "notes": "Scan completed (mock returns immediately)."}


@mcp.tool()
def get_scan_results(scan_id: str) -> dict:
    """Return CVEs and severities discovered by a previously-queued scan."""
    vulns = SCAN_BY_ID.get(scan_id)
    if vulns is None:
        return {"scan_id": scan_id, "found": False,
                "notes": "Unknown scan_id."}
    return {"scan_id": scan_id, "found": True, "count": len(vulns), "vulns": vulns}


if __name__ == "__main__":
    mcp.run()

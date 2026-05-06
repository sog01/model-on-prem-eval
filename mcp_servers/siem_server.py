"""Mock SIEM MCP server.

Tools:
    query_logs(query, hours) -> matched count + sample events + summary
"""

from mcp.server.fastmcp import FastMCP

from fixtures import SIEM_QUERIES

mcp = FastMCP("siem")


@mcp.tool()
def query_logs(query: str, hours: int = 24) -> dict:
    """Run a free-text query against the SIEM and return matching events.

    The query is matched substring-wise against ingested fields (account,
    source IP, host, command, path, EventID, etc.). Use this to confirm that
    suspicious activity reported in an alert has additional supporting events
    nearby — for example, whether a single failed login is part of a wider
    burst, or whether a flagged IP shows up against other targets.
    """
    q = query.lower()
    for needle, payload in SIEM_QUERIES:
        if needle in q:
            return {"query": query, "hours": hours, **payload}
    return {"query": query, "hours": hours, "matched": 0, "events": [],
            "summary": "No matching events in the requested window."}


if __name__ == "__main__":
    mcp.run()

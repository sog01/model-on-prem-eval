"""Mock CMDB / asset-database MCP server.

Tools:
    get_asset(host_or_ip) -> hostname, criticality, owner, BU, OS, tags
"""

from mcp.server.fastmcp import FastMCP

from fixtures import ASSETS, lookup_ci

mcp = FastMCP("cmdb")


@mcp.tool()
def get_asset(host_or_ip: str) -> dict:
    """Look up an asset by hostname or IP.

    Returns criticality (low/medium/high/critical), the owning team or user,
    the business unit, OS, and any operational tags. Tags include hints like
    'no-egress-allowed' or 'no-admin-auth-expected' that should change the
    severity of an event involving this asset.
    """
    rec = lookup_ci(ASSETS, host_or_ip)
    if rec is None:
        return {"query": host_or_ip, "found": False,
                "notes": "Not in CMDB — likely external or unmanaged asset."}
    return {"query": host_or_ip, "found": True, **rec}


if __name__ == "__main__":
    mcp.run()

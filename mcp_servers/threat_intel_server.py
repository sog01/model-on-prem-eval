"""Mock threat-intelligence MCP server.

Tools:
    lookup_ip(ip)         -> reputation, geo, tags, score
    lookup_domain(domain) -> reputation, registration, tags
    lookup_hash(sha256)   -> reputation, family, tags
"""

from mcp.server.fastmcp import FastMCP

from fixtures import DOMAIN_INTEL, HASH_INTEL, IP_INTEL

mcp = FastMCP("threat_intel")


@mcp.tool()
def lookup_ip(ip: str) -> dict:
    """Look up an IPv4/IPv6 address against the threat-intel feed.

    Returns the verdict (malicious / suspicious / benign), a 0-100 confidence
    score, geographic origin, observed tags, and a short note. Use this on any
    external source IP that appears in the alert.
    """
    rec = IP_INTEL.get(ip)
    if rec is None:
        return {"ip": ip, "verdict": "unknown", "score": 0,
                "notes": "No record in threat-intel feed."}
    return {"ip": ip, **rec}


@mcp.tool()
def lookup_domain(domain: str) -> dict:
    """Look up a domain against the threat-intel feed.

    Returns the verdict, score, registration date, and tags. Useful for any
    external domain seen in DNS queries, URLs in process command lines, or
    email reply-to addresses.
    """
    rec = DOMAIN_INTEL.get(domain.lower())
    if rec is None:
        return {"domain": domain, "verdict": "unknown", "score": 0,
                "notes": "No record in threat-intel feed."}
    return {"domain": domain, **rec}


@mcp.tool()
def lookup_hash(sha256: str) -> dict:
    """Look up a SHA256 file hash against the threat-intel feed.

    Returns malware family attribution and reputation when known. Use this
    on any hash extracted from EDR or sandbox output.
    """
    rec = HASH_INTEL.get(sha256.lower())
    if rec is None:
        return {"sha256": sha256, "verdict": "unknown", "score": 0,
                "notes": "Hash not in threat-intel feed."}
    return {"sha256": sha256, **rec}


if __name__ == "__main__":
    mcp.run()

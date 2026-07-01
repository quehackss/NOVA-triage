"""Look up known vulnerabilities for a package/version via OSV.dev.

OSV (osv.dev) is chosen because it's free, no API key required, and
aggregates advisories across ecosystems (PyPI, npm, Go, crates.io, etc.)
-- good for a portfolio project since anyone can run this with zero setup.
"""

from __future__ import annotations

import httpx

OSV_API_URL = "https://api.osv.dev/v1/query"


class AdvisoryLookupError(Exception):
    pass


async def check_dependency_advisory(package: str, version: str, ecosystem: str = "PyPI") -> dict:
    """Query OSV.dev for known advisories affecting this exact package/version.

    ecosystem examples: "PyPI", "npm", "Go", "crates.io", "Maven"
    """
    payload = {
        "version": version,
        "package": {"name": package, "ecosystem": ecosystem},
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(OSV_API_URL, json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise AdvisoryLookupError(f"OSV query failed for {package}=={version}: {e}") from e

    data = resp.json()
    vulns = data.get("vulns", [])

    return {
        "package": package,
        "version": version,
        "ecosystem": ecosystem,
        "vulnerable": len(vulns) > 0,
        "advisories": [
            {
                "id": v.get("id"),
                "summary": v.get("summary", "")[:300],
                "severity": _extract_severity(v),
            }
            for v in vulns
        ],
    }


def _extract_severity(vuln: dict) -> str:
    severities = vuln.get("severity", [])
    if severities:
        return severities[0].get("score", "UNKNOWN")
    # some advisories only carry a database_specific severity string
    return vuln.get("database_specific", {}).get("severity", "UNKNOWN")

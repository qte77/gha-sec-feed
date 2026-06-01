"""NVD CVE API v2 fetcher. Emits rows in the C1 contract shape.

Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0

Rate limit without an ``NVD_API_KEY`` env var: 5 requests / 30 seconds.
With a key (injected automatically by :mod:`gha_sec_feed.http`): 50 / 30s.
See tracking issue #4.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

from gha_sec_feed import http

_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_SCHEMA_VERSION = "1.0.0"


def _severity(base_score: float | None) -> str:
    """Map a CVSS v3.1 base score to the C1 ``severity`` enum.

    Thresholds match the FIRST.org CVSS v3.1 qualitative bands.
    """
    if base_score is None or base_score <= 0:
        return "unknown"
    if base_score >= 9.0:
        return "critical"
    if base_score >= 7.0:
        return "high"
    if base_score >= 4.0:
        return "medium"
    return "low"


def _normalize_published(value: str) -> str:
    """Convert NVD's ``YYYY-MM-DDTHH:MM:SS.sss`` to ISO-Z without sub-seconds."""
    return value.split(".", 1)[0].rstrip("Z") + "Z"


def _extract_base_score(cve: dict[str, Any]) -> float | None:
    """Pull a CVSS v3.1 ``baseScore`` if present; otherwise ``None``."""
    metrics = cve.get("metrics", {}).get("cvssMetricV31") or []
    if not metrics:
        return None
    return metrics[0].get("cvssData", {}).get("baseScore")


def _to_row(cve: dict[str, Any]) -> dict[str, Any]:
    """Transform one NVD ``cve`` object into a C1 row."""
    base_score = _extract_base_score(cve)
    return {
        "id": cve["id"],
        "source": "nvd",
        "published": _normalize_published(cve["published"]),
        "severity": _severity(base_score),
        "cvss": base_score,
        "epss": None,
        "kev": False,
        "refs": [ref["url"] for ref in cve.get("references", [])],
        "schema_version": _SCHEMA_VERSION,
    }


def fetch(since: str) -> list[dict[str, Any]]:
    """Fetch CVEs published since ``since`` (ISO-8601 Z-suffixed UTC).

    Args:
        since: Lower-bound publication timestamp, ``YYYY-MM-DDTHH:MM:SSZ``.

    Returns:
        List of C1 rows, one per ``vulnerabilities[].cve`` in the response.
    """
    pub_end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = f"{_ENDPOINT}?{urlencode({'pubStartDate': since, 'pubEndDate': pub_end})}"
    payload = json.loads(http.get(url))
    return [_to_row(item["cve"]) for item in payload.get("vulnerabilities", [])]

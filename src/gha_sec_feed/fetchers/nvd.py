"""NVD CVE API v2 fetcher. Emits :class:`FeedRow` instances per the C1 contract.

Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0

Rate limit without an ``NVD_API_KEY`` env var: 5 requests / 30 seconds.
With a key (injected automatically by :mod:`gha_sec_feed.http`): 50 / 30s.
See tracking issue #4.
"""

from __future__ import annotations

from datetime import datetime, timezone
from json import loads
from typing import Any

from gha_sec_feed import http
from gha_sec_feed.models import FeedRow

_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


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


def _extract_description(cve: dict[str, Any]) -> str:
    """Pull the English description text; empty string if none."""
    for entry in cve.get("descriptions", []):
        if entry.get("lang") == "en":
            return entry.get("value", "")
    return ""


def _extract_cwes(cve: dict[str, Any]) -> list[str]:
    """Pull CWE identifiers from ``weaknesses[].description[]``, deduped.

    NVD ships noise markers like ``NVD-CWE-Other`` and ``NVD-CWE-noinfo``
    for entries without a specific weakness — filter those out by the
    ``CWE-`` prefix. Order of first occurrence is preserved so consumers
    that care about primary-vs-secondary precedence see NVD's ordering.
    """
    cwes: list[str] = []
    seen: set[str] = set()
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-") and value not in seen:
                cwes.append(value)
                seen.add(value)
    return cwes


def _extract_refs(cve: dict[str, Any]) -> list[str]:
    """Return the ``references[].url`` list, falling back to the NVD detail page.

    The C1 contract requires ``len(refs) >= 1``; NVD occasionally ships
    CVEs with an empty ``references`` array (typically very fresh
    entries). Fall back to the canonical detail page URL so every row
    carries at least one authoritative reference, matching the
    catalog-URL fallback pattern in the KEV fetcher.
    """
    urls = [ref["url"] for ref in cve.get("references", [])]
    if not urls:
        return [f"https://nvd.nist.gov/vuln/detail/{cve['id']}"]
    return urls


def _to_row(cve: dict[str, Any]) -> FeedRow:
    """Transform one NVD ``cve`` object into a :class:`FeedRow`."""
    base_score = _extract_base_score(cve)
    return FeedRow(
        id=cve["id"],
        source="nvd",
        published=_normalize_published(cve["published"]),
        severity=_severity(base_score),  # pyright: ignore[reportArgumentType]
        cvss=base_score,
        epss=None,
        kev=False,
        refs=_extract_refs(cve),
        description=_extract_description(cve),
        cwes=_extract_cwes(cve),
    )


def fetch(since: str) -> list[FeedRow]:
    """Fetch CVEs published since ``since`` (ISO-8601 Z-suffixed UTC).

    Args:
        since: Lower-bound publication timestamp, ``YYYY-MM-DDTHH:MM:SSZ``.

    Returns:
        List of :class:`FeedRow`, one per ``vulnerabilities[].cve``.
    """
    # NVD CVE API v2 wants literal colons in the query timestamps and is
    # picky about the URL builder — passing a pre-built URL string with
    # urllib.urlencode (even with `safe=":"`) was observed to 404 while a
    # bare `httpx.get(url, params=...)` against the same endpoint and
    # same wall-clock minute returned 200. We therefore delegate the
    # query-string assembly to httpx via the `params=` path. See #27.
    pub_end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    params = {"pubStartDate": since, "pubEndDate": pub_end}
    payload = loads(http.get(_ENDPOINT, params=params))
    return [_to_row(item["cve"]) for item in payload.get("vulnerabilities", [])]

"""Microsoft Security Response Center (MSRC) CVRF fetcher.

Endpoint: ``https://api.msrc.microsoft.com/cvrf/v3.0`` — monthly CVRF v3.0
documents (one per Patch-Tuesday release). No auth. Two-step: list ``/updates``,
then pull each in-window ``/cvrf/{id}`` document and map its ``Vulnerability[]``.

NOTE: this fetcher is built against the documented CVRF v3.0 JSON shape; it
could not be live-verified because the MSRC API returns HTTP 999 (Azure WAF)
to datacenter IPs — which may also block GitHub Actions runners. The producer
wraps each source in graceful degradation (see ``__main__``), so an MSRC block
contributes nothing rather than failing the run. Mapping is defensive
(``.get`` everywhere) so an unexpected shape skips rather than crashes.
"""

from __future__ import annotations

from json import loads
from typing import Any

from gha_sec_feed import http
from gha_sec_feed.models import FeedRow

_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"
# MSRC severity vocabulary -> C1 severity enum.
_MS_SEVERITY = {
    "critical": "critical",
    "important": "high",
    "moderate": "medium",
    "low": "low",
}


def _severity(vuln: dict[str, Any]) -> str:
    """First MSRC severity found in ``Threats[].Description.Value``, mapped.

    Scans by value rather than the ``Type`` enum int so it is robust to CVRF
    encoding differences (the int meaning could not be verified live).
    """
    for threat in vuln.get("Threats", []):
        value = (threat.get("Description") or {}).get("Value", "").strip().lower()
        if value in _MS_SEVERITY:
            return _MS_SEVERITY[value]
    return "unknown"


def _cvss(vuln: dict[str, Any]) -> float | None:
    """First positive ``CVSSScoreSets[].BaseScore``; else ``None``."""
    for score_set in vuln.get("CVSSScoreSets", []):
        score = score_set.get("BaseScore")
        if isinstance(score, (int, float)) and score > 0:
            return float(score)
    return None


def _normalize_published(value: str) -> str:
    """Coerce a CVRF release timestamp to ISO-Z without sub-seconds/offset."""
    base = value.split(".", 1)[0].split("+", 1)[0].rstrip("Z")
    return (base or "1970-01-01T00:00:00") + "Z"


def _to_row(vuln: dict[str, Any], cve: str, published: str) -> FeedRow:
    """Map one CVRF ``Vulnerability`` (already known to carry a CVE) to a row."""
    return FeedRow(
        id=cve,
        source="msrc",
        published=published,
        severity=_severity(vuln),  # pyright: ignore[reportArgumentType]
        cvss=_cvss(vuln),
        epss=None,
        kev=False,
        refs=[f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"],
        description=(vuln.get("Title") or {}).get("Value", ""),
        cwes=[],
    )


def fetch(since: str) -> list[FeedRow]:
    """Fetch the latest monthly CVRF document and map its CVE vulnerabilities.

    MSRC publishes one CVRF document per month (Patch Tuesday), so the
    producer's narrow weekly ``since`` window would usually match none. The
    fetcher therefore always pulls the **latest** monthly document (by release
    date) and emits one row per CVE-bearing ``Vulnerability`` (``ADV``-style
    non-CVE advisories are skipped). The weekly re-emit is idempotent and
    downstream dedup (NVD wins on ``cve_id``) collapses the overlap. ``since``
    is accepted for signature parity but does not narrow the selection.
    """
    updates = loads(http.get(f"{_BASE}/updates"))
    entries = [e for e in updates.get("value", []) if e.get("ID")]
    if not entries:
        return []
    # Always pull the single latest monthly document; do not narrow by the
    # 7-day `since`. The weekly re-emit is idempotent and downstream dedup
    # (NVD wins on cve_id) collapses the overlap.
    latest = max(entries, key=lambda e: e.get("CurrentReleaseDate", ""))
    doc = loads(http.get(f"{_BASE}/cvrf/{latest['ID']}"))
    published = _normalize_published(
        (doc.get("DocumentTracking") or {}).get(
            "CurrentReleaseDate", latest.get("CurrentReleaseDate", "")
        )
    )
    rows: list[FeedRow] = []
    for vuln in doc.get("Vulnerability", []):
        cve = vuln.get("CVE") or ""
        if cve.startswith("CVE-"):
            rows.append(_to_row(vuln, cve, published))
    return rows

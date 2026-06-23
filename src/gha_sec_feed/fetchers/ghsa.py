"""GitHub Security Advisories (GHSA) fetcher. Emits :class:`FeedRow` per advisory.

Endpoint: ``https://api.github.com/advisories`` — the global database of
GitHub-reviewed advisories. Licensed CC-BY 4.0, so each row carries the
advisory ``html_url`` in ``refs`` as the required per-record attribution. Auth
is optional: a ``GITHUB_TOKEN`` (injected by :mod:`gha_sec_feed.http`) raises
the REST limit from 60/hr to 1000/hr — recommended on shared CI runners.
"""

from __future__ import annotations

from json import loads
from typing import Any
from warnings import warn

from gha_sec_feed import http
from gha_sec_feed.models import FeedRow

_ENDPOINT = "https://api.github.com/advisories"
_PER_PAGE = 100
_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
# GitHub recommends an explicit Accept + API version for REST calls.
_GH_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


def _severity(value: Any) -> str:
    """Map the advisory severity to the C1 enum; unknown if missing/odd."""
    return value if value in _SEVERITIES else "unknown"


def _cvss(advisory: dict[str, Any]) -> float | None:
    """First positive CVSS score among top-level, v3, then v4; else ``None``.

    GitHub increasingly leaves the top-level ``cvss.score`` null and carries
    the real score under ``cvss_severities.cvss_v3`` / ``cvss_v4``. A score of
    ``0`` is GitHub's "no score" placeholder, treated as absent.
    """
    severities = advisory.get("cvss_severities") or {}
    candidates = (
        (advisory.get("cvss") or {}).get("score"),
        (severities.get("cvss_v3") or {}).get("score"),
        (severities.get("cvss_v4") or {}).get("score"),
    )
    for score in candidates:
        if isinstance(score, (int, float)) and score > 0:
            return float(score)
    return None


def _epss(advisory: dict[str, Any]) -> float | None:
    """Pull the EPSS probability (already 0–1) from ``epss.percentage``."""
    percentage = (advisory.get("epss") or {}).get("percentage")
    return float(percentage) if isinstance(percentage, (int, float)) else None


def _cwes(advisory: dict[str, Any]) -> list[str]:
    """Pull ``CWE-``-prefixed ids from ``cwes[].cwe_id``, deduped in order."""
    cwes: list[str] = []
    seen: set[str] = set()
    for entry in advisory.get("cwes", []):
        cwe = entry.get("cwe_id", "")
        if cwe.startswith("CWE-") and cwe not in seen:
            cwes.append(cwe)
            seen.add(cwe)
    return cwes


def _refs(advisory: dict[str, Any]) -> list[str]:
    """Advisory ``html_url`` first (CC-BY attribution), then ``references``.

    Deduped, order-preserving. C1 requires ``len(refs) >= 1``; the advisory
    page URL guarantees that even when ``references`` is empty.
    """
    refs: list[str] = []
    seen: set[str] = set()
    for url in [advisory.get("html_url", ""), *advisory.get("references", [])]:
        if url and url not in seen:
            refs.append(url)
            seen.add(url)
    return refs or [_ENDPOINT]


def _normalize_published(value: str) -> str:
    """Convert an ISO timestamp to ISO-Z without sub-seconds."""
    return value.split(".", 1)[0].rstrip("Z") + "Z"


def _to_row(advisory: dict[str, Any]) -> FeedRow:
    """Transform one ``/advisories`` entry into a :class:`FeedRow`.

    ``id`` is the CVE id when the advisory has one, else the GHSA id (so
    advisories without a CVE still get a stable identifier and dedupe key).
    """
    return FeedRow(
        id=advisory.get("cve_id") or advisory["ghsa_id"],
        source="ghsa",
        published=_normalize_published(advisory["published_at"]),
        severity=_severity(advisory.get("severity")),  # pyright: ignore[reportArgumentType]
        cvss=_cvss(advisory),
        epss=_epss(advisory),
        kev=False,
        refs=_refs(advisory),
        description=advisory.get("summary", ""),
        cwes=_cwes(advisory),
    )


def fetch(since: str) -> list[FeedRow]:
    """Fetch reviewed advisories published since ``since`` (ISO-8601 Z UTC).

    Withdrawn advisories are dropped. A single page of up to 100 advisories is
    fetched (no pagination); if the page is full, a warning is emitted so the
    cap is visible rather than silently truncating.
    """
    params = {
        "type": "reviewed",
        "per_page": str(_PER_PAGE),
        "published": f">={since[:10]}",
    }
    payload = loads(http.get(_ENDPOINT, params=params, headers=_GH_HEADERS))
    if len(payload) >= _PER_PAGE:
        warn(
            f"GHSA fetch hit the {_PER_PAGE}-advisory page cap; advisories "
            "published in this window may be omitted (pagination not implemented).",
            RuntimeWarning,
            stacklevel=2,
        )
    return [_to_row(a) for a in payload if not a.get("withdrawn_at")]

"""CISA Known Exploited Vulnerabilities catalog fetcher.

Endpoint: a static JSON file behind a CDN, refreshed by CISA on every
catalog update. No authentication, no documented rate limit.
"""

from __future__ import annotations

from json import loads
from re import split
from typing import Any

from gha_sec_feed import http
from gha_sec_feed.models import FeedRow

_ENDPOINT = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def _refs(notes: str) -> list[str]:
    """Split ``notes`` into individual reference URLs.

    KEV ``notes`` can carry several URLs joined by ``;`` with arbitrary
    surrounding whitespace (e.g. ``"https://a ; https://b"``). Split on the
    separator, keep only the ``http(s)`` parts, and fall back to the catalog
    homepage when none qualify — C1 requires ``len(refs) >= 1``.
    """
    candidates = [part.strip() for part in split(r"\s*;\s*", notes) if part.strip()]
    urls = [part for part in candidates if part.startswith(("http://", "https://"))]
    return urls or [_CATALOG_URL]


def _to_row(entry: dict[str, Any]) -> FeedRow:
    """Transform one KEV ``vulnerabilities[]`` entry into a :class:`FeedRow`."""
    return FeedRow(
        id=entry["cveID"],
        source="cisa-kev",
        published=f"{entry['dateAdded']}T00:00:00Z",
        severity="unknown",
        cvss=None,
        epss=None,
        kev=True,
        refs=_refs(entry.get("notes", "")),
        description=entry.get("shortDescription", ""),
        cwes=list(entry.get("cwes", [])),
    )


def fetch() -> list[FeedRow]:
    """Fetch the full KEV catalog and return :class:`FeedRow` instances.

    Returns:
        List of C1 rows, one per ``vulnerabilities[]`` entry in the catalog.
        Every row has ``kev=True``, ``severity="unknown"``, and ``cvss=None``
        (the KEV feed does not ship CVSS scores).
    """
    payload = loads(http.get(_ENDPOINT))
    return [_to_row(entry) for entry in payload.get("vulnerabilities", [])]

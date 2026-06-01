"""CISA Known Exploited Vulnerabilities catalog fetcher.

Endpoint: a static JSON file behind a CDN, refreshed by CISA on every
catalog update. No authentication, no documented rate limit.
"""

from __future__ import annotations

import json
from typing import Any

from gha_sec_feed import http

_ENDPOINT = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
_SCHEMA_VERSION = "1.0.0"


def _refs(notes: str) -> list[str]:
    """Use a notes URL when present; otherwise the catalog homepage.

    C1 requires ``len(refs) >= 1``; KEV entries with empty ``notes`` get
    the catalog page as the canonical reference.
    """
    notes = notes.strip()
    if notes.startswith(("http://", "https://")):
        return [notes]
    return [_CATALOG_URL]


def _to_row(entry: dict[str, Any]) -> dict[str, Any]:
    """Transform one KEV ``vulnerabilities[]`` entry into a C1 row."""
    return {
        "id": entry["cveID"],
        "source": "cisa-kev",
        "published": f"{entry['dateAdded']}T00:00:00Z",
        "severity": "unknown",
        "cvss": None,
        "epss": None,
        "kev": True,
        "refs": _refs(entry.get("notes", "")),
        "schema_version": _SCHEMA_VERSION,
    }


def fetch() -> list[dict[str, Any]]:
    """Fetch the full KEV catalog and return C1 rows.

    Returns:
        List of C1 rows, one per ``vulnerabilities[]`` entry in the catalog.
        Every row has ``kev=True``, ``severity="unknown"``, and ``cvss=None``
        (the KEV feed does not ship CVSS scores).
    """
    payload = json.loads(http.get(_ENDPOINT))
    return [_to_row(entry) for entry in payload.get("vulnerabilities", [])]

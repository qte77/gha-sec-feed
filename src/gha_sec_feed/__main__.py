"""CLI entrypoint: fetch NVD + CISA KEV, dedupe + sort, write the C1 contract.

Run as ``python -m gha_sec_feed --out data --since 2026-05-01T00:00:00Z``.
``--since`` defaults to 7 days ago. The output is the C1 contract:
``feed.jsonl`` (one row per line) and ``feed-meta.json``.

The per-source attribution and licence strings travel with every published
artifact via the ``sources`` array in ``feed-meta.json`` so consumers don't
have to scrape upstream pages for legal notices.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from gha_sec_feed import __version__, kev, nvd, writer

_SCHEMA_VERSION = "1.0.0"

# Per-source manifest emitted into feed-meta.json sources[]. Adding a new
# source means appending an entry here and a fetcher; see docs/SOURCES.md.
_SOURCES_MANIFEST: list[dict[str, str]] = [
    {
        "id": "nvd",
        "name": "National Vulnerability Database (NVD)",
        "url": "https://nvd.nist.gov/",
        "license": "US-Government-Work",
        "attribution": (
            "This product uses the NVD API but is not endorsed or certified by the NVD."
        ),
    },
    {
        "id": "cisa-kev",
        "name": "CISA Known Exploited Vulnerabilities Catalog",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "license": "CC0-1.0",
        "attribution": "CISA KEV Catalog — public domain, no endorsement implied.",
    },
]


def _iso_z(dt: datetime) -> str:
    """ISO-8601 Z-suffixed UTC timestamp at second precision."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_since() -> str:
    """Lower-bound ``pubStartDate`` default: 7 days ago, ISO-Z."""
    return _iso_z(datetime.now(timezone.utc) - timedelta(days=7))


def _merge(nvd_rows: list[dict[str, Any]], kev_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Dedupe by ``id``; sort by ``published`` descending.

    KEV's contribution is the ``kev=True`` flag; NVD's contribution is the
    CVSS + severity. On overlap, the NVD row wins for every field except
    ``kev``, which is set to ``True``.
    """
    by_id: dict[str, dict[str, Any]] = {row["id"]: row for row in nvd_rows}
    for k_row in kev_rows:
        cve_id = k_row["id"]
        if cve_id in by_id:
            by_id[cve_id] = {**by_id[cve_id], "kev": True}
        else:
            by_id[cve_id] = k_row
    return sorted(by_id.values(), key=lambda r: r["published"], reverse=True)


def _build_meta(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Assemble the ``feed-meta.json`` payload."""
    return {
        "sources": _SOURCES_MANIFEST,
        "last_run": _iso_z(datetime.now(timezone.utc)),
        "schema_version": _SCHEMA_VERSION,
        "item_count": len(rows),
        "tool_version": __version__,
    }


def main(argv: list[str] | None = None) -> None:
    """CLI entrypoint: fetch, merge, write."""
    parser = argparse.ArgumentParser(prog="gha_sec_feed")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("./data"),
        help="Output directory for feed.jsonl and feed-meta.json (default: ./data).",
    )
    parser.add_argument(
        "--since",
        type=str,
        default=_default_since(),
        help="NVD pubStartDate, ISO-8601 Z UTC (default: 7 days ago).",
    )
    args = parser.parse_args(argv)

    nvd_rows = nvd.fetch(args.since)
    kev_rows = kev.fetch()
    merged = _merge(nvd_rows, kev_rows)
    meta = _build_meta(merged)
    writer.write_feed(merged, meta, args.out)


if __name__ == "__main__":  # pragma: no cover
    main()

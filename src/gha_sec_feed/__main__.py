"""CLI entrypoint: fetch NVD + CISA KEV, dedupe + sort, write the C1 contract.

Run as ``python -m gha_sec_feed --out data --since 2026-05-01T00:00:00Z``.
``--since`` defaults to 7 days ago. The output is the C1 contract:
``feed.jsonl`` (one row per line) and ``feed-meta.json``.

The per-source attribution and licence strings travel with every published
artifact via the ``sources`` array in ``feed-meta.json`` so consumers don't
have to scrape upstream pages for legal notices.
"""

from __future__ import annotations

from argparse import ArgumentParser
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from warnings import warn

from gha_sec_feed import __version__, writer
from gha_sec_feed.config import settings
from gha_sec_feed.fetchers import ghsa, kev, msrc, nvd
from gha_sec_feed.filter import apply_filters
from gha_sec_feed.models import FEED_SCHEMA_VERSION, FeedMeta, FeedRow, SourceEntry

# Per-source manifest emitted into feed-meta.json sources[]. Adding a new
# source means appending an entry here and a fetcher; see docs/SOURCES.md.
_SOURCES_MANIFEST: list[SourceEntry] = [
    SourceEntry(
        id="nvd",
        name="National Vulnerability Database (NVD)",
        url="https://nvd.nist.gov/",
        license="US-Government-Work",
        attribution=("This product uses the NVD API but is not endorsed or certified by the NVD."),
    ),
    SourceEntry(
        id="cisa-kev",
        name="CISA Known Exploited Vulnerabilities Catalog",
        url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        license="CC0-1.0",
        attribution="CISA KEV Catalog — public domain, no endorsement implied.",
    ),
    SourceEntry(
        id="ghsa",
        name="GitHub Security Advisories (GHSA)",
        url="https://github.com/advisories",
        license="CC-BY-4.0",
        attribution="GitHub Advisory Database — CC BY 4.0; per-record advisory URL carried in each row's refs.",
    ),
    SourceEntry(
        id="msrc",
        name="Microsoft Security Response Center (MSRC)",
        url="https://msrc.microsoft.com/update-guide",
        license="proprietary",
        attribution="Microsoft Security Response Center — © Microsoft Corporation; per-record update-guide URL carried in each row's refs.",
    ),
]


def _iso_z(dt: datetime) -> str:
    """ISO-8601 Z-suffixed UTC timestamp at second precision."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_since() -> str:
    """Lower-bound ``pubStartDate`` default: 7 days ago, ISO-Z."""
    return _iso_z(datetime.now(timezone.utc) - timedelta(days=7))


def _merge(*sources: list[FeedRow]) -> list[FeedRow]:
    """Dedupe by ``id`` across sources; sort by ``published`` descending.

    Pass sources in precedence order — earliest wins on field values: NVD
    (authoritative CVSS + vendors) first, then GHSA (fills CVEs/advisories NVD
    hasn't covered), then KEV. The ``kev`` flag is OR'd across every source, so
    any source marking an id ``kev=True`` flips the surviving row — KEV's sole
    contribution (the exploited-in-the-wild flag) is never lost to a
    higher-precedence row.
    """
    by_id: dict[str, FeedRow] = {}
    kev_ids: set[str] = set()
    for source in sources:
        for row in source:
            if row.kev:
                kev_ids.add(row.id)
            by_id.setdefault(row.id, row)
    merged = [
        row.model_copy(update={"kev": True}) if row.id in kev_ids and not row.kev else row
        for row in by_id.values()
    ]
    return sorted(merged, key=lambda r: r.published, reverse=True)


def _build_meta(rows: list[FeedRow]) -> FeedMeta:
    """Assemble the ``feed-meta.json`` payload."""
    return FeedMeta(
        item_count=len(rows),
        last_run=_iso_z(datetime.now(timezone.utc)),
        schema_version=FEED_SCHEMA_VERSION,
        sources=_SOURCES_MANIFEST,
        tool_version=__version__,
    )


def _fetch_all(since: str) -> list[list[FeedRow]]:
    """Fetch every source in precedence order, degrading on per-source failure.

    A source that raises is logged and contributes no rows, so one upstream
    outage (e.g. an MSRC WAF 999, or NVD 5xx after retries) does not sink the
    whole refresh. If *every* source fails, raise — better to leave the prior
    feed intact than to overwrite it with an empty one. Order matches
    :func:`_merge` precedence: NVD, GHSA, MSRC, then KEV.
    """
    sources: list[tuple[str, Callable[[], list[FeedRow]]]] = [
        ("nvd", lambda: nvd.fetch(since)),
        ("ghsa", lambda: ghsa.fetch(since)),
        ("msrc", lambda: msrc.fetch(since)),
        ("cisa-kev", kev.fetch),
    ]
    results: list[list[FeedRow]] = []
    failures = 0
    for name, fetch_source in sources:
        try:
            results.append(fetch_source())
        except Exception as exc:  # degrade: one source must not sink the run
            failures += 1
            results.append([])
            warn(
                f"source {name!r} failed and was skipped: {type(exc).__name__}: {exc}",
                RuntimeWarning,
                stacklevel=2,
            )
    if failures == len(sources):
        raise RuntimeError("all sources failed; refusing to overwrite the feed")
    return results


def main(argv: list[str] | None = None) -> None:
    """CLI entrypoint: fetch, merge, write."""
    parser = ArgumentParser(prog="gha_sec_feed")
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

    nvd_rows, ghsa_rows, msrc_rows, kev_rows = _fetch_all(args.since)
    merged = _merge(nvd_rows, ghsa_rows, msrc_rows, kev_rows)
    filtered = apply_filters(merged, settings())
    meta = _build_meta(filtered)
    writer.write_feed(filtered, meta, args.out)


if __name__ == "__main__":  # pragma: no cover
    main()

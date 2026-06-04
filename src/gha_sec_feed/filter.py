"""Post-merge row filter driven by the four AppSettings knobs.

All four predicates are conjunctive (AND). Defaults are no-op so a
caller who sets nothing receives the full merged feed unchanged — the
producer-is-neutral property required by downstream callers of the
reusable workflow.

Filter haystack for keyword match is ``id + description`` only. The
``refs[]`` URLs are deliberately excluded: NVD's GHSA-mirror cross-
references are dominated by ``github.com`` URLs, so haystacking refs
would make the ``github`` keyword match essentially every NVD row.
"""

from __future__ import annotations

from gha_sec_feed.config import AppSettings
from gha_sec_feed.models import FeedRow, Severity

_RANK: dict[Severity, int] = {
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _severity_rank(severity: Severity) -> int:
    """Map a :data:`Severity` literal to a strictly increasing integer."""
    return _RANK[severity]


def _passes(row: FeedRow, settings: AppSettings) -> bool:
    """Return True iff ``row`` satisfies every configured filter knob."""
    if _severity_rank(row.severity) < _severity_rank(settings.severity_min):
        return False
    if settings.kev_only and not row.kev:
        return False
    if settings.cwe_include:
        wanted = {cwe.lower() for cwe in settings.cwe_include}
        have = {cwe.lower() for cwe in row.cwes}
        if not wanted & have:
            return False
    if settings.keywords:
        haystack = f"{row.id} {row.description}".lower()
        if not any(kw.lower() in haystack for kw in settings.keywords):
            return False
    return True


def apply_filters(rows: list[FeedRow], settings: AppSettings) -> list[FeedRow]:
    """Return the subset of ``rows`` admitted by ``settings``; input order preserved."""
    return [r for r in rows if _passes(r, settings)]

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

import re

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


def _matched_keywords(row: FeedRow, keywords: list[str]) -> list[str]:
    """Return the subset of ``keywords`` that match ``row``'s id + description.

    Strings are returned in *settings form* (as the caller configured them)
    so downstream consumers see an audit trail that matches their input.
    Word-boundary regex on a lowercased haystack — see :func:`_passes`
    for the case-folding rationale.
    """
    if not keywords:
        return []
    haystack = f"{row.id} {row.description}".lower()
    return [kw for kw in keywords if re.search(rf"\b{re.escape(kw.lower())}\b", haystack)]


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
    if settings.vendor_include:
        # `product_include` would mirror this block 1:1 against
        # `row.products` — add when the field exists.
        wanted = {v.lower() for v in settings.vendor_include}
        have = {v.lower() for v in row.vendors}
        if not wanted & have:
            return False
    if settings.keywords and not _matched_keywords(row, settings.keywords):
        # Word-boundary match (case-insensitive) so short keywords like
        # `rust`, `uv`, `pip`, `npm` don't fire on substrings like
        # "trust", "intrusion", "OpenUV", "pipeline", "snmpwalk". The
        # naive `kw in haystack` substring impl produced ~186/272 hits
        # for `rust` alone in the 2026-06-05 showcase run.
        return False
    return True


def apply_filters(rows: list[FeedRow], settings: AppSettings) -> list[FeedRow]:
    """Return the subset of ``rows`` admitted by ``settings``; input order preserved.

    Admitted rows have their ``keywords_matched`` field populated with
    the subset of ``settings.keywords`` (settings form) that matched —
    an audit trail for consumers that want to know *why* a row landed
    in their feed. Empty when ``settings.keywords`` is unset.
    """
    out: list[FeedRow] = []
    for row in rows:
        if not _passes(row, settings):
            continue
        if settings.keywords:
            row = row.model_copy(
                update={"keywords_matched": _matched_keywords(row, settings.keywords)}
            )
        out.append(row)
    return out

"""Tests for ``gha_sec_feed.fetchers.kev`` — CISA KEV catalog fetcher."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from gha_sec_feed.fetchers.kev import _CATALOG_URL, _refs, fetch
from gha_sec_feed.models import FEED_SCHEMA_VERSION, FeedRow

FIXTURE = Path(__file__).parent / "fixtures" / "kev_sample.json"


@pytest.fixture
def mock_http(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {}
    fixture_bytes = FIXTURE.read_bytes()

    def fake_get(url: str, **_kw: Any) -> bytes:
        captured["url"] = url
        return fixture_bytes

    monkeypatch.setattr("gha_sec_feed.fetchers.kev.http.get", fake_get)
    return captured


def test_fetch_calls_http_with_canonical_kev_json_url(mock_http: dict[str, Any]):
    fetch()
    assert (
        mock_http["url"]
        == "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )


def test_fetch_returns_one_feedrow_per_vulnerability(mock_http: dict[str, Any]):
    rows = fetch()
    assert len(rows) == 3
    assert all(isinstance(r, FeedRow) for r in rows)
    assert [r.id for r in rows] == ["CVE-2026-2001", "CVE-2026-2002", "CVE-2026-2003"]


def test_fetch_emits_c1_static_fields_on_every_row(mock_http: dict[str, Any]):
    for row in fetch():
        assert row.source == "cisa-kev"
        assert row.kev is True
        assert row.severity == "unknown"
        assert row.cvss is None
        assert row.epss is None
        assert row.schema_version == FEED_SCHEMA_VERSION


def test_fetch_normalizes_date_added_to_iso_z_midnight(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch()}
    # KEV ships YYYY-MM-DD — C1 requires ISO-Z timestamp.
    assert rows["CVE-2026-2001"].published == "2026-05-29T00:00:00Z"
    assert rows["CVE-2026-2002"].published == "2026-05-28T00:00:00Z"


def test_fetch_uses_notes_url_when_present(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch()}
    assert rows["CVE-2026-2001"].refs == ["https://security.testvendor.example/CVE-2026-2001"]
    assert rows["CVE-2026-2003"].refs == ["https://example.com/advisory/CVE-2026-2003"]


def test_fetch_falls_back_to_catalog_url_when_notes_empty(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch()}
    # CVE-2026-2002 has empty notes — must still have ≥1 ref per C1
    assert rows["CVE-2026-2002"].refs == [_CATALOG_URL]
    assert len(rows["CVE-2026-2002"].refs) == 1


def test_fetch_passes_shortDescription_into_description_field(mock_http: dict[str, Any]):
    # KEV ships the human-readable text under `shortDescription` (not
    # `description`). Catches forgetting to wire the field through, or
    # mis-naming the source key.
    rows = {r.id: r for r in fetch()}
    assert rows["CVE-2026-2001"].description == "Authentication bypass in TestProduct."
    assert rows["CVE-2026-2002"].description == "Remote code execution vulnerability."


def test_fetch_passes_through_cwes_list_verbatim(mock_http: dict[str, Any]):
    # KEV `cwes` is already an array of CWE-prefixed IDs — no filter or
    # dedup needed. Catches the impl confusing KEV's flat list with NVD's
    # nested weaknesses[].description[] shape.
    rows = {r.id: r for r in fetch()}
    assert rows["CVE-2026-2001"].cwes == ["CWE-287"]
    assert rows["CVE-2026-2002"].cwes == ["CWE-78"]
    assert rows["CVE-2026-2003"].cwes == ["CWE-22"]


# ---------- _refs: multi-URL notes splitting (#18) ---------------------------
# KEV `notes` can carry several URLs joined by a semicolon. The old impl
# emitted the whole string as a single malformed ref. _refs must split on
# semicolons (with any surrounding whitespace), keep only http(s) parts, and
# fall back to the catalog URL when none qualify.


def test_refs_splits_semicolon_space_separated_urls():
    notes = "https://a.example/CVE-1; https://nvd.nist.gov/vuln/detail/CVE-1"
    assert _refs(notes) == ["https://a.example/CVE-1", "https://nvd.nist.gov/vuln/detail/CVE-1"]


def test_refs_splits_space_semicolon_space_separated_urls():
    notes = "https://a.example/CVE-1 ; https://b.example/CVE-1"
    assert _refs(notes) == ["https://a.example/CVE-1", "https://b.example/CVE-1"]


def test_refs_splits_bare_semicolon_separated_urls():
    notes = "https://a.example/CVE-1;https://b.example/CVE-1"
    assert _refs(notes) == ["https://a.example/CVE-1", "https://b.example/CVE-1"]


def test_refs_drops_non_url_parts_keeping_urls():
    notes = "https://a.example/CVE-1 ; see vendor bulletin"
    assert _refs(notes) == ["https://a.example/CVE-1"]


def test_refs_falls_back_to_catalog_url_when_no_url_present():
    assert _refs("") == [_CATALOG_URL]
    assert _refs("   ") == [_CATALOG_URL]
    assert _refs("see vendor advisory") == [_CATALOG_URL]

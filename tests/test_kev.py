"""Tests for ``gha_sec_feed.kev`` — CISA KEV catalog fetcher."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from gha_sec_feed.kev import _CATALOG_URL, fetch
from gha_sec_feed.models import FeedRow

FIXTURE = Path(__file__).parent / "fixtures" / "kev_sample.json"


@pytest.fixture
def mock_http(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {}
    fixture_bytes = FIXTURE.read_bytes()

    def fake_get(url: str, **_kw: Any) -> bytes:
        captured["url"] = url
        return fixture_bytes

    monkeypatch.setattr("gha_sec_feed.kev.http.get", fake_get)
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
        assert row.schema_version == "1.0.0"


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

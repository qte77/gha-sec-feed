"""Tests for ``gha_sec_feed.fetchers.nvd`` — NVD CVE API v2 fetcher."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from gha_sec_feed.fetchers.nvd import _severity, fetch
from gha_sec_feed.models import FeedRow

FIXTURE = Path(__file__).parent / "fixtures" / "nvd_sample.json"
SINCE = "2026-05-01T00:00:00Z"


@pytest.fixture
def mock_http(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Patch ``gha_sec_feed.nvd.http.get`` to return the NVD fixture bytes."""
    captured: dict[str, Any] = {}
    fixture_bytes = FIXTURE.read_bytes()

    def fake_get(url: str, **_kw: Any) -> bytes:
        captured["url"] = url
        return fixture_bytes

    monkeypatch.setattr("gha_sec_feed.fetchers.nvd.http.get", fake_get)
    return captured


def test_fetch_calls_http_with_pub_start_date_from_since(mock_http: dict[str, Any]):
    fetch(SINCE)
    assert "pubStartDate=" in mock_http["url"]
    assert SINCE.replace(":", "%3A") in mock_http["url"]
    assert mock_http["url"].startswith("https://services.nvd.nist.gov/rest/json/cves/2.0")


def test_fetch_returns_one_feedrow_per_vulnerability(mock_http: dict[str, Any]):
    rows = fetch(SINCE)
    assert len(rows) == 3
    assert all(isinstance(r, FeedRow) for r in rows)
    assert [r.id for r in rows] == ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"]


def test_fetch_emits_c1_static_fields_on_every_row(mock_http: dict[str, Any]):
    for row in fetch(SINCE):
        assert row.source == "nvd"
        assert row.kev is False
        assert row.epss is None
        assert row.schema_version == "1.0.0"


def test_fetch_maps_severity_by_threshold(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch(SINCE)}
    assert rows["CVE-2026-1001"].severity == "critical"  # 9.8
    assert rows["CVE-2026-1002"].severity == "medium"  # 5.5
    assert rows["CVE-2026-1003"].severity == "unknown"  # no metrics


def test_fetch_extracts_cvss_or_none_when_missing(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch(SINCE)}
    assert rows["CVE-2026-1001"].cvss == 9.8
    assert rows["CVE-2026-1002"].cvss == 5.5
    assert rows["CVE-2026-1003"].cvss is None


def test_fetch_extracts_all_reference_urls(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch(SINCE)}
    assert rows["CVE-2026-1001"].refs == [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-1001",
        "https://example.com/advisory/CVE-2026-1001",
    ]
    assert rows["CVE-2026-1002"].refs == [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-1002",
    ]


def test_fetch_normalizes_published_to_iso_z_no_microseconds(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch(SINCE)}
    # NVD ships "2026-05-30T12:00:00.000" — C1 requires "...T...:00Z"
    assert rows["CVE-2026-1001"].published == "2026-05-30T12:00:00Z"
    for row in rows.values():
        assert row.published.endswith("Z")
        assert "." not in row.published


def test_severity_threshold_table():
    # Boundaries explicit; catches off-by-one in the mapping.
    assert _severity(10.0) == "critical"
    assert _severity(9.0) == "critical"
    assert _severity(8.9) == "high"
    assert _severity(7.0) == "high"
    assert _severity(6.9) == "medium"
    assert _severity(4.0) == "medium"
    assert _severity(3.9) == "low"
    assert _severity(0.1) == "low"
    assert _severity(0.0) == "unknown"
    assert _severity(None) == "unknown"

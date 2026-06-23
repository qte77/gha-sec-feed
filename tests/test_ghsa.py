"""Tests for ``gha_sec_feed.fetchers.ghsa`` — GitHub Security Advisories fetcher."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from gha_sec_feed.fetchers.ghsa import _ENDPOINT, fetch
from gha_sec_feed.models import FEED_SCHEMA_VERSION, FeedRow

FIXTURE = Path(__file__).parent / "fixtures" / "ghsa_sample.json"
SINCE = "2026-06-15T00:00:00Z"


@pytest.fixture
def mock_http(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {}
    fixture_bytes = FIXTURE.read_bytes()

    def fake_get(
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        **_kw: Any,
    ) -> bytes:
        captured["url"] = url
        captured["params"] = dict(params) if params else {}
        captured["headers"] = dict(headers) if headers else {}
        return fixture_bytes

    monkeypatch.setattr("gha_sec_feed.fetchers.ghsa.http.get", fake_get)
    return captured


def test_fetch_requests_reviewed_advisories_published_since(mock_http: dict[str, Any]):
    fetch(SINCE)
    assert mock_http["url"] == _ENDPOINT
    assert mock_http["params"]["type"] == "reviewed"
    assert mock_http["params"]["published"] == ">=2026-06-15"
    # GitHub REST etiquette: explicit Accept + API version.
    assert mock_http["headers"]["Accept"] == "application/vnd.github+json"


def test_fetch_skips_withdrawn_advisories(mock_http: dict[str, Any]):
    rows = fetch(SINCE)
    # CVE-2026-7003 is withdrawn → dropped; two rows remain.
    assert [r.id for r in rows] == ["CVE-2026-7001", "GHSA-2222-2222-2222"]
    assert all(isinstance(r, FeedRow) for r in rows)


def test_fetch_emits_c1_static_fields(mock_http: dict[str, Any]):
    for row in fetch(SINCE):
        assert row.source == "ghsa"
        assert row.kev is False
        assert row.schema_version == FEED_SCHEMA_VERSION


def test_fetch_uses_ghsa_id_when_cve_id_absent(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch(SINCE)}
    assert "GHSA-2222-2222-2222" in rows  # cve_id was null
    assert "CVE-2026-7001" in rows  # cve_id present wins over ghsa_id


def test_fetch_maps_severity_verbatim(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch(SINCE)}
    assert rows["CVE-2026-7001"].severity == "critical"
    assert rows["GHSA-2222-2222-2222"].severity == "medium"


def test_fetch_prefers_top_level_cvss_then_v3_then_v4(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch(SINCE)}
    # row1: top-level 9.8 used.
    assert rows["CVE-2026-7001"].cvss == 9.8
    # row2: top-level null, v3 is 0 (placeholder → skipped), v4 5.3 used.
    assert rows["GHSA-2222-2222-2222"].cvss == 5.3


def test_fetch_reads_epss_percentage_as_unit_interval(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch(SINCE)}
    # GitHub's epss.percentage is already 0–1; no scaling.
    assert rows["CVE-2026-7001"].epss == 0.42
    assert rows["GHSA-2222-2222-2222"].epss is None  # empty epss object


def test_fetch_dedupes_cwes_preserving_order(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch(SINCE)}
    assert rows["CVE-2026-7001"].cwes == ["CWE-89"]
    assert rows["GHSA-2222-2222-2222"].cwes == []


def test_fetch_puts_advisory_html_url_first_in_refs(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch(SINCE)}
    # CC-BY attribution: the advisory page URL leads, then upstream refs.
    assert rows["CVE-2026-7001"].refs[0] == "https://github.com/advisories/GHSA-1111-1111-1111"
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-7001" in rows["CVE-2026-7001"].refs


def test_fetch_falls_back_to_html_url_when_references_empty(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch(SINCE)}
    # C1 requires len(refs) >= 1; references was empty.
    assert rows["GHSA-2222-2222-2222"].refs == ["https://github.com/advisories/GHSA-2222-2222-2222"]


def test_fetch_normalizes_published_to_iso_z_no_microseconds(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch(SINCE)}
    assert rows["GHSA-2222-2222-2222"].published == "2026-06-19T08:30:00Z"
    for row in rows.values():
        assert row.published.endswith("Z")
        assert "." not in row.published

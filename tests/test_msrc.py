"""Tests for ``gha_sec_feed.fetchers.msrc`` — MSRC CVRF v3.0 fetcher.

The MSRC API could not be live-verified (Azure WAF returns 999 to datacenter
IPs), so these tests pin the producer against the documented CVRF v3.0 JSON
shape. The fetcher is intentionally defensive; these tests lock that contract.
"""

from __future__ import annotations

from json import dumps
from typing import Any

import pytest

from gha_sec_feed.fetchers.msrc import fetch
from gha_sec_feed.models import FEED_SCHEMA_VERSION, FeedRow

SINCE = "2026-06-05T00:00:00Z"

_UPDATES = {
    "value": [
        {"ID": "2026-Jun", "CurrentReleaseDate": "2026-06-10T07:00:00Z"},
        {"ID": "2026-May", "CurrentReleaseDate": "2026-05-13T07:00:00Z"},  # < since → skip
    ]
}

_DOC_JUN = {
    "DocumentTracking": {"CurrentReleaseDate": "2026-06-10T07:00:00.000"},
    "Vulnerability": [
        {
            "CVE": "CVE-2026-30001",
            "Title": {"Value": "Windows Kernel Elevation of Privilege"},
            "CVSSScoreSets": [{"BaseScore": 7.8, "Vector": "CVSS:3.1/AV:L"}],
            "Threats": [
                {"Type": 0, "Description": {"Value": "Elevation of Privilege"}},
                {"Type": 3, "Description": {"Value": "Important"}},
            ],
        },
        {"CVE": "ADV260001", "Title": {"Value": "Defender advisory (not a CVE)"}},
        {
            "CVE": "CVE-2026-30002",
            "Title": {"Value": "Critical RCE"},
            "CVSSScoreSets": [{"BaseScore": 9.8}],
            "Threats": [{"Type": 3, "Description": {"Value": "Critical"}}],
        },
    ],
}


@pytest.fixture
def mock_http(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {"urls": []}

    def fake_get(url: str, **_kw: Any) -> bytes:
        captured["urls"].append(url)
        payload = _UPDATES if url.endswith("/updates") else _DOC_JUN
        return dumps(payload).encode()

    monkeypatch.setattr("gha_sec_feed.fetchers.msrc.http.get", fake_get)
    return captured


def test_fetch_lists_updates_then_pulls_only_the_latest_document(mock_http: dict[str, Any]):
    fetch(SINCE)
    urls = mock_http["urls"]
    assert urls[0].endswith("/cvrf/v3.0/updates")
    assert any(u.endswith("/cvrf/2026-Jun") for u in urls)  # latest month
    # Only the latest monthly document is pulled; older months are not.
    assert not any(u.endswith("/cvrf/2026-May") for u in urls)


def test_fetch_ignores_since_window_for_monthly_selection(mock_http: dict[str, Any]):
    # MSRC is monthly: even a `since` AFTER the latest release still pulls the
    # latest document (the old 7-day-window filter wrongly excluded it, #66).
    rows = fetch("2026-07-01T00:00:00Z")
    assert [r.id for r in rows] == ["CVE-2026-30001", "CVE-2026-30002"]


def test_fetch_skips_non_cve_advisories(mock_http: dict[str, Any]):
    rows = fetch(SINCE)
    assert [r.id for r in rows] == ["CVE-2026-30001", "CVE-2026-30002"]
    assert all(isinstance(r, FeedRow) for r in rows)


def test_fetch_maps_msrc_severity_to_c1(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch(SINCE)}
    assert rows["CVE-2026-30001"].severity == "high"  # "Important" → high
    assert rows["CVE-2026-30002"].severity == "critical"  # "Critical" → critical


def test_fetch_maps_cvss_base_score(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch(SINCE)}
    assert rows["CVE-2026-30001"].cvss == 7.8
    assert rows["CVE-2026-30002"].cvss == 9.8


def test_fetch_emits_c1_static_fields(mock_http: dict[str, Any]):
    for row in fetch(SINCE):
        assert row.source == "msrc"
        assert row.kev is False
        assert row.epss is None
        assert row.schema_version == FEED_SCHEMA_VERSION


def test_fetch_refs_is_update_guide_url(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch(SINCE)}
    assert rows["CVE-2026-30001"].refs == [
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-30001"
    ]


def test_fetch_normalizes_published_to_iso_z(mock_http: dict[str, Any]):
    rows = {r.id: r for r in fetch(SINCE)}
    assert rows["CVE-2026-30001"].published == "2026-06-10T07:00:00Z"
    for row in rows.values():
        assert row.published.endswith("Z")
        assert "." not in row.published

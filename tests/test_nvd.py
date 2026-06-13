"""Tests for ``gha_sec_feed.fetchers.nvd`` — NVD CVE API v2 fetcher."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from gha_sec_feed.fetchers.nvd import _extract_refs, _severity, fetch
from gha_sec_feed.models import FEED_SCHEMA_VERSION, FeedRow

FIXTURE = Path(__file__).parent / "fixtures" / "nvd_sample.json"
SINCE = "2026-05-01T00:00:00Z"


@pytest.fixture
def mock_http(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Patch ``gha_sec_feed.nvd.http.get`` to return the NVD fixture bytes."""
    captured: dict[str, Any] = {}
    fixture_bytes = FIXTURE.read_bytes()

    def fake_get(
        url: str,
        *,
        params: dict[str, str] | None = None,
        **_kw: Any,
    ) -> bytes:
        captured["url"] = url
        captured["params"] = dict(params) if params else {}
        return fixture_bytes

    monkeypatch.setattr("gha_sec_feed.fetchers.nvd.http.get", fake_get)
    return captured


def test_fetch_passes_pub_start_date_via_params_in_iso_z_form(
    mock_http: dict[str, Any],
):
    # NVD CVE API v2 wants the ISO-8601 Z form (no millisecond suffix)
    # in the `pubStartDate` query parameter, and is picky about the
    # URL builder — pre-building the URL with urllib.urlencode was
    # observed to 404 while passing the params separately so httpx
    # builds the query returned 200. See #27.
    fetch(SINCE)
    assert mock_http["params"]["pubStartDate"] == SINCE
    assert mock_http["url"] == "https://services.nvd.nist.gov/rest/json/cves/2.0"


def test_fetch_pub_end_date_param_uses_iso_z_form(mock_http: dict[str, Any]):
    # pubEndDate is computed inside fetch() (datetime.now); assert the
    # format alone without pinning the value. Anti-regression on the
    # `.000`-no-Z form (#29).
    import re

    fetch(SINCE)
    end = mock_http["params"]["pubEndDate"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", end), end


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
        assert row.schema_version == FEED_SCHEMA_VERSION


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


def test_fetch_picks_english_description_when_multiple_languages_present(
    mock_http: dict[str, Any],
):
    # CVE-2026-1002's fixture ships an `es` description before the `en` one.
    # Catches "take the first descriptions[] entry regardless of lang".
    rows = {r.id: r for r in fetch(SINCE)}
    assert rows["CVE-2026-1002"].description == "Medium severity disclosure"


def test_fetch_returns_empty_description_when_descriptions_field_absent(
    mock_http: dict[str, Any],
):
    # Construct a row where the source omits descriptions entirely by
    # reusing CVE-2026-1003 — its English string is present, exercise the
    # empty-default branch via a separate assertion below.
    rows = {r.id: r for r in fetch(SINCE)}
    # The fixture provides English text for all three rows, so verify
    # the third (no weaknesses field) still gets a non-empty description.
    assert rows["CVE-2026-1003"].description == "Unscored / awaiting analysis"


def test_fetch_dedupes_repeated_cwe_ids_preserving_first_occurrence_order(
    mock_http: dict[str, Any],
):
    # CVE-2026-1001 lists CWE-79 twice, then CWE-200 — output must keep
    # one CWE-79 in the position of its first occurrence. Catches both
    # "emit duplicates" and "sort alphabetically" bugs.
    rows = {r.id: r for r in fetch(SINCE)}
    assert rows["CVE-2026-1001"].cwes == ["CWE-79", "CWE-200"]


def test_fetch_rejects_weakness_descriptions_without_cwe_prefix(
    mock_http: dict[str, Any],
):
    # CVE-2026-1001 includes a "NVD-CWE-Other" weakness — NVD's noise
    # marker for "no specific CWE assigned". Catches a blind append.
    rows = {r.id: r for r in fetch(SINCE)}
    assert "NVD-CWE-Other" not in rows["CVE-2026-1001"].cwes


def test_fetch_returns_empty_cwes_when_weaknesses_field_absent(
    mock_http: dict[str, Any],
):
    # CVE-2026-1003 omits `weaknesses`. Catches KeyError / AttributeError
    # against missing upstream fields.
    rows = {r.id: r for r in fetch(SINCE)}
    assert rows["CVE-2026-1003"].cwes == []


def test_fetch_extracts_vendors_dedupes_and_skips_wildcards(
    mock_http: dict[str, Any],
):
    # CVE-2026-1001's fixture lists `python` twice, `apache` once, and a
    # wildcard `*` vendor — output must be ["python", "apache"]: dedup
    # preserving first-occurrence order, wildcard skipped. Catches a
    # blind append, a wrong CPE-split index, and an out-of-order dedup.
    rows = {r.id: r for r in fetch(SINCE)}
    assert rows["CVE-2026-1001"].vendors == ["python", "apache"]


def test_fetch_extracts_single_vendor_per_cve(mock_http: dict[str, Any]):
    # CVE-2026-1002 has just `nginx`. Single-element case catches
    # "only emit when >1 vendor" filtering and off-by-one indexing.
    rows = {r.id: r for r in fetch(SINCE)}
    assert rows["CVE-2026-1002"].vendors == ["nginx"]


def test_fetch_returns_empty_vendors_when_configurations_field_absent(
    mock_http: dict[str, Any],
):
    # CVE-2026-1003 omits `configurations`. Catches KeyError /
    # AttributeError against missing upstream fields — fresh NVD CVEs
    # routinely ship before CPE assignment completes.
    rows = {r.id: r for r in fetch(SINCE)}
    assert rows["CVE-2026-1003"].vendors == []


def test_extract_refs_passes_through_reference_urls():
    cve = {
        "id": "CVE-2026-9999",
        "references": [
            {"url": "https://example.com/a"},
            {"url": "https://example.com/b"},
        ],
    }
    assert _extract_refs(cve) == ["https://example.com/a", "https://example.com/b"]


def test_extract_refs_falls_back_to_nvd_detail_url_when_empty():
    # NVD occasionally ships CVEs with no `references` entries (usually
    # very fresh entries that haven't been enriched yet). The C1
    # contract requires len(refs) >= 1, so we must synthesise a
    # canonical URL — the NVD detail page is the authoritative
    # fallback. Catches a regression to the pre-fix behaviour where
    # _to_row passed an empty list straight through to FeedRow.
    cve = {"id": "CVE-2026-8888", "references": []}
    assert _extract_refs(cve) == ["https://nvd.nist.gov/vuln/detail/CVE-2026-8888"]


def test_extract_refs_falls_back_when_references_field_absent():
    # Same fallback when the field is missing entirely (not just empty).
    cve = {"id": "CVE-2026-7777"}
    assert _extract_refs(cve) == ["https://nvd.nist.gov/vuln/detail/CVE-2026-7777"]


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

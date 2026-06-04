"""Tests for ``gha_sec_feed.__main__`` — CLI assembly + dedupe/sort/merge."""

from __future__ import annotations

from json import loads
from pathlib import Path
from typing import Any

import pytest

from gha_sec_feed import __main__ as cli
from gha_sec_feed.__main__ import _SOURCES_MANIFEST, _build_meta, _default_since, _merge, main
from gha_sec_feed.models import FeedMeta, FeedRow


def _row(
    cve_id: str,
    *,
    source: str = "nvd",
    published: str = "2026-05-01T00:00:00Z",
    severity: str = "high",
    cvss: float | None = 7.5,
    kev: bool = False,
) -> FeedRow:
    return FeedRow.model_validate(
        {
            "id": cve_id,
            "source": source,
            "published": published,
            "severity": severity,
            "cvss": cvss,
            "epss": None,
            "kev": kev,
            "refs": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
        }
    )


# ---------- _merge -----------------------------------------------------------


def test_merge_passes_nvd_only_rows_through_unchanged():
    rows = _merge([_row("CVE-1")], [])
    assert rows == [_row("CVE-1")]


def test_merge_passes_kev_only_rows_through_unchanged():
    kev_row = _row("CVE-2", source="cisa-kev", severity="unknown", cvss=None, kev=True)
    rows = _merge([], [kev_row])
    assert rows == [kev_row]


def test_merge_overlap_keeps_nvd_fields_but_flips_kev_true():
    nvd_row = _row("CVE-3", cvss=9.8, severity="critical", kev=False)
    kev_row = _row("CVE-3", source="cisa-kev", severity="unknown", cvss=None, kev=True)
    rows = _merge([nvd_row], [kev_row])

    assert len(rows) == 1
    merged = rows[0]
    # NVD wins on cvss / severity / source / refs
    assert merged.source == "nvd"
    assert merged.cvss == 9.8
    assert merged.severity == "critical"
    # KEV wins on the kev flag
    assert merged.kev is True


def test_merge_output_sorted_by_published_descending():
    rows = _merge(
        [
            _row("CVE-A", published="2026-05-01T00:00:00Z"),
            _row("CVE-B", published="2026-05-10T00:00:00Z"),
            _row("CVE-C", published="2026-05-05T00:00:00Z"),
        ],
        [],
    )
    assert [r.id for r in rows] == ["CVE-B", "CVE-C", "CVE-A"]


# ---------- _build_meta ------------------------------------------------------


def test_build_meta_includes_sources_manifest_with_nvd_attribution():
    meta = _build_meta(rows=[_row("CVE-1"), _row("CVE-2")])
    assert isinstance(meta, FeedMeta)
    assert meta.sources == _SOURCES_MANIFEST
    assert meta.item_count == 2
    assert meta.schema_version == "1.0.0"
    assert meta.tool_version  # non-empty
    assert meta.last_run.endswith("Z")

    nvd_entry = next(s for s in meta.sources if s.id == "nvd")
    assert (
        nvd_entry.attribution
        == "This product uses the NVD API but is not endorsed or certified by the NVD."
    )

    kev_entry = next(s for s in meta.sources if s.id == "cisa-kev")
    assert kev_entry.license == "CC0-1.0"


# ---------- _default_since ---------------------------------------------------


def test_default_since_is_seven_days_ago_iso_z():
    from datetime import datetime, timezone

    raw = _default_since()
    assert raw.endswith("Z")
    parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    delta = datetime.now(timezone.utc) - parsed
    # Allow ±1 minute clock drift.
    assert 6 * 24 * 3600 + 23 * 3600 + 59 * 60 < delta.total_seconds() < 7 * 24 * 3600 + 60


# ---------- main() end-to-end -----------------------------------------------


def test_main_writes_feed_and_meta_to_out_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    nvd_rows = [_row("CVE-100", cvss=9.8, severity="critical")]
    kev_rows = [
        _row("CVE-100", source="cisa-kev", severity="unknown", cvss=None, kev=True),
        _row("CVE-200", source="cisa-kev", severity="unknown", cvss=None, kev=True),
    ]
    monkeypatch.setattr(cli.nvd, "fetch", lambda _since: nvd_rows)
    monkeypatch.setattr(cli.kev, "fetch", lambda: kev_rows)

    main(["--out", str(tmp_path), "--since", "2026-05-01T00:00:00Z"])

    jsonl = (tmp_path / "feed.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(jsonl) == 2  # dedupe collapsed CVE-100 across sources
    ids = {loads(line)["id"] for line in jsonl}
    assert ids == {"CVE-100", "CVE-200"}

    meta = loads((tmp_path / "feed-meta.json").read_text(encoding="utf-8"))
    assert meta["item_count"] == 2
    assert {s["id"] for s in meta["sources"]} == {"nvd", "cisa-kev"}


def test_main_default_out_dir_is_data(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    captured: dict[str, Any] = {}
    monkeypatch.setattr(cli.nvd, "fetch", lambda _s: [])
    monkeypatch.setattr(cli.kev, "fetch", lambda: [])
    monkeypatch.setattr(
        cli.writer,
        "write_feed",
        lambda rows, meta, out_dir: captured.update({"out_dir": out_dir}),
    )
    monkeypatch.chdir(tmp_path)

    main(["--since", "2026-05-01T00:00:00Z"])

    assert captured["out_dir"] == Path("./data")

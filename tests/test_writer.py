"""Tests for ``gha_sec_feed.writer`` — atomic JSONL + meta writer."""

from __future__ import annotations

from json import loads
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from gha_sec_feed.writer import write_feed


def _rows() -> list[dict[str, Any]]:
    return [
        {
            "id": "CVE-2026-0001",
            "source": "nvd",
            "published": "2026-05-31T00:00:00Z",
            "severity": "critical",
            "cvss": 9.8,
            "epss": None,
            "kev": False,
            "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2026-0001"],
            "schema_version": "1.0.0",
        },
        {
            "id": "CVE-2026-0002",
            "source": "cisa-kev",
            "published": "2026-05-30T00:00:00Z",
            "severity": "unknown",
            "cvss": None,
            "epss": None,
            "kev": True,
            "refs": ["https://cisa.gov/advisory/2026-0002"],
            "schema_version": "1.0.0",
        },
    ]


def _meta() -> dict[str, Any]:
    return {
        "sources": ["nvd", "cisa-kev"],
        "last_run": "2026-05-31T11:27:00Z",
        "schema_version": "1.0.0",
        "item_count": 2,
    }


def test_writes_rows_as_one_json_object_per_line(tmp_path: Path):
    write_feed(_rows(), _meta(), tmp_path)

    text = (tmp_path / "feed.jsonl").read_text(encoding="utf-8")
    lines = text.splitlines()
    assert len(lines) == 2
    parsed = [loads(line) for line in lines]
    assert parsed == _rows()


def test_writes_meta_as_valid_json(tmp_path: Path):
    write_feed(_rows(), _meta(), tmp_path)

    parsed = loads((tmp_path / "feed-meta.json").read_text(encoding="utf-8"))
    assert parsed == _meta()


def test_output_is_byte_identical_across_runs(tmp_path: Path):
    # Permute key order on input — sort_keys must give the same bytes.
    rows_a = [{"id": "X", "kev": False, "source": "nvd"}]
    rows_b = [{"source": "nvd", "kev": False, "id": "X"}]
    meta_same = {"item_count": 1, "sources": ["nvd"]}

    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()

    write_feed(rows_a, meta_same, dir_a)
    write_feed(rows_b, meta_same, dir_b)

    assert (dir_a / "feed.jsonl").read_bytes() == (dir_b / "feed.jsonl").read_bytes()
    assert (dir_a / "feed-meta.json").read_bytes() == (dir_b / "feed-meta.json").read_bytes()


def test_atomic_write_leaves_previous_file_intact_on_failure(tmp_path: Path):
    # Seed a previous successful write.
    write_feed(_rows(), _meta(), tmp_path)
    original_jsonl = (tmp_path / "feed.jsonl").read_bytes()
    original_meta = (tmp_path / "feed-meta.json").read_bytes()

    # Next call: rename fails mid-stream. Original files must NOT be clobbered.
    with patch("gha_sec_feed.writer.replace", side_effect=OSError("disk full")):
        with pytest.raises(OSError, match="disk full"):
            write_feed([{"id": "NEW", "source": "nvd"}], {"item_count": 1}, tmp_path)

    assert (tmp_path / "feed.jsonl").read_bytes() == original_jsonl
    assert (tmp_path / "feed-meta.json").read_bytes() == original_meta


def test_atomic_write_cleans_up_tempfile_on_failure(tmp_path: Path):
    with patch("gha_sec_feed.writer.replace", side_effect=OSError("disk full")):
        with pytest.raises(OSError):
            write_feed(_rows(), _meta(), tmp_path)

    # No half-written .tmp files left behind.
    leftover = list(tmp_path.glob("*.tmp"))
    assert leftover == []

"""Tests for ``gha_sec_feed.models`` — C1 payload validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gha_sec_feed.models import (
    FEED_SCHEMA_VERSION,
    FeedMeta,
    FeedRow,
    SourceEntry,
)


def _valid_row(**overrides):
    base = {
        "id": "CVE-2026-0001",
        "source": "nvd",
        "published": "2026-05-30T12:00:00Z",
        "severity": "critical",
        "cvss": 9.8,
        "epss": None,
        "kev": False,
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2026-0001"],
    }
    base.update(overrides)
    return base


def test_feed_row_default_schema_version_matches_constant():
    row = FeedRow(**_valid_row())
    assert row.schema_version == FEED_SCHEMA_VERSION == "1.0.0"


def test_feed_row_rejects_unknown_source_slug():
    with pytest.raises(ValidationError, match="source"):
        FeedRow(**_valid_row(source="github"))


def test_feed_row_rejects_unknown_severity():
    with pytest.raises(ValidationError, match="severity"):
        FeedRow(**_valid_row(severity="catastrophic"))


def test_feed_row_rejects_cvss_above_ten():
    with pytest.raises(ValidationError, match="cvss"):
        FeedRow(**_valid_row(cvss=11.0))


def test_feed_row_rejects_negative_cvss():
    with pytest.raises(ValidationError, match="cvss"):
        FeedRow(**_valid_row(cvss=-0.1))


def test_feed_row_accepts_integer_cvss_from_nvd():
    # NVD sometimes serialises baseScore as int; strict=False allows coercion.
    row = FeedRow(**_valid_row(cvss=10))
    assert row.cvss == 10.0


def test_feed_row_rejects_epss_above_one():
    with pytest.raises(ValidationError, match="epss"):
        FeedRow(**_valid_row(epss=1.5))


def test_feed_row_rejects_empty_refs_list():
    # C1 contract: refs has length >= 1
    with pytest.raises(ValidationError, match="refs"):
        FeedRow(**_valid_row(refs=[]))


def test_feed_row_rejects_extra_fields():
    with pytest.raises(ValidationError, match="extra"):
        FeedRow(**_valid_row(unknown_field="oops"))


def test_feed_row_is_frozen():
    row = FeedRow(**_valid_row())
    with pytest.raises(ValidationError, match="frozen"):
        row.cvss = 5.0


def test_source_entry_rejects_unknown_id():
    with pytest.raises(ValidationError, match="id"):
        SourceEntry.model_validate(
            {
                "id": "urlhaus",
                "name": "x",
                "url": "x",
                "license": "x",
                "attribution": "x",
            }
        )


def test_feed_meta_rejects_negative_item_count():
    with pytest.raises(ValidationError, match="item_count"):
        FeedMeta(
            sources=[],
            last_run="2026-05-31T00:00:00Z",
            schema_version=FEED_SCHEMA_VERSION,
            item_count=-1,
            tool_version="0.1.0",
        )


def test_feed_meta_roundtrips_via_model_validate_and_model_dump():
    original = FeedMeta(
        sources=[
            SourceEntry(
                id="nvd",
                name="NVD",
                url="https://nvd.nist.gov/",
                license="US-Government-Work",
                attribution="...",
            )
        ],
        last_run="2026-05-31T00:00:00Z",
        schema_version=FEED_SCHEMA_VERSION,
        item_count=42,
        tool_version="0.1.0",
    )
    roundtripped = FeedMeta.model_validate(original.model_dump())
    assert roundtripped == original

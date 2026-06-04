"""Pydantic models for the C1 contract.

Single source of truth for the row schema (:class:`FeedRow`), the meta
sidecar (:class:`FeedMeta`), and the per-source manifest entries
(:class:`SourceEntry`). All three are frozen + ``extra="forbid"`` so a
typo at construction site fails loudly.

:data:`FEED_SCHEMA_VERSION` is the one authoritative schema version
string — fetchers and the CLI both import it from here so a contract
bump touches one constant rather than three.
"""

from __future__ import annotations

from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

FEED_SCHEMA_VERSION: Final[str] = "1.0.0"

Severity = Literal["critical", "high", "medium", "low", "unknown"]
SourceSlug = Literal["nvd", "cisa-kev"]


class SourceEntry(BaseModel):
    """One entry in :class:`FeedMeta.sources` — licence + attribution per source."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: SourceSlug
    name: str
    url: str
    license: str
    attribution: str


class FeedRow(BaseModel):
    """One row of ``data/feed.jsonl`` — the C1 contract row shape.

    ``strict=False`` to accept integer ``cvss`` values from NVD (e.g.,
    ``baseScore: 10`` instead of ``10.0``); range constraints still hold.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    source: SourceSlug
    published: str  # ISO-8601 Z UTC
    severity: Severity
    cvss: Annotated[float, Field(ge=0.0, le=10.0)] | None
    epss: Annotated[float, Field(ge=0.0, le=1.0)] | None
    kev: bool
    refs: Annotated[list[str], Field(min_length=1)]
    schema_version: str = FEED_SCHEMA_VERSION


class FeedMeta(BaseModel):
    """Payload of ``data/feed-meta.json`` — sidecar metadata for the C1 feed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sources: list[SourceEntry]
    last_run: str  # ISO-8601 Z UTC
    schema_version: str
    item_count: Annotated[int, Field(ge=0)]
    tool_version: str

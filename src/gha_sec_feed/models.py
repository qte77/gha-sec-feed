"""Pydantic models for the C1 contract.

Single source of truth for the row schema (:class:`FeedRow`), the meta
sidecar (:class:`FeedMeta`), and the per-source manifest entries
(:class:`SourceEntry`). All three are frozen + ``extra="forbid"`` so a
typo at construction site fails loudly.

Field order is alphabetical so ``model_dump_json()`` produces wire-format
output byte-identical to the pre-Pydantic ``json.dumps(..., sort_keys=True)``
behaviour — keeps the cron PR diff tractable across the refactor.

:data:`FEED_SCHEMA_VERSION` is the one authoritative schema version
string — fetchers and the CLI both import it from here so a contract
bump touches one constant rather than three.

Schema 1.1.0 adds ``description`` and ``cwes`` to :class:`FeedRow` so
consumers can filter by free-text keywords and by weakness category
without re-fetching upstream. Both fields default to empty values, so
v1.0.0 callers stay valid and v1.0.0 consumers reading v1.1.0 rows see
extra keys they can safely ignore.

Schema 1.2.0 adds CPE-derived ``vendors`` and filter-derived
``keywords_matched`` to :class:`FeedRow`. ``vendors`` carries
authoritative product-affiliation signal that text-based filtering
can't (e.g. ``cpe:2.3:a:python:python:*`` vs ``cpe:2.3:a:tautulli:*``).
``keywords_matched`` is the subset of the producer's configured
``settings.keywords`` that matched a row's ``id + description``, so
downstream consumers see an audit trail for filter hits. Both fields
default ``[]`` so prior callers stay valid; the
``keywords_matched`` semantic is per-producer-run and distinct from
the eval-side ``matched_keywords`` field on C2 (which reflects
``stack_keywords`` matches against ``refs``).

Schema 1.3.0 adds the ``ghsa`` source slug (GitHub Security Advisories). No
new field is introduced — the advisory's ``html_url`` rides in ``refs`` as the
required CC-BY 4.0 per-record attribution. The bump signals the new ``source``
value so consumers that switch on ``source`` know to expect it.
"""

from __future__ import annotations

from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

FEED_SCHEMA_VERSION: Final[str] = "1.3.0"

Severity = Literal["critical", "high", "medium", "low", "unknown"]
SourceSlug = Literal["nvd", "cisa-kev", "ghsa"]


class SourceEntry(BaseModel):
    """One entry in :class:`FeedMeta.sources` — licence + attribution per source."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    attribution: str
    id: SourceSlug
    license: str
    name: str
    url: str


class FeedRow(BaseModel):
    """One row of ``data/feed.jsonl`` — the C1 contract row shape.

    ``strict=False`` (default) so NVD's occasional integer ``baseScore``
    coerces to float cleanly; range constraints still hold.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    cvss: Annotated[float, Field(ge=0.0, le=10.0)] | None
    cwes: list[str] = []
    description: str = ""
    epss: Annotated[float, Field(ge=0.0, le=1.0)] | None
    id: str
    kev: bool
    keywords_matched: list[str] = []
    published: str  # ISO-8601 Z UTC
    refs: Annotated[list[str], Field(min_length=1)]
    schema_version: str = FEED_SCHEMA_VERSION
    severity: Severity
    source: SourceSlug
    vendors: list[str] = []


class FeedMeta(BaseModel):
    """Payload of ``data/feed-meta.json`` — sidecar metadata for the C1 feed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    item_count: Annotated[int, Field(ge=0)]
    last_run: str  # ISO-8601 Z UTC
    schema_version: str
    sources: list[SourceEntry]
    tool_version: str

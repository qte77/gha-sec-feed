"""Pydantic-settings ``AppSettings`` — env-driven deployment knobs.

The producer reads all per-deployment configuration from env vars at
process start. ``GSF_*``-prefixed vars cover producer-specific knobs
(timeout, retries, output dir); the upstream-defined ``NVD_API_KEY``
is the one exception kept unprefixed to match NIST's documented name.

Security-critical invariants (`_ALLOWED_HOSTS`, retry status codes,
backoff math) intentionally live as code constants in
:mod:`gha_sec_feed.http`. An env var that adds an outbound host or
silences retry policy would be exactly the threat the allowlist
defends against — not negotiable per deployment.

Construct via :func:`settings`. The singleton is created lazily on
first call so importing this module never touches the environment
(important for tests that monkeypatch env vars after import).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from secrets import choice
from typing import Annotated, Any

from pydantic import BeforeValidator, Field, SecretStr
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from gha_sec_feed import __version__
from gha_sec_feed.models import Severity

# Curated list of top desktop browser User-Agent strings (Chrome /
# Firefox / Safari / Edge on Windows / macOS / Linux), per
# https://www.useragents.me top entries. NVD is behind Cloudflare,
# which fingerprints non-browser User-Agents and silently 404s
# requests after a small number of failures from the same UA value.
# Defaulting to a random pick from a real-browser pool sidesteps
# that heuristic without needing an NVD API key.
_BROWSER_UAS: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
)


def _random_browser_ua() -> str:
    """Pick a random recent browser UA from :data:`_BROWSER_UAS`."""
    return choice(_BROWSER_UAS)


def _parse_csv(value: Any) -> Any:
    """Parse a CSV string into a list, stripping whitespace and empties.

    The workflow_call surface passes inputs as plain strings, so list
    knobs accept ``"github,docker"`` rather than the default
    pydantic-settings JSON form ``'["github","docker"]'``. ``NoDecode``
    on the type alias suppresses pydantic-settings' eager JSON parse so
    the raw env string reaches this validator unchanged.
    """
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


_CsvList = Annotated[list[str], NoDecode, BeforeValidator(_parse_csv)]


class AppSettings(BaseSettings):
    """Producer deployment knobs read from env vars."""

    model_config = SettingsConfigDict(
        env_prefix="GSF_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    nvd_api_key: SecretStr | None = Field(
        default=None,
        alias="NVD_API_KEY",
        description=(
            "Optional NVD API key. Raises rate limit from 5/30s to 50/30s. "
            "See https://nvd.nist.gov/developers/request-an-api-key"
        ),
    )

    out_dir: Path = Field(
        default=Path("./data"),
        description="Output directory for feed.jsonl and feed-meta.json.",
    )

    since_days: int = Field(
        default=7,
        ge=1,
        le=120,
        description="Default lower-bound publication window in days.",
    )

    http_timeout: float = Field(
        default=30.0,
        gt=0.0,
        description="Per-request HTTP timeout in seconds.",
    )

    http_max_retries: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Number of attempts before raising RuntimeError.",
    )

    user_agent: str = Field(
        default_factory=_random_browser_ua,
        description=(
            "Outbound User-Agent. Default picks a random recent browser UA "
            "from a curated list to avoid CDN bot-detection heuristics — "
            "NVD's Cloudflare layer silently 404s requests after a small "
            "number of failures from the same non-browser UA value. Carries "
            "no project identity; forks override via GSF_USER_AGENT."
        ),
    )

    severity_min: Severity = Field(
        default="unknown",
        description=(
            "Minimum severity rank admitted by the filter. Default 'unknown' "
            "is the no-filter sentinel (every row passes the severity check)."
        ),
    )

    kev_only: bool = Field(
        default=False,
        description="If true, keep only rows with kev=True; default keeps every row.",
    )

    cwe_include: _CsvList = Field(
        default_factory=list,
        description=(
            "CSV list of CWE identifiers; a row passes if it shares at least "
            "one CWE (case-insensitive). Empty list = no CWE filter."
        ),
    )

    vendor_include: _CsvList = Field(
        default_factory=list,
        description=(
            "CSV list of CPE-derived vendor names; a row passes if it shares "
            "at least one vendor (case-insensitive). Empty list = no vendor "
            "filter. KEV rows have empty `vendors` by default and are "
            "rejected when this filter is set — use `kev_only` for an "
            "orthogonal KEV-keeping path."
        ),
    )

    keywords: _CsvList = Field(
        default_factory=list,
        description=(
            "CSV list of keywords matched case-insensitively against id + "
            "description. Empty list = no keyword filter."
        ),
    )


@lru_cache(maxsize=1)
def settings() -> AppSettings:
    """Return the lazily-constructed :class:`AppSettings` singleton."""
    return AppSettings()  # pyright: ignore[reportCallIssue]


def reset_settings_cache() -> None:
    """Drop the cached settings instance. Tests use this after env mutation."""
    settings.cache_clear()

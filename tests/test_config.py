"""Tests for ``gha_sec_feed.config`` — env-driven AppSettings."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from gha_sec_feed.config import AppSettings, reset_settings_cache, settings


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    """Wipe all settings env vars before every test and drop the cached singleton."""
    for var in (
        "NVD_API_KEY",
        "GSF_OUT_DIR",
        "GSF_SINCE_DAYS",
        "GSF_HTTP_TIMEOUT",
        "GSF_HTTP_MAX_RETRIES",
        "GSF_USER_AGENT",
        "GSF_SEVERITY_MIN",
        "GSF_KEV_ONLY",
        "GSF_CWE_INCLUDE",
        "GSF_KEYWORDS",
    ):
        monkeypatch.delenv(var, raising=False)
    reset_settings_cache()
    yield
    reset_settings_cache()


def test_defaults_when_no_env_vars_set():
    s = AppSettings()
    assert s.nvd_api_key is None
    assert s.out_dir == Path("./data")
    assert s.since_days == 7
    assert s.http_timeout == 30.0
    assert s.http_max_retries == 3
    # Default User-Agent: no project identity, picked from the curated
    # browser pool so CDN fingerprinting heuristics don't flag us.
    assert "gha-sec-feed" not in s.user_agent
    assert "qte77" not in s.user_agent
    assert "github.com" not in s.user_agent
    assert s.user_agent.startswith("Mozilla/5.0")


def test_user_agent_default_factory_picks_from_curated_pool():
    # The factory must return one of the declared browser UAs (no string
    # constructed from elsewhere) — catches silently-introduced template
    # interpolation or trimming of the pool.
    from gha_sec_feed.config import _BROWSER_UAS

    sampled = {AppSettings().user_agent for _ in range(50)}
    assert sampled <= set(_BROWSER_UAS)
    # Pool has > 1 distinct entry — verify randomisation is actually
    # giving us variety across 50 samples (probability of getting only
    # 1 distinct value out of 7 in 50 picks is ~7 * (1/7)^49 ≈ 0).
    assert len(sampled) > 1


def test_nvd_api_key_read_from_unprefixed_env_var(monkeypatch: pytest.MonkeyPatch):
    # Matches NIST's documented env var name; does NOT take the GSF_ prefix.
    monkeypatch.setenv("NVD_API_KEY", "secret-123")
    s = AppSettings()
    assert isinstance(s.nvd_api_key, SecretStr)
    assert s.nvd_api_key.get_secret_value() == "secret-123"


def test_prefixed_env_vars_override_defaults(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    out_dir = tmp_path / "feed"
    monkeypatch.setenv("GSF_SINCE_DAYS", "14")
    monkeypatch.setenv("GSF_HTTP_TIMEOUT", "60")
    monkeypatch.setenv("GSF_HTTP_MAX_RETRIES", "5")
    monkeypatch.setenv("GSF_USER_AGENT", "my-fork/2.0 (+https://example.com)")
    monkeypatch.setenv("GSF_OUT_DIR", str(out_dir))

    s = AppSettings()
    assert s.since_days == 14
    assert s.http_timeout == 60.0
    assert s.http_max_retries == 5
    assert s.user_agent == "my-fork/2.0 (+https://example.com)"
    assert s.out_dir == out_dir


def test_since_days_out_of_range_rejected(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GSF_SINCE_DAYS", "0")
    with pytest.raises(ValidationError, match="since_days"):
        AppSettings()


def test_http_max_retries_above_ten_rejected(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GSF_HTTP_MAX_RETRIES", "11")
    with pytest.raises(ValidationError, match="http_max_retries"):
        AppSettings()


def test_http_timeout_must_be_positive(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GSF_HTTP_TIMEOUT", "0")
    with pytest.raises(ValidationError, match="http_timeout"):
        AppSettings()


def test_settings_returns_cached_singleton():
    first = settings()
    second = settings()
    assert first is second


def test_reset_settings_cache_picks_up_env_changes(monkeypatch: pytest.MonkeyPatch):
    first = settings()
    assert first.since_days == 7

    monkeypatch.setenv("GSF_SINCE_DAYS", "30")
    reset_settings_cache()
    second = settings()
    assert second.since_days == 30
    assert first is not second


def test_app_settings_is_frozen():
    s = AppSettings()
    with pytest.raises(ValidationError, match="frozen"):
        s.since_days = 14


def test_filter_knobs_default_to_no_filter():
    # Producer-is-neutral default: a deployment that sets no filter env
    # vars gets the full feed (preserving v0.1.0 behaviour). Catches an
    # accidental tightening of any default.
    s = AppSettings()
    assert s.severity_min == "unknown"
    assert s.kev_only is False
    assert s.cwe_include == []
    assert s.keywords == []


def test_filter_knobs_parsed_from_env_vars(monkeypatch: pytest.MonkeyPatch):
    # The workflow_call surface passes inputs as plain strings, so CSV
    # parsing must work for the list-typed knobs. Catches the default
    # pydantic-settings behaviour of requiring JSON for list[str].
    monkeypatch.setenv("GSF_SEVERITY_MIN", "high")
    monkeypatch.setenv("GSF_KEV_ONLY", "true")
    monkeypatch.setenv("GSF_CWE_INCLUDE", "CWE-79,CWE-200")
    monkeypatch.setenv("GSF_KEYWORDS", "github,docker,rust")

    s = AppSettings()
    assert s.severity_min == "high"
    assert s.kev_only is True
    assert s.cwe_include == ["CWE-79", "CWE-200"]
    assert s.keywords == ["github", "docker", "rust"]


def test_keywords_csv_strips_whitespace_and_drops_empty_segments(
    monkeypatch: pytest.MonkeyPatch,
):
    # Workflow YAML may emit `keywords: "github, docker , "` after YAML
    # input templating; the parser must normalise. Catches a naive
    # `str.split(",")` impl that leaves whitespace and empty entries.
    monkeypatch.setenv("GSF_KEYWORDS", "github, docker ,, rust ,")
    s = AppSettings()
    assert s.keywords == ["github", "docker", "rust"]


def test_severity_min_rejects_invalid_literal(monkeypatch: pytest.MonkeyPatch):
    # Catches accidentally widening the Literal type or omitting it.
    monkeypatch.setenv("GSF_SEVERITY_MIN", "catastrophic")
    with pytest.raises(ValidationError, match="severity_min"):
        AppSettings()

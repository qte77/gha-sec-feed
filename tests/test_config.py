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
    assert "gha-sec-feed/" in s.user_agent
    assert "github.com/qte77/gha-sec-feed" in s.user_agent


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

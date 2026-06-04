"""Tests for ``gha_sec_feed.http`` — egress allowlist + identity headers + retry."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from gha_sec_feed import http
from gha_sec_feed.config import reset_settings_cache
from gha_sec_feed.http import _validate_url, get

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@pytest.fixture(autouse=True)
def _clean_settings(monkeypatch: pytest.MonkeyPatch):
    """Clear env vars + cached AppSettings before every test."""
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


def _mock(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


# ---------- URL validation -------------------------------------------------


def test_validate_allows_nvd_host():
    _validate_url(NVD_URL)


def test_validate_allows_cisa_host():
    _validate_url(KEV_URL)


def test_validate_rejects_disallowed_host():
    with pytest.raises(ValueError, match="[Aa]llowlist"):
        _validate_url("https://evil.example.com/exfil")


def test_validate_rejects_http_scheme():
    with pytest.raises(ValueError, match="HTTPS"):
        _validate_url("http://services.nvd.nist.gov/rest/json/cves/2.0")


def test_validate_rejects_non_443_port():
    with pytest.raises(ValueError, match="port"):
        _validate_url("https://services.nvd.nist.gov:8080/rest/json/cves/2.0")


def test_validate_rejects_userinfo():
    with pytest.raises(ValueError, match="[Uu]serinfo"):
        _validate_url("https://user:pass@services.nvd.nist.gov/rest/json/cves/2.0")


# ---------- get(): happy path + headers -----------------------------------


def test_get_returns_response_body():
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"hello")

    assert get(NVD_URL, _transport=_mock(handler)) == b"hello"


def test_get_injects_default_identity_user_agent():
    captured: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured.update(req.headers)
        return httpx.Response(200, content=b"")

    get(NVD_URL, _transport=_mock(handler))
    ua = captured["user-agent"]
    assert "gha-sec-feed/" in ua
    assert "github.com/qte77/gha-sec-feed" in ua


def test_get_user_agent_from_settings_env_override(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GSF_USER_AGENT", "my-fork/2.0 (+https://example.com)")
    reset_settings_cache()
    captured: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured.update(req.headers)
        return httpx.Response(200, content=b"")

    get(NVD_URL, _transport=_mock(handler))
    assert captured["user-agent"] == "my-fork/2.0 (+https://example.com)"


def test_get_preserves_caller_user_agent_case_insensitive():
    captured: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured.update(req.headers)
        return httpx.Response(200, content=b"")

    get(NVD_URL, headers={"user-agent": "my-tool/1.0"}, _transport=_mock(handler))
    assert captured["user-agent"] == "my-tool/1.0"


def test_get_injects_default_accept_json():
    captured: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured.update(req.headers)
        return httpx.Response(200, content=b"")

    get(NVD_URL, _transport=_mock(handler))
    assert captured["accept"] == "application/json"


def test_get_injects_default_referer():
    captured: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured.update(req.headers)
        return httpx.Response(200, content=b"")

    get(NVD_URL, _transport=_mock(handler))
    assert captured["referer"] == "https://github.com/qte77/gha-sec-feed"


def test_get_preserves_caller_referer():
    captured: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured.update(req.headers)
        return httpx.Response(200, content=b"")

    get(
        NVD_URL,
        headers={"Referer": "https://custom.example/"},
        _transport=_mock(handler),
    )
    assert captured["referer"] == "https://custom.example/"


def test_get_injects_apikey_for_nvd_when_env_set(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("NVD_API_KEY", "secret-123")
    reset_settings_cache()
    captured: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured.update(req.headers)
        return httpx.Response(200, content=b"")

    get(NVD_URL, _transport=_mock(handler))
    assert captured["apikey"] == "secret-123"


def test_get_does_not_inject_apikey_for_non_nvd_host(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("NVD_API_KEY", "secret-123")
    reset_settings_cache()
    captured: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured.update(req.headers)
        return httpx.Response(200, content=b"")

    get(KEV_URL, _transport=_mock(handler))
    assert "apikey" not in (k.lower() for k in captured)


def test_get_does_not_inject_apikey_when_env_unset():
    captured: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured.update(req.headers)
        return httpx.Response(200, content=b"")

    get(NVD_URL, _transport=_mock(handler))
    assert "apikey" not in (k.lower() for k in captured)


# ---------- retry behavior -------------------------------------------------


def test_get_honors_retry_after_on_429(monkeypatch: pytest.MonkeyPatch):
    slept: list[float] = []
    monkeypatch.setattr(http, "_sleep", slept.append)
    calls = {"n": 0}

    def handler(_req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "7"})
        return httpx.Response(200, content=b"ok")

    assert get(NVD_URL, _transport=_mock(handler)) == b"ok"
    assert slept == [7.0]


def test_get_uses_exponential_backoff_on_429_without_retry_after(
    monkeypatch: pytest.MonkeyPatch,
):
    slept: list[float] = []
    monkeypatch.setattr(http, "_sleep", slept.append)
    calls = {"n": 0}

    def handler(_req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(429)
        return httpx.Response(200, content=b"ok")

    assert get(NVD_URL, _transport=_mock(handler)) == b"ok"
    # First retry: 0.2 * 2**0 = 0.2; second retry: 0.2 * 2**1 = 0.4
    assert slept == [0.2, 0.4]


def test_get_raises_after_max_retries_exhausted(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(http, "_sleep", lambda _s: None)

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    with pytest.raises(RuntimeError, match="after 3 attempts"):
        get(NVD_URL, _transport=_mock(handler))


def test_get_max_retries_from_settings_env_override(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(http, "_sleep", lambda _s: None)
    monkeypatch.setenv("GSF_HTTP_MAX_RETRIES", "2")
    reset_settings_cache()

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    with pytest.raises(RuntimeError, match="after 2 attempts"):
        get(NVD_URL, _transport=_mock(handler))


def test_get_raises_immediately_on_non_retryable_4xx():
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(400)

    with pytest.raises(RuntimeError, match="400"):
        get(NVD_URL, _transport=_mock(handler))

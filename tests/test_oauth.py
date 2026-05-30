"""Tests for the OAuth2 refresh-token helper (no network)."""

from __future__ import annotations

import pytest

from icloud_calendar_manager.exceptions import AuthenticationError, ConfigurationError
from icloud_calendar_manager.oauth import (
    OAuthRefreshConfig,
    TokenProvider,
    oauth_config_from_env,
    refresh_access_token,
)


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def make_post(response, recorder=None):
    def _post(url, data):
        if recorder is not None:
            recorder.append((url, data))
        return response
    return _post


def test_oauth_config_from_env_google(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("GOOGLE_REFRESH_TOKEN", "rtoken")
    cfg = oauth_config_from_env("google")
    assert cfg is not None
    assert cfg.client_id == "cid"
    assert cfg.refresh_token == "rtoken"
    assert cfg.token_url.endswith("googleapis.com/token")


def test_oauth_config_microsoft_tenant(monkeypatch):
    monkeypatch.setenv("MICROSOFT_CLIENT_ID", "cid")
    monkeypatch.setenv("MICROSOFT_REFRESH_TOKEN", "rtoken")
    monkeypatch.setenv("MICROSOFT_TENANT", "contoso")
    cfg = oauth_config_from_env("microsoft")
    assert "contoso" in cfg.token_url


def test_oauth_config_none_without_refresh_token(monkeypatch):
    for var in ("GOOGLE_REFRESH_TOKEN", "OAUTH_REFRESH_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    assert oauth_config_from_env("google") is None


def test_oauth_config_missing_client_id_raises(monkeypatch):
    for var in ("GOOGLE_CLIENT_ID", "OAUTH_CLIENT_ID"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(ConfigurationError):
        oauth_config_from_env("google", refresh_token="rtoken")


def test_refresh_access_token_success():
    recorder = []
    post = make_post(FakeResponse(200, {"access_token": "fresh-token", "expires_in": 3600}), recorder)
    cfg = OAuthRefreshConfig(
        client_id="cid", client_secret="sec", refresh_token="rt",
        token_url="https://example/token",
    )
    token = refresh_access_token(cfg, post=post)
    assert token == "fresh-token"
    # Verify the grant payload.
    url, data = recorder[0]
    assert url == "https://example/token"
    assert data["grant_type"] == "refresh_token"
    assert data["refresh_token"] == "rt"
    assert data["client_id"] == "cid"
    assert data["client_secret"] == "sec"


def test_refresh_access_token_failure_raises():
    post = make_post(FakeResponse(400, {"error": "invalid_grant", "error_description": "bad"}))
    cfg = OAuthRefreshConfig(
        client_id="cid", client_secret=None, refresh_token="rt",
        token_url="https://example/token",
    )
    with pytest.raises(AuthenticationError) as exc:
        refresh_access_token(cfg, post=post)
    assert "bad" in str(exc.value)


def test_token_provider_static_token():
    tp = TokenProvider(access_token="static")
    assert tp.token() == "static"


def test_token_provider_refreshes_and_caches():
    calls = []

    def post(url, data):
        calls.append(data)
        return FakeResponse(200, {"access_token": f"token-{len(calls)}"})

    clock = [1000.0]
    cfg = OAuthRefreshConfig(
        client_id="cid", client_secret=None, refresh_token="rt",
        token_url="https://example/token",
    )
    tp = TokenProvider(refresh=cfg, post=post, clock=lambda: clock[0])
    first = tp.token()
    assert first == "token-1"
    # Cached within the expiry window: no new call.
    assert tp.token() == "token-1"
    assert len(calls) == 1
    # Advance past expiry: a refresh happens.
    clock[0] += 4000
    assert tp.token() == "token-2"
    assert len(calls) == 2


def test_token_provider_requires_something():
    with pytest.raises(ConfigurationError):
        TokenProvider()


def test_oauth_config_repr_hides_secrets():
    cfg = OAuthRefreshConfig(
        client_id="cid", client_secret="SECRET", refresh_token="REFRESH",
        token_url="https://example/token",
    )
    text = repr(cfg)
    assert "SECRET" not in text
    assert "REFRESH" not in text

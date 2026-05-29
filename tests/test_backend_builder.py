"""Tests for build_backend wiring: provider -> backend + OAuth refresh."""

from __future__ import annotations

from icloud_calendar_manager.backends import (
    CalDAVBackend,
    GoogleBackend,
    GraphBackend,
    build_backend,
    resolve_bearer_token,
)
from icloud_calendar_manager.config import resolve_auth
from icloud_calendar_manager.oauth import OAuthRefreshConfig


def test_build_caldav_backend_for_fastmail():
    auth = resolve_auth("fastmail", username="me@fastmail.com", secret="pw")
    backend = build_backend(auth)
    assert isinstance(backend, CalDAVBackend)


def test_build_graph_backend_for_microsoft():
    auth = resolve_auth("microsoft", secret="graph-token")
    # Inject a dummy session so no real GraphTransport/requests is constructed.
    backend = build_backend(auth, session=object())
    assert isinstance(backend, GraphBackend)


def test_build_google_backend_is_composite():
    auth = resolve_auth("google", username="me@gmail.com", secret="token")
    backend = build_backend(auth, session=object())
    assert isinstance(backend, GoogleBackend)


def test_resolve_bearer_token_uses_static_secret():
    auth = resolve_auth("microsoft", secret="static-token")
    assert resolve_bearer_token(auth) == "static-token"


def test_resolve_bearer_token_uses_oauth_refresh():
    auth = resolve_auth("microsoft", secret="", allow_missing_secret=True)
    cfg = OAuthRefreshConfig(
        client_id="cid", client_secret=None, refresh_token="rt",
        token_url="https://example/token",
    )

    class _Resp:
        status_code = 200

        def json(self):
            return {"access_token": "minted-token"}

    token = resolve_bearer_token(auth, oauth=cfg, post=lambda url, data: _Resp())
    assert token == "minted-token"


def test_allow_missing_secret_lets_google_build_with_refresh_only():
    # No access token, but a refresh config will mint one lazily.
    auth = resolve_auth("google", username="me@gmail.com", allow_missing_secret=True)
    assert auth.secret == ""
    backend = build_backend(auth, session=object())
    assert isinstance(backend, GoogleBackend)

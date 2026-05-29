"""Tests for the provider registry and multi-provider auth resolution."""

from __future__ import annotations

import pytest

from icloud_calendar_manager.config import resolve_auth
from icloud_calendar_manager.exceptions import ConfigurationError
from icloud_calendar_manager.providers import (
    BACKEND_CALDAV,
    BACKEND_GRAPH,
    DEFAULT_PROVIDER,
    PROVIDERS,
    get_provider,
)


def test_default_provider_is_icloud():
    assert DEFAULT_PROVIDER == "icloud"
    assert get_provider("icloud").backend == BACKEND_CALDAV


def test_all_expected_providers_registered():
    assert set(PROVIDERS) == {"icloud", "fastmail", "yahoo", "google", "microsoft", "generic"}


def test_microsoft_uses_graph_backend():
    assert get_provider("microsoft").backend == BACKEND_GRAPH


def test_unknown_provider_raises():
    with pytest.raises(KeyError) as exc:
        get_provider("nope")
    assert "Unknown provider" in str(exc.value)


def test_resolve_fastmail_basic(monkeypatch):
    monkeypatch.delenv("CALENDAR_USERNAME", raising=False)
    auth = resolve_auth("fastmail", username="me@fastmail.com", secret="app-pw")
    assert auth.auth_scheme == "basic"
    assert auth.url == "https://caldav.fastmail.com/dav/"
    assert auth.username == "me@fastmail.com"
    assert auth.secret == "app-pw"


def test_resolve_google_bearer():
    auth = resolve_auth("google", username="me@gmail.com", secret="ya29.token")
    assert auth.auth_scheme == "bearer"
    assert auth.backend == "caldav"
    assert auth.provider.supports_reminders is False


def test_resolve_microsoft_bearer_no_username():
    auth = resolve_auth("microsoft", secret="graph-token")
    assert auth.auth_scheme == "bearer"
    assert auth.backend == "graph"
    assert auth.username is None  # Graph derives identity from the token


def test_generic_requires_url():
    with pytest.raises(ConfigurationError) as exc:
        resolve_auth("generic", username="u", secret="p")
    assert "URL" in str(exc.value)


def test_generic_with_url_ok():
    auth = resolve_auth("generic", url="https://dav.example.com/", username="u", secret="p")
    assert auth.url == "https://dav.example.com/"


def test_missing_secret_message_mentions_token_for_bearer():
    with pytest.raises(ConfigurationError) as exc:
        resolve_auth("microsoft")
    assert "token" in str(exc.value).lower()


def test_provider_env_aliases(monkeypatch):
    monkeypatch.setenv("FASTMAIL_USERNAME", "env@fastmail.com")
    monkeypatch.setenv("FASTMAIL_PASSWORD", "env-pw")
    auth = resolve_auth("fastmail")
    assert auth.username == "env@fastmail.com"
    assert auth.secret == "env-pw"


def test_generic_env_vars(monkeypatch):
    monkeypatch.setenv("CALDAV_URL", "https://dav.example.org/")
    monkeypatch.setenv("CALENDAR_USERNAME", "alice")
    monkeypatch.setenv("CALENDAR_PASSWORD", "secret")
    auth = resolve_auth("generic")
    assert auth.url == "https://dav.example.org/"
    assert auth.username == "alice"
    assert auth.secret == "secret"


def test_explicit_args_override_env(monkeypatch):
    monkeypatch.setenv("FASTMAIL_USERNAME", "env@fastmail.com")
    monkeypatch.setenv("FASTMAIL_PASSWORD", "env-pw")
    auth = resolve_auth("fastmail", username="explicit@fastmail.com")
    assert auth.username == "explicit@fastmail.com"
    assert auth.secret == "env-pw"


def test_authconfig_repr_hides_secret():
    auth = resolve_auth("fastmail", username="u@fastmail.com", secret="TOPSECRET")
    assert "TOPSECRET" not in repr(auth)
    assert "***" in repr(auth)

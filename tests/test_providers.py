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
    resolve_provider_url,
    well_known_url,
)


def test_default_provider_is_icloud():
    assert DEFAULT_PROVIDER == "icloud"
    assert get_provider("icloud").backend == BACKEND_CALDAV


def test_all_expected_providers_registered():
    # Hosted services, self-hosted open-source servers, and the generic escape hatch.
    expected = {
        "icloud", "fastmail", "yahoo", "posteo", "mailbox", "gmx",
        "google", "microsoft",
        "nextcloud", "owncloud", "radicale", "baikal", "sogo", "davical",
        "zimbra", "synology", "vikunja",
        "generic",
    }
    assert set(PROVIDERS) == expected


def test_microsoft_uses_graph_backend():
    assert get_provider("microsoft").backend == BACKEND_GRAPH


def test_self_hosted_providers_require_url():
    # Self-hosted servers have no fixed host; base_url is None until --url given.
    for key in ("nextcloud", "radicale", "baikal", "sogo", "davical", "vikunja", "generic"):
        assert get_provider(key).base_url is None
        assert get_provider(key).self_hosted is True


def test_resolve_provider_url_appends_path_suffix():
    nc = get_provider("nextcloud")
    assert resolve_provider_url(nc, "https://cloud.example.com") == (
        "https://cloud.example.com/remote.php/dav"
    )
    # Trailing slash is normalized.
    assert resolve_provider_url(nc, "https://cloud.example.com/") == (
        "https://cloud.example.com/remote.php/dav"
    )


def test_resolve_provider_url_does_not_double_append():
    nc = get_provider("nextcloud")
    already = "https://cloud.example.com/remote.php/dav/"
    assert resolve_provider_url(nc, already) == "https://cloud.example.com/remote.php/dav"


def test_resolve_provider_url_uses_base_when_no_url():
    icloud = get_provider("icloud")
    assert resolve_provider_url(icloud, None) == "https://caldav.icloud.com"


def test_resolve_provider_url_no_suffix_provider():
    radicale = get_provider("radicale")  # no path_suffix
    assert resolve_provider_url(radicale, "https://r.example.com/dav") == (
        "https://r.example.com/dav"
    )


def test_well_known_url_derivation():
    assert well_known_url("https://cloud.example.com/remote.php/dav") == (
        "https://cloud.example.com/.well-known/caldav"
    )
    # Bare host without scheme defaults to https.
    assert well_known_url("cloud.example.com") == "https://cloud.example.com/.well-known/caldav"


def test_vikunja_is_tasks_only():
    vikunja = get_provider("vikunja")
    assert vikunja.supports_events is False
    assert vikunja.supports_reminders is True


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
    # Google now supports reminders via the Google Tasks API (composite backend).
    assert auth.provider.supports_reminders is True


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
    # A trailing slash on the supplied URL is normalized away.
    assert auth.url == "https://dav.example.com"


def test_resolve_auth_applies_nextcloud_path_suffix():
    # resolve_auth should combine the bare host with the provider's preset path.
    auth = resolve_auth("nextcloud", url="https://cloud.example.com", username="u", secret="pw")
    assert auth.url == "https://cloud.example.com/remote.php/dav"


def test_resolve_auth_baikal_suffix():
    auth = resolve_auth("baikal", url="https://dav.example.com", username="u", secret="pw")
    assert auth.url == "https://dav.example.com/dav.php"


def test_resolve_auth_nextcloud_requires_url():
    # Self-hosted providers have no default host; a URL is mandatory.
    with pytest.raises(ConfigurationError) as exc:
        resolve_auth("nextcloud", username="u", secret="pw")
    assert "URL" in str(exc.value)


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
    assert auth.url == "https://dav.example.org"  # trailing slash normalized
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

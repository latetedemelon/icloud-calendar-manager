"""Tests for client construction, endpoint caching and error mapping."""

from __future__ import annotations

import caldav
import pytest

from icloud_calendar_manager.client import (
    EndpointCache,
    build_client,
    get_principal,
    partition_base_url,
)
from icloud_calendar_manager.config import DEFAULT_CALDAV_URL, Credentials
from icloud_calendar_manager.exceptions import AuthenticationError
from icloud_calendar_manager.exceptions import ConnectionError as ICloudConnectionError


def test_endpoint_cache_round_trip(tmp_path):
    cache = EndpointCache(str(tmp_path / "endpoint.json"))
    assert cache.load() is None
    cache.save("https://p9-caldav.icloud.com")
    assert cache.load() == "https://p9-caldav.icloud.com"


def test_endpoint_cache_bare_filename(tmp_path, monkeypatch):
    # The original implementation crashed on a filename with no directory.
    monkeypatch.chdir(tmp_path)
    cache = EndpointCache("endpoint.json")
    cache.save("https://p1-caldav.icloud.com")
    assert cache.load() == "https://p1-caldav.icloud.com"


def test_endpoint_cache_ignores_corrupt_file(tmp_path):
    path = tmp_path / "endpoint.json"
    path.write_text("not json {{{")
    cache = EndpointCache(str(path))
    assert cache.load() is None


def test_build_client_prefers_cache(tmp_path):
    cache = EndpointCache(str(tmp_path / "endpoint.json"))
    cache.save("https://p5-caldav.icloud.com")
    creds = Credentials("me@example.com", "pw")
    client = build_client(creds, cache=cache)
    assert "p5-caldav.icloud.com" in str(client.url)


def test_build_client_defaults_to_generic_host():
    creds = Credentials("me@example.com", "pw")
    client = build_client(creds)
    assert str(client.url).startswith(DEFAULT_CALDAV_URL)


class _Cal:
    def __init__(self, url):
        self.url = url


class _Principal:
    def __init__(self, calendars):
        self._calendars = calendars

    def calendars(self):
        return self._calendars


def test_partition_base_url_derivation():
    principal = _Principal([_Cal("https://p33-caldav.icloud.com/99/calendars/home/")])
    assert partition_base_url(principal) == "https://p33-caldav.icloud.com"


def test_partition_base_url_handles_no_calendars():
    assert partition_base_url(_Principal([])) is None


class _AuthFailClient:
    def principal(self):
        raise caldav.lib.error.AuthorizationError()


class _ConnFailClient:
    def principal(self):
        raise OSError("name resolution failed")


def test_get_principal_maps_authorization_error():
    with pytest.raises(AuthenticationError):
        get_principal(_AuthFailClient())


def test_get_principal_maps_connection_error():
    with pytest.raises(ICloudConnectionError):
        get_principal(_ConnFailClient())

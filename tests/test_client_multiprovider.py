"""Tests for build_caldav_client choosing Basic vs Bearer auth."""

from __future__ import annotations

from icloud_calendar_manager.client import build_caldav_client


def test_basic_auth_client_sets_username():
    client = build_caldav_client(
        url="https://caldav.fastmail.com/dav/",
        auth_scheme="basic",
        username="me@fastmail.com",
        secret="app-pw",
    )
    assert client.username == "me@fastmail.com"
    assert "fastmail.com" in str(client.url)


def test_bearer_auth_client_sets_authorization_header():
    client = build_caldav_client(
        url="https://apidata.googleusercontent.com/caldav/v2/",
        auth_scheme="bearer",
        username="me@gmail.com",
        secret="ya29.token",
    )
    headers = client.headers or {}
    assert headers.get("Authorization") == "Bearer ya29.token"
    # Bearer mode must not send a basic-auth password.
    assert not client.password


def test_bearer_client_url_is_google():
    client = build_caldav_client(
        url="https://apidata.googleusercontent.com/caldav/v2/",
        auth_scheme="bearer",
        secret="tok",
    )
    assert "googleusercontent.com" in str(client.url)

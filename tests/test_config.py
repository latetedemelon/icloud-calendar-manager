"""Tests for credential/config resolution."""

from __future__ import annotations

import pytest

from icloud_calendar_manager.config import Credentials
from icloud_calendar_manager.exceptions import ConfigurationError


def test_from_env_uses_explicit_arguments(monkeypatch):
    monkeypatch.delenv("APPLE_ID", raising=False)
    monkeypatch.delenv("APPLE_PASSWORD", raising=False)
    creds = Credentials.from_env("me@example.com", "abcd-efgh-ijkl-mnop")
    assert creds.apple_id == "me@example.com"
    assert creds.app_password == "abcd-efgh-ijkl-mnop"


def test_from_env_reads_environment(monkeypatch):
    monkeypatch.setenv("APPLE_ID", "env@example.com")
    monkeypatch.setenv("APPLE_PASSWORD", "secret-pass")
    creds = Credentials.from_env()
    assert creds.apple_id == "env@example.com"
    assert creds.app_password == "secret-pass"


def test_explicit_argument_overrides_environment(monkeypatch):
    monkeypatch.setenv("APPLE_ID", "env@example.com")
    monkeypatch.setenv("APPLE_PASSWORD", "secret-pass")
    creds = Credentials.from_env(apple_id="override@example.com")
    assert creds.apple_id == "override@example.com"
    assert creds.app_password == "secret-pass"


def test_missing_credentials_raise(monkeypatch):
    monkeypatch.delenv("APPLE_ID", raising=False)
    monkeypatch.delenv("APPLE_PASSWORD", raising=False)
    with pytest.raises(ConfigurationError) as exc:
        Credentials.from_env()
    assert "APPLE_ID" in str(exc.value)
    assert "APPLE_PASSWORD" in str(exc.value)


def test_repr_hides_password():
    creds = Credentials("me@example.com", "super-secret")
    text = repr(creds)
    assert "super-secret" not in text
    assert "me@example.com" in text

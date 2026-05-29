"""Tests for the backwards-compatible module-level helper functions."""

from __future__ import annotations

import datetime as dt

import pytest

import icloud_calendar_manager as icm


@pytest.fixture
def patched_default_manager(manager, monkeypatch):
    """Make the stateless module helpers use the fake-backed manager."""
    monkeypatch.setattr(icm, "_default_manager", lambda: manager)
    return manager


def test_list_calendars_helper(patched_default_manager):
    names = {c.name for c in icm.list_calendars()}
    assert names == {"Home", "Reminders"}


def test_discover_caldav_calendars_helper(patched_default_manager):
    assert {c.name for c in icm.discover_caldav_calendars()} == {"Home", "Reminders"}


def test_list_reminder_lists_helper(patched_default_manager):
    assert [c.name for c in icm.list_reminder_lists()] == ["Reminders"]


def test_add_and_get_events_helpers(patched_default_manager):
    assert icm.add_event_to_calendar(
        "Home", "Sync", dt.datetime(2026, 6, 1, 9), dt.datetime(2026, 6, 1, 10)
    ) is True
    events = icm.get_apple_calendar_events(
        "Home", dt.datetime(2026, 6, 1), dt.datetime(2026, 6, 2)
    )
    assert [e.summary for e in events] == ["Sync"]


def test_reminder_helpers(patched_default_manager):
    patched_default_manager.add_reminder("Reminders", "Call back")
    reminders = icm.get_reminders("Reminders")
    assert [r.summary for r in reminders] == ["Call back"]


def test_find_calendar_helper(principal):
    assert icm.find_calendar(principal, "Home").name == "Home"
    assert icm.find_calendar(principal, "Missing") is None

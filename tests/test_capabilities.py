"""Tests for provider capability gating (e.g. Google CalDAV has no reminders)."""

from __future__ import annotations

import datetime as dt

import pytest

from icloud_calendar_manager.exceptions import CapabilityError
from icloud_calendar_manager.manager import CalendarManager


def test_reminders_blocked_when_unsupported(principal):
    # Simulate a provider (like Google CalDAV) that doesn't expose reminders.
    manager = CalendarManager(principal=principal, supports_reminders=False)
    with pytest.raises(CapabilityError):
        manager.list_reminders("Reminders")
    with pytest.raises(CapabilityError):
        manager.add_reminder("Reminders", "x")


def test_events_still_work_when_reminders_unsupported(principal):
    manager = CalendarManager(principal=principal, supports_reminders=False)
    created = manager.add_event(
        "Home", "Mtg", dt.datetime(2026, 6, 1, 9), dt.datetime(2026, 6, 1, 10)
    )
    assert created.summary == "Mtg"


def test_events_blocked_when_unsupported(principal):
    # Simulate a tasks-only provider (like Vikunja): no events.
    manager = CalendarManager(principal=principal, supports_events=False)
    with pytest.raises(CapabilityError):
        manager.list_events("Home", dt.datetime(2026, 6, 1), dt.datetime(2026, 6, 2))
    with pytest.raises(CapabilityError):
        manager.add_event("Home", "x", dt.datetime(2026, 6, 1, 9))
    with pytest.raises(CapabilityError):
        manager.delete_event("Home", "uid")


def test_reminders_still_work_when_events_unsupported(principal):
    manager = CalendarManager(principal=principal, supports_events=False)
    created = manager.add_reminder("Reminders", "Buy milk")
    assert created.summary == "Buy milk"


def test_vikunja_provider_is_tasks_only(monkeypatch):
    # from_provider should propagate supports_events=False for Vikunja.
    monkeypatch.setenv("CALENDAR_USERNAME", "u")
    monkeypatch.setenv("CALENDAR_PASSWORD", "p")
    manager = CalendarManager.from_provider("vikunja", url="https://vikunja.example")
    assert manager._supports_events is False
    assert manager._supports_reminders is True

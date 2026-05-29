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

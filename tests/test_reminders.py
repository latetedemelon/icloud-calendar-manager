"""Tests for CalendarManager reminder (VTODO) operations."""

from __future__ import annotations

import datetime as dt

import pytest

from icloud_calendar_manager.exceptions import ObjectNotFoundError


def test_add_and_list_reminder(manager):
    created = manager.add_reminder(
        "Reminders", "Buy milk", due=dt.datetime(2026, 6, 1, 18, 0), priority=5
    )
    assert created.summary == "Buy milk"
    assert created.completed is False

    reminders = manager.list_reminders("Reminders")
    assert [r.summary for r in reminders] == ["Buy milk"]
    assert reminders[0].priority == 5


def test_complete_reminder_hides_from_default_list(manager):
    created = manager.add_reminder("Reminders", "Submit report")
    completed = manager.complete_reminder("Reminders", created.uid)
    assert completed.completed is True
    assert completed.status == "COMPLETED"

    # Completed reminders are hidden by default but visible with include_completed.
    assert manager.list_reminders("Reminders") == []
    all_reminders = manager.list_reminders("Reminders", include_completed=True)
    assert [r.summary for r in all_reminders] == ["Submit report"]


def test_delete_reminder(manager):
    created = manager.add_reminder("Reminders", "Temporary")
    manager.delete_reminder("Reminders", created.uid)
    assert manager.list_reminders("Reminders", include_completed=True) == []


def test_complete_missing_reminder_raises(manager):
    with pytest.raises(ObjectNotFoundError):
        manager.complete_reminder("Reminders", "nope")


def test_delete_missing_reminder_raises(manager):
    with pytest.raises(ObjectNotFoundError):
        manager.delete_reminder("Reminders", "nope")

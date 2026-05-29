"""Tests for CalendarManager event operations and calendar discovery."""

from __future__ import annotations

import datetime as dt

import pytest

from icloud_calendar_manager.exceptions import CalendarNotFoundError, ObjectNotFoundError


def test_list_calendars_and_reminder_lists(manager):
    names = {c.name for c in manager.list_calendars()}
    assert names == {"Home", "Reminders"}
    assert [c.name for c in manager.list_reminder_lists()] == ["Reminders"]
    assert [c.name for c in manager.list_calendars(include_reminder_lists=False)] == ["Home"]


def test_check_connection_counts(manager):
    info = manager.check_connection()
    assert info["calendars"] == 1
    assert info["reminder_lists"] == 1
    assert "principal" in info["principal_url"]


def test_unknown_calendar_raises(manager):
    with pytest.raises(CalendarNotFoundError):
        manager.list_events("Nope", dt.datetime(2026, 1, 1), dt.datetime(2026, 1, 2))


def test_add_and_list_event_round_trip(manager):
    created = manager.add_event(
        "Home",
        "Lunch",
        dt.datetime(2026, 6, 1, 12, 0),
        dt.datetime(2026, 6, 1, 13, 0),
        location="Cafe",
    )
    assert created.summary == "Lunch"
    assert created.uid

    events = manager.list_events("Home", dt.datetime(2026, 6, 1), dt.datetime(2026, 6, 2))
    assert len(events) == 1
    assert events[0].summary == "Lunch"
    assert events[0].location == "Cafe"


def test_list_events_filters_by_window(manager):
    manager.add_event("Home", "June", dt.datetime(2026, 6, 1, 9), dt.datetime(2026, 6, 1, 10))
    manager.add_event("Home", "August", dt.datetime(2026, 8, 1, 9), dt.datetime(2026, 8, 1, 10))
    june = manager.list_events("Home", dt.datetime(2026, 6, 1), dt.datetime(2026, 6, 30))
    assert [e.summary for e in june] == ["June"]


def test_update_event_changes_fields(manager):
    created = manager.add_event(
        "Home", "Old", dt.datetime(2026, 6, 1, 12), dt.datetime(2026, 6, 1, 13)
    )
    updated = manager.update_event("Home", created.uid, summary="New", location="Desk")
    assert updated.summary == "New"
    assert updated.location == "Desk"


def test_update_missing_event_raises(manager):
    with pytest.raises(ObjectNotFoundError):
        manager.update_event("Home", "does-not-exist", summary="x")


def test_delete_event(manager):
    created = manager.add_event(
        "Home", "Temp", dt.datetime(2026, 6, 1, 12), dt.datetime(2026, 6, 1, 13)
    )
    manager.delete_event("Home", created.uid)
    events = manager.list_events("Home", dt.datetime(2026, 6, 1), dt.datetime(2026, 6, 2))
    assert events == []


def test_delete_missing_event_raises(manager):
    with pytest.raises(ObjectNotFoundError):
        manager.delete_event("Home", "missing")

"""Tests for parsing/serialization models."""

from __future__ import annotations

import datetime as dt

import icalendar

from icloud_calendar_manager.models import CalendarInfo, EventInfo, ReminderInfo


class _Obj:
    """Minimal object exposing ``icalendar_component`` and ``url``."""

    def __init__(self, component, url="https://example/obj.ics"):
        self.icalendar_component = component
        self.url = url


def _event_component(**kwargs):
    ev = icalendar.Event()
    for key, value in kwargs.items():
        ev.add(key, value)
    return ev


def test_event_info_parses_timed_event():
    comp = _event_component(
        uid="evt-1",
        summary="Standup",
        dtstart=dt.datetime(2026, 6, 1, 9, 0),
        dtend=dt.datetime(2026, 6, 1, 9, 15),
        location="Room 1",
    )
    info = EventInfo.from_caldav_object(_Obj(comp), "Home")
    assert info.uid == "evt-1"
    assert info.summary == "Standup"
    assert info.location == "Room 1"
    assert info.all_day is False
    assert info.calendar == "Home"
    data = info.to_dict()
    assert data["start"] == "2026-06-01T09:00:00"
    assert data["end"] == "2026-06-01T09:15:00"


def test_event_info_detects_all_day():
    comp = _event_component(uid="evt-2", summary="Holiday", dtstart=dt.date(2026, 7, 4))
    info = EventInfo.from_caldav_object(_Obj(comp))
    assert info.all_day is True
    assert info.to_dict()["start"] == "2026-07-04"


def test_reminder_info_completed_detection():
    todo = icalendar.Todo()
    todo.add("uid", "todo-1")
    todo.add("summary", "Buy milk")
    todo.add("status", "COMPLETED")
    todo.add("percent-complete", 100)
    info = ReminderInfo.from_caldav_object(_Obj(todo), "Reminders")
    assert info.completed is True
    assert info.status == "COMPLETED"
    assert info.list_name == "Reminders"


def test_reminder_info_pending():
    todo = icalendar.Todo()
    todo.add("uid", "todo-2")
    todo.add("summary", "Walk dog")
    todo.add("due", dt.datetime(2026, 6, 1, 18, 0))
    info = ReminderInfo.from_caldav_object(_Obj(todo))
    assert info.completed is False
    assert info.to_dict()["due"] == "2026-06-01T18:00:00"


class _FakeCal:
    def __init__(self, name, url, components):
        self.name = name
        self.url = url
        self._components = components

    def get_supported_components(self):
        return self._components


def test_calendar_info_reminder_list_classification():
    rem = CalendarInfo.from_calendar(_FakeCal("Reminders", "https://x/rem/", ["VTODO"]))
    cal = CalendarInfo.from_calendar(_FakeCal("Home", "https://x/home/", ["VEVENT"]))
    assert rem.is_reminder_list is True
    assert cal.is_reminder_list is False
    assert rem.to_dict()["is_reminder_list"] is True

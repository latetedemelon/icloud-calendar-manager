"""Regression tests for the real ``caldav`` edit/serialize idiom.

The unit tests elsewhere use in-memory fakes. These tests instead exercise
*genuine* ``caldav`` objects (without any network) to verify the assumption the
manager relies on: accessing ``icalendar_component``, mutating it, and reading
the object back yields the updated payload that ``save()`` would PUT. If a
future ``caldav`` release changes this behavior, these tests will catch it.
"""

from __future__ import annotations

import datetime as dt

import caldav

from icloud_calendar_manager.manager import _build_vevent, _build_vtodo, _replace


def test_build_vevent_is_parseable_and_complete():
    data = _build_vevent(
        "Lunch",
        dt.datetime(2026, 6, 1, 12, 0),
        dt.datetime(2026, 6, 1, 13, 0),
        "uid-1",
        location="Cafe",
        description="Catch up",
    )
    component = caldav.Event(client=None, data=data).icalendar_component
    assert str(component.get("summary")) == "Lunch"
    assert str(component.get("uid")) == "uid-1"
    assert str(component.get("location")) == "Cafe"
    assert str(component.get("description")) == "Catch up"


def test_build_vtodo_defaults_to_needs_action():
    data = _build_vtodo("Buy milk", "todo-1", due=dt.datetime(2026, 6, 1, 18, 0), priority=5)
    component = caldav.Todo(client=None, data=data).icalendar_component
    assert str(component.get("summary")) == "Buy milk"
    assert str(component.get("status")) == "NEEDS-ACTION"
    assert int(component.get("priority")) == 5


def test_replace_persists_into_serialized_event():
    data = _build_vevent(
        "Old Title",
        dt.datetime(2026, 6, 1, 9, 0),
        dt.datetime(2026, 6, 1, 10, 0),
        "uid-2",
    )
    event = caldav.Event(client=None, data=data)
    component = event.icalendar_component
    _replace(component, "summary", "New Title")
    _replace(component, "dtstart", dt.datetime(2026, 6, 2, 11, 0))

    serialized = event.data  # what save() would send to the server
    assert "New Title" in serialized
    assert "Old Title" not in serialized
    assert "20260602T110000" in serialized


def test_complete_idiom_persists_status():
    data = _build_vtodo("Submit report", "todo-2")
    todo = caldav.Todo(client=None, data=data)
    component = todo.icalendar_component
    _replace(component, "status", "COMPLETED")
    _replace(component, "percent-complete", 100)

    serialized = todo.data
    assert "COMPLETED" in serialized
    assert "100" in serialized
    assert "NEEDS-ACTION" not in serialized

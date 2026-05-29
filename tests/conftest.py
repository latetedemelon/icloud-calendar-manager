"""Shared pytest fixtures and in-memory fakes for the CalDAV object model.

These fakes implement just enough of the ``caldav`` Calendar/Principal/object
surface that :class:`CalendarManager` uses, so the whole stack can be tested
without a network connection.
"""

from __future__ import annotations

import datetime as dt

import caldav
import icalendar
import pytest

from icloud_calendar_manager.manager import CalendarManager


def _extract_component(ical, name: str):
    cal = icalendar.Calendar.from_ical(ical)
    for component in cal.walk():
        if component.name == name:
            return component
    raise AssertionError(f"No {name} component found in iCalendar payload")


def _as_datetime(value):
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        return value
    if isinstance(value, dt.date):
        return dt.datetime(value.year, value.month, value.day)
    return None


class FakeObject:
    """Stand-in for a caldav Event/Todo resource."""

    def __init__(self, component, url, store, key):
        self._component = component
        self.url = url
        self._store = store
        self._key = key
        self.saved = False
        self.deleted = False

    @property
    def icalendar_component(self):
        return self._component

    @property
    def icalendar_instance(self):
        cal = icalendar.Calendar()
        cal.add_component(self._component)
        return cal

    @property
    def data(self):
        return self.icalendar_instance.to_ical()

    def save(self):
        self.saved = True
        return self

    def delete(self):
        self.deleted = True
        self._store.pop(self._key, None)


class FakeCalendar:
    """Stand-in for a caldav Calendar/reminder-list collection."""

    def __init__(self, name, url, components=("VEVENT", "VTODO")):
        self.name = name
        self.url = url
        self._components = list(components)
        self.events_store = {}
        self.todos_store = {}

    def get_supported_components(self):
        return list(self._components)

    def save_event(self, ical=None, **kwargs):
        component = _extract_component(ical, "VEVENT")
        uid = str(component.get("uid"))
        obj = FakeObject(component, f"{self.url}{uid}.ics", self.events_store, uid)
        self.events_store[uid] = obj
        return obj

    def save_todo(self, ical=None, **kwargs):
        component = _extract_component(ical, "VTODO")
        uid = str(component.get("uid"))
        obj = FakeObject(component, f"{self.url}{uid}.ics", self.todos_store, uid)
        self.todos_store[uid] = obj
        return obj

    def events(self):
        return list(self.events_store.values())

    def todos(self, include_completed=False, **kwargs):
        result = []
        for obj in self.todos_store.values():
            status = str(obj.icalendar_component.get("status") or "").upper()
            if not include_completed and status == "COMPLETED":
                continue
            result.append(obj)
        return result

    def search(self, start=None, end=None, event=False, todo=False, expand=False, **kwargs):
        objs = list(self.events_store.values())
        if start is None or end is None:
            return objs
        matched = []
        for obj in objs:
            raw = obj.icalendar_component.get("dtstart")
            value = _as_datetime(getattr(raw, "dt", None))
            if value is None or start <= value <= end:
                matched.append(obj)
        return matched

    def event_by_uid(self, uid):
        if uid in self.events_store:
            return self.events_store[uid]
        raise caldav.lib.error.NotFoundError(uid)

    def todo_by_uid(self, uid):
        if uid in self.todos_store:
            return self.todos_store[uid]
        raise caldav.lib.error.NotFoundError(uid)


class FakePrincipal:
    def __init__(self, calendars, url="https://p1-caldav.icloud.com/12345/principal/"):
        self._calendars = list(calendars)
        self.url = url

    def calendars(self):
        return list(self._calendars)


@pytest.fixture
def home_calendar():
    return FakeCalendar("Home", "https://p1-caldav.icloud.com/12345/calendars/home/", ["VEVENT"])


@pytest.fixture
def reminder_list():
    return FakeCalendar("Reminders", "https://p1-caldav.icloud.com/12345/calendars/rem/", ["VTODO"])


@pytest.fixture
def principal(home_calendar, reminder_list):
    return FakePrincipal([home_calendar, reminder_list])


@pytest.fixture
def manager(principal):
    return CalendarManager(principal=principal)

"""Tests for the Google Tasks backend and the composite Google backend."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest

from icloud_calendar_manager.backends.google_tasks import (
    GoogleBackend,
    GoogleTasksBackend,
)
from icloud_calendar_manager.exceptions import CalendarNotFoundError, ObjectNotFoundError
from icloud_calendar_manager.manager import CalendarManager


class FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload
        self.text = str(payload)

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeTasksTransport:
    """Minimal in-memory Google Tasks REST emulation."""

    def __init__(self):
        self.lists = {"list-1": {"id": "list-1", "title": "My Tasks"}}
        self.tasks = {}

    def request(self, method, path, *, params=None, json=None, headers=None):
        parts = [p for p in path.split("/") if p]
        if path == "/users/@me/lists" and method == "GET":
            return FakeResponse(200, {"items": list(self.lists.values())})
        if parts[:1] == ["lists"] and parts[-1] == "tasks":
            if method == "GET":
                return self._list_tasks(params)
            if method == "POST":
                return self._create(json)
        if parts[:1] == ["lists"] and "tasks" in parts and len(parts) == 4:
            return self._by_id(method, parts[3], json)
        return FakeResponse(404, {"error": {"message": f"no route {method} {path}"}})

    def _list_tasks(self, params):
        show_completed = (params or {}).get("showCompleted") == "true"
        items = []
        for t in self.tasks.values():
            if not show_completed and t.get("status") == "completed":
                continue
            items.append(t)
        return FakeResponse(200, {"items": items})

    def _create(self, body):
        tid = str(uuid.uuid4())
        resource = dict(body or {})
        resource["id"] = tid
        resource.setdefault("status", "needsAction")
        self.tasks[tid] = resource
        return FakeResponse(200, resource)

    def _by_id(self, method, tid, body):
        if tid not in self.tasks:
            return FakeResponse(404, {"error": {"message": "not found"}})
        if method == "GET":
            return FakeResponse(200, self.tasks[tid])
        if method == "PATCH":
            self.tasks[tid].update(body or {})
            return FakeResponse(200, self.tasks[tid])
        if method == "DELETE":
            del self.tasks[tid]
            return FakeResponse(204)
        return FakeResponse(405)


@pytest.fixture
def tasks_backend():
    return GoogleTasksBackend(FakeTasksTransport())


def test_list_task_lists(tasks_backend):
    lists = tasks_backend.list_task_lists()
    assert [c.name for c in lists] == ["My Tasks"]
    assert lists[0].is_reminder_list is True


def test_reminder_round_trip(tasks_backend):
    created = tasks_backend.add_reminder(
        "My Tasks", "Buy milk", due=dt.datetime(2026, 6, 1, 18, 0), description="2%"
    )
    assert created.summary == "Buy milk"
    assert created.completed is False

    listed = tasks_backend.list_reminders("My Tasks")
    assert [r.summary for r in listed] == ["Buy milk"]

    fetched = tasks_backend.get_reminder("My Tasks", created.uid)
    assert fetched.description == "2%"

    done = tasks_backend.complete_reminder("My Tasks", created.uid)
    assert done.completed is True
    assert tasks_backend.list_reminders("My Tasks") == []
    assert len(tasks_backend.list_reminders("My Tasks", include_completed=True)) == 1

    tasks_backend.delete_reminder("My Tasks", created.uid)
    assert tasks_backend.list_reminders("My Tasks", include_completed=True) == []


def test_unknown_list_raises(tasks_backend):
    with pytest.raises(CalendarNotFoundError):
        tasks_backend.add_reminder("Nope", "x")


def test_missing_reminder_raises(tasks_backend):
    with pytest.raises(ObjectNotFoundError):
        tasks_backend.get_reminder("My Tasks", "missing")


# -- composite backend: events via CalDAV, reminders via Tasks ---------------


class FakeCalDAVEvents:
    """Stand-in CalDAV backend recording event calls and exposing one calendar."""

    def __init__(self):
        self.calls = []

    def account_identifier(self):
        return "google-account"

    def list_calendars(self):
        from icloud_calendar_manager.models import CalendarInfo
        return [CalendarInfo(name="Home", url="u", supported_components=["VEVENT"])]

    def list_events(self, *a, **k):
        self.calls.append("list_events")
        return []

    def add_event(self, *a, **k):
        self.calls.append("add_event")
        from icloud_calendar_manager.models import EventInfo
        return EventInfo(uid="e1", summary=a[1], start=None, end=None)

    def get_event(self, *a, **k):
        return None

    def update_event(self, *a, **k):
        return None

    def delete_event(self, *a, **k):
        self.calls.append("delete_event")


def test_google_composite_routes_events_and_reminders():
    cal = FakeCalDAVEvents()
    tasks = GoogleTasksBackend(FakeTasksTransport())
    backend = GoogleBackend(cal, tasks)
    manager = CalendarManager(backend=backend)

    # Calendars merge event calendars (CalDAV) + task lists (Tasks API).
    names = {c.name for c in manager.list_calendars()}
    assert names == {"Home", "My Tasks"}
    assert [c.name for c in manager.list_reminder_lists()] == ["My Tasks"]

    # Event op hits the CalDAV backend.
    manager.add_event("Home", "Meeting", dt.datetime(2026, 6, 1, 9, 0))
    assert "add_event" in cal.calls

    # Reminder op hits the Tasks backend.
    created = manager.add_reminder("My Tasks", "Call dentist")
    assert created.summary == "Call dentist"
    assert [r.summary for r in manager.list_reminders("My Tasks")] == ["Call dentist"]

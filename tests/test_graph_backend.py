"""Tests for the Microsoft Graph backend using an in-memory fake transport.

The fake transport emulates just enough of the Graph REST surface (calendars,
events, To Do lists and tasks) to exercise the backend without a network.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest

from icloud_calendar_manager.backends.graph_backend import GraphBackend
from icloud_calendar_manager.exceptions import (
    AuthenticationError,
    CalendarNotFoundError,
    ObjectNotFoundError,
)
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


class FakeGraphTransport:
    """Minimal in-memory Microsoft Graph emulation."""

    def __init__(self, *, unauthorized=False):
        self.unauthorized = unauthorized
        self.calendars = {"cal-1": {"id": "cal-1", "name": "Calendar"}}
        self.events = {}  # id -> event resource
        self.lists = {"list-1": {"id": "list-1", "displayName": "Tasks"}}
        self.tasks = {}  # id -> task resource

    def request(self, method, path, *, params=None, json=None, headers=None):
        if self.unauthorized:
            return FakeResponse(401, {"error": {"message": "unauthorized"}})
        return self._route(method, path, params, json)

    # -- routing -------------------------------------------------------------

    def _route(self, method, path, params, body):
        parts = [p for p in path.split("/") if p]
        simple = {
            "/me": {"userPrincipalName": "user@contoso.com"},
            "/me/calendars": {"value": list(self.calendars.values())},
            "/me/todo/lists": {"value": list(self.lists.values())},
        }
        if path in simple and method == "GET":
            return FakeResponse(200, simple[path])
        if "calendarView" in parts:
            return FakeResponse(200, {"value": list(self.events.values())})
        if "calendars" in parts and parts[-1] == "events" and method == "POST":
            return self._create_event(body)
        if parts[:2] == ["me", "events"]:
            return self._event_by_id(method, parts[2], body)
        if parts[:2] == ["me", "todo"]:
            return self._route_tasks(method, parts, body)
        return FakeResponse(404, {"error": {"message": f"no route for {method} {path}"}})

    def _route_tasks(self, method, parts, body):
        # /me/todo/lists/{id}/tasks  and  /me/todo/lists/{id}/tasks/{taskId}
        if parts[-1] == "tasks":
            if method == "GET":
                return FakeResponse(200, {"value": list(self.tasks.values())})
            if method == "POST":
                return self._create_task(parts[3], body)
        if "tasks" in parts and len(parts) == 6:
            return self._task_by_id(method, parts[5], body)
        return FakeResponse(404, {"error": {"message": "no task route"}})

    # -- events --------------------------------------------------------------

    def _create_event(self, body):
        eid = str(uuid.uuid4())
        resource = dict(body or {})
        resource["id"] = eid
        resource.setdefault("subject", None)
        self.events[eid] = resource
        return FakeResponse(201, resource)

    def _event_by_id(self, method, eid, body):
        if eid not in self.events:
            return FakeResponse(404, {"error": {"message": "not found"}})
        if method == "GET":
            return FakeResponse(200, self.events[eid])
        if method == "PATCH":
            self.events[eid].update(body or {})
            return FakeResponse(200, self.events[eid])
        if method == "DELETE":
            del self.events[eid]
            return FakeResponse(204)
        return FakeResponse(405)

    # -- tasks ---------------------------------------------------------------

    def _create_task(self, list_id, body):
        tid = str(uuid.uuid4())
        resource = dict(body or {})
        resource["id"] = tid
        resource.setdefault("status", "notStarted")
        self.tasks[tid] = resource
        return FakeResponse(201, resource)

    def _task_by_id(self, method, tid, body):
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
def graph_manager():
    transport = FakeGraphTransport()
    backend = GraphBackend(transport=transport)
    return CalendarManager(backend=backend), transport


def test_account_identifier(graph_manager):
    manager, _ = graph_manager
    assert manager.check_connection()["principal_url"] == "user@contoso.com"


def test_list_calendars_includes_calendar_and_task_list(graph_manager):
    manager, _ = graph_manager
    cals = manager.list_calendars()
    names = {c.name for c in cals}
    assert names == {"Calendar", "Tasks"}
    # The To Do list should classify as a reminder list (VTODO).
    assert [c.name for c in manager.list_reminder_lists()] == ["Tasks"]


def test_event_round_trip(graph_manager):
    manager, _ = graph_manager
    created = manager.add_event(
        "Calendar", "Sync", dt.datetime(2026, 6, 1, 9, 0), dt.datetime(2026, 6, 1, 10, 0),
        location="HQ",
    )
    assert created.summary == "Sync"
    assert created.uid

    events = manager.list_events("Calendar", dt.datetime(2026, 6, 1), dt.datetime(2026, 6, 2))
    assert [e.summary for e in events] == ["Sync"]

    fetched = manager.get_event("Calendar", created.uid)
    assert fetched.location == "HQ"

    manager.update_event("Calendar", created.uid, summary="Renamed")
    assert manager.get_event("Calendar", created.uid).summary == "Renamed"

    manager.delete_event("Calendar", created.uid)
    assert manager.list_events("Calendar", dt.datetime(2026, 6, 1), dt.datetime(2026, 6, 2)) == []


def test_unknown_calendar_raises(graph_manager):
    manager, _ = graph_manager
    with pytest.raises(CalendarNotFoundError):
        manager.add_event("Nope", "x", dt.datetime(2026, 6, 1, 9, 0))


def test_reminder_round_trip_and_completion(graph_manager):
    manager, _ = graph_manager
    created = manager.add_reminder("Tasks", "Buy milk", priority=1)
    assert created.summary == "Buy milk"

    pending = manager.list_reminders("Tasks")
    assert [r.summary for r in pending] == ["Buy milk"]

    done = manager.complete_reminder("Tasks", created.uid)
    assert done.completed is True

    # Completed task hidden by default, visible with include_completed.
    assert manager.list_reminders("Tasks") == []
    assert len(manager.list_reminders("Tasks", include_completed=True)) == 1

    manager.delete_reminder("Tasks", created.uid)
    assert manager.list_reminders("Tasks", include_completed=True) == []


def test_get_missing_reminder_raises(graph_manager):
    manager, _ = graph_manager
    with pytest.raises(ObjectNotFoundError):
        manager.get_reminder("Tasks", "does-not-exist")


def test_unauthorized_raises_authentication_error():
    backend = GraphBackend(transport=FakeGraphTransport(unauthorized=True))
    manager = CalendarManager(backend=backend)
    with pytest.raises(AuthenticationError):
        manager.list_calendars()


def test_priority_maps_to_importance(graph_manager):
    manager, transport = graph_manager
    manager.add_reminder("Tasks", "High", priority=1)
    stored = list(transport.tasks.values())[0]
    assert stored["importance"] == "high"

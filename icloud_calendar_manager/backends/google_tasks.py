"""Google Tasks REST backend and a composite Google backend.

Google exposes calendars/events over CalDAV but **tasks** only via the separate
Google Tasks REST API (https://developers.google.com/tasks). To give the
``google`` provider full event *and* reminder support, :class:`GoogleBackend`
composes:

* a CalDAV backend for calendars and events, and
* :class:`GoogleTasksBackend` (this module) for reminders.

Both authenticate with the same OAuth2 access token. The Tasks HTTP layer is
injectable so it is unit-tested with a fake transport.
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any, List, Optional

from ..exceptions import CalendarNotFoundError, ObjectNotFoundError
from ..models import CalendarInfo, EventInfo, ReminderInfo
from .base import CalendarBackend
from .transport import json_or_raise

logger = logging.getLogger(__name__)

_TASKS_BASE = "https://tasks.googleapis.com/tasks/v1"
_SERVICE = "Google Tasks"


def _reminder_from_task(task: dict, list_name: Optional[str]) -> ReminderInfo:
    status = task.get("status")  # "needsAction" | "completed"
    completed = status == "completed"
    due = task.get("due")
    parsed_due = None
    if due:
        try:
            parsed_due = dt.datetime.fromisoformat(due.replace("Z", "+00:00"))
        except ValueError:
            parsed_due = None
    return ReminderInfo(
        uid=task.get("id"),
        summary=task.get("title"),
        due=parsed_due,
        status=status,
        priority=None,
        percent_complete=100 if completed else None,
        completed=completed,
        description=task.get("notes"),
        list_name=list_name,
        url=task.get("webViewLink"),
    )


class GoogleTasksBackend:
    """Reminder operations backed by the Google Tasks REST API.

    Only the reminder-related methods are implemented; it is intended to be
    composed inside :class:`GoogleBackend` rather than used directly as a full
    :class:`CalendarBackend`.
    """

    def __init__(self, transport: Any):
        self._t = transport

    def _json(self, method, path, *, params=None, json=None, not_found=None):
        resp = self._t.request(method, path, params=params, json=json)
        return json_or_raise(resp, service=_SERVICE, not_found=not_found)

    def _list_id(self, name: str) -> str:
        data = self._json("GET", "/users/@me/lists") or {}
        for item in data.get("items", []):
            if item.get("title") == name:
                return item["id"]
        raise CalendarNotFoundError(name)

    def list_task_lists(self) -> List[CalendarInfo]:
        data = self._json("GET", "/users/@me/lists") or {}
        return [
            CalendarInfo(
                name=item.get("title", ""),
                url=item.get("id", ""),
                supported_components=["VTODO"],
            )
            for item in data.get("items", [])
        ]

    def list_reminders(self, list_name, *, include_completed=False) -> List[ReminderInfo]:
        list_id = self._list_id(list_name)
        params = {"showCompleted": "true" if include_completed else "false"}
        if include_completed:
            params["showHidden"] = "true"
        data = self._json("GET", f"/lists/{list_id}/tasks", params=params) or {}
        return [_reminder_from_task(t, list_name) for t in data.get("items", [])]

    def get_reminder(self, list_name, uid) -> ReminderInfo:
        list_id = self._list_id(list_name)
        task = self._json(
            "GET", f"/lists/{list_id}/tasks/{uid}", not_found=ObjectNotFoundError(uid)
        )
        return _reminder_from_task(task or {}, list_name)

    def add_reminder(
        self, list_name, summary, *, due=None, priority=None, description=None, uid=None
    ) -> ReminderInfo:
        list_id = self._list_id(list_name)
        body: dict = {"title": summary}
        if description is not None:
            body["notes"] = description
        if due is not None:
            body["due"] = _google_due(due)
        created = self._json("POST", f"/lists/{list_id}/tasks", json=body)
        logger.info("Created Google task %r in %r", summary, list_name)
        return _reminder_from_task(created or {}, list_name)

    def complete_reminder(self, list_name, uid) -> ReminderInfo:
        list_id = self._list_id(list_name)
        updated = self._json(
            "PATCH",
            f"/lists/{list_id}/tasks/{uid}",
            json={"status": "completed"},
            not_found=ObjectNotFoundError(uid),
        )
        logger.info("Completed Google task uid=%s", uid)
        return _reminder_from_task(updated or {}, list_name)

    def delete_reminder(self, list_name, uid) -> None:
        list_id = self._list_id(list_name)
        self._json(
            "DELETE", f"/lists/{list_id}/tasks/{uid}", not_found=ObjectNotFoundError(uid)
        )
        logger.info("Deleted Google task uid=%s", uid)


def _google_due(value: dt.datetime | dt.date) -> str:
    """Google Tasks accepts an RFC 3339 ``due`` (date portion is significant)."""
    if isinstance(value, dt.datetime):
        if value.tzinfo is not None:
            value = value.astimezone(dt.timezone.utc).replace(tzinfo=None)
        return value.isoformat() + "Z"
    return dt.datetime(value.year, value.month, value.day).isoformat() + "Z"


class GoogleBackend(CalendarBackend):
    """Composite backend: CalDAV for events + Google Tasks for reminders."""

    supports_reminders = True

    def __init__(self, caldav_backend: CalendarBackend, tasks_backend: GoogleTasksBackend):
        self._cal = caldav_backend
        self._tasks = tasks_backend

    # -- calendars (events via CalDAV, task lists via Tasks API) -------------

    def account_identifier(self) -> str:
        return self._cal.account_identifier()

    def list_calendars(self) -> List[CalendarInfo]:
        # Event calendars come from CalDAV; reminder lists from Google Tasks.
        calendars = [c for c in self._cal.list_calendars() if not c.is_reminder_list]
        return calendars + self._tasks.list_task_lists()

    # -- events (delegate to CalDAV) -----------------------------------------

    def list_events(self, calendar_name, start, end, *, expand=True) -> List[EventInfo]:
        return self._cal.list_events(calendar_name, start, end, expand=expand)

    def get_event(self, calendar_name, uid) -> EventInfo:
        return self._cal.get_event(calendar_name, uid)

    def add_event(
        self, calendar_name, summary, start, end=None, *, location=None, description=None, uid=None
    ) -> EventInfo:
        return self._cal.add_event(
            calendar_name, summary, start, end,
            location=location, description=description, uid=uid,
        )

    def update_event(
        self, calendar_name, uid, *, summary=None, start=None, end=None, location=None, description=None
    ) -> EventInfo:
        return self._cal.update_event(
            calendar_name, uid, summary=summary, start=start, end=end,
            location=location, description=description,
        )

    def delete_event(self, calendar_name, uid) -> None:
        self._cal.delete_event(calendar_name, uid)

    # -- reminders (delegate to Google Tasks) --------------------------------

    def list_reminders(self, list_name, *, include_completed=False) -> List[ReminderInfo]:
        return self._tasks.list_reminders(list_name, include_completed=include_completed)

    def get_reminder(self, list_name, uid) -> ReminderInfo:
        return self._tasks.get_reminder(list_name, uid)

    def add_reminder(
        self, list_name, summary, *, due=None, priority=None, description=None, uid=None
    ) -> ReminderInfo:
        return self._tasks.add_reminder(
            list_name, summary, due=due, priority=priority, description=description, uid=uid
        )

    def complete_reminder(self, list_name, uid) -> ReminderInfo:
        return self._tasks.complete_reminder(list_name, uid)

    def delete_reminder(self, list_name, uid) -> None:
        self._tasks.delete_reminder(list_name, uid)

"""Microsoft 365 / Outlook backend via the Microsoft Graph REST API.

Outlook/Microsoft 365 do not speak CalDAV, so this backend talks to Microsoft
Graph (https://graph.microsoft.com) over HTTPS using an OAuth2 access token.
Calendars and events use the Graph *calendar* API; reminders map to Microsoft
*To Do* tasks.

The HTTP layer is injected via a small ``transport`` object so the backend can
be unit-tested without a network connection. Acquiring/refreshing the OAuth2
token is the caller's responsibility (supply it via ``--token`` or env var).

This backend is **experimental**: it is exercised by unit tests with a fake
transport, but has not been validated against a live tenant in CI.
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any, List, Optional

from ..exceptions import CalendarNotFoundError, ObjectNotFoundError
from ..models import CalendarInfo, EventInfo, ReminderInfo
from .base import CalendarBackend
from .transport import BearerTransport, json_or_raise

logger = logging.getLogger(__name__)

_SERVICE = "Microsoft Graph"


def _graph_datetime(value: dt.datetime | dt.date) -> dict:
    """Render a date/datetime as a Graph ``dateTimeTimeZone`` (assumed UTC)."""
    if isinstance(value, dt.datetime):
        if value.tzinfo is not None:
            value = value.astimezone(dt.timezone.utc).replace(tzinfo=None)
        return {"dateTime": value.isoformat(), "timeZone": "UTC"}
    midnight = dt.datetime(value.year, value.month, value.day)
    return {"dateTime": midnight.isoformat(), "timeZone": "UTC"}


def _priority_to_importance(priority: Optional[int]) -> Optional[str]:
    if priority is None:
        return None
    if priority <= 3:
        return "high"
    if priority >= 7:
        return "low"
    return "normal"


class GraphTransport(BearerTransport):
    """HTTP transport for Microsoft Graph (a thin BearerTransport alias)."""


class GraphBackend(CalendarBackend):
    """CalendarBackend backed by Microsoft Graph."""

    supports_reminders = True

    def __init__(self, transport: Any):
        self._t = transport

    # -- request plumbing ----------------------------------------------------

    def _json(self, method, path, *, params=None, json=None, headers=None, not_found=None):
        resp = self._t.request(method, path, params=params, json=json, headers=headers)
        return json_or_raise(resp, service=_SERVICE, not_found=not_found)

    def _values(self, path: str) -> List[dict]:
        data = self._json("GET", path) or {}
        return data.get("value", [])

    # -- discovery -----------------------------------------------------------

    def account_identifier(self) -> str:
        me = self._json("GET", "/me") or {}
        return me.get("userPrincipalName") or me.get("mail") or "microsoft-graph"

    def list_calendars(self) -> List[CalendarInfo]:
        infos = [
            CalendarInfo(name=c.get("name", ""), url=c.get("id", ""), supported_components=["VEVENT"])
            for c in self._values("/me/calendars")
        ]
        infos += [
            CalendarInfo(name=lst.get("displayName", ""), url=lst.get("id", ""), supported_components=["VTODO"])
            for lst in self._values("/me/todo/lists")
        ]
        return infos

    def _calendar_id(self, name: str) -> str:
        for cal in self._values("/me/calendars"):
            if cal.get("name") == name:
                return cal["id"]
        raise CalendarNotFoundError(name)

    def _list_id(self, name: str) -> str:
        for lst in self._values("/me/todo/lists"):
            if lst.get("displayName") == name:
                return lst["id"]
        raise CalendarNotFoundError(name)

    # -- events --------------------------------------------------------------

    def list_events(self, calendar_name, start, end, *, expand=True) -> List[EventInfo]:
        cal_id = self._calendar_id(calendar_name)
        params = {"startDateTime": start.isoformat(), "endDateTime": end.isoformat()}
        headers = {"Prefer": 'outlook.timezone="UTC"'}
        data = self._json(
            "GET", f"/me/calendars/{cal_id}/calendarView", params=params, headers=headers
        ) or {}
        return [EventInfo.from_graph(e, calendar_name) for e in data.get("value", [])]

    def get_event(self, calendar_name, uid) -> EventInfo:
        event = self._json("GET", f"/me/events/{uid}", not_found=ObjectNotFoundError(uid))
        return EventInfo.from_graph(event or {}, calendar_name)

    def add_event(
        self, calendar_name, summary, start, end=None, *, location=None, description=None, uid=None
    ) -> EventInfo:
        cal_id = self._calendar_id(calendar_name)
        if end is None:
            delta = dt.timedelta(hours=1) if isinstance(start, dt.datetime) else dt.timedelta(days=1)
            end = start + delta
        body = _event_body(summary, start, end, location, description)
        created = self._json("POST", f"/me/calendars/{cal_id}/events", json=body)
        logger.info("Created Graph event %r in %r", summary, calendar_name)
        return EventInfo.from_graph(created or {}, calendar_name)

    def update_event(
        self, calendar_name, uid, *, summary=None, start=None, end=None, location=None, description=None
    ) -> EventInfo:
        body = _event_body(summary, start, end, location, description)
        updated = self._json(
            "PATCH", f"/me/events/{uid}", json=body, not_found=ObjectNotFoundError(uid)
        )
        logger.info("Updated Graph event uid=%s", uid)
        return EventInfo.from_graph(updated or {}, calendar_name)

    def delete_event(self, calendar_name, uid) -> None:
        self._json("DELETE", f"/me/events/{uid}", not_found=ObjectNotFoundError(uid))
        logger.info("Deleted Graph event uid=%s", uid)

    # -- reminders (Microsoft To Do) -----------------------------------------

    def list_reminders(self, list_name, *, include_completed=False) -> List[ReminderInfo]:
        list_id = self._list_id(list_name)
        tasks = self._values(f"/me/todo/lists/{list_id}/tasks")
        result = []
        for task in tasks:
            if not include_completed and task.get("status") == "completed":
                continue
            result.append(ReminderInfo.from_graph(task, list_name))
        return result

    def get_reminder(self, list_name, uid) -> ReminderInfo:
        list_id = self._list_id(list_name)
        task = self._json(
            "GET", f"/me/todo/lists/{list_id}/tasks/{uid}", not_found=ObjectNotFoundError(uid)
        )
        return ReminderInfo.from_graph(task or {}, list_name)

    def add_reminder(
        self, list_name, summary, *, due=None, priority=None, description=None, uid=None
    ) -> ReminderInfo:
        list_id = self._list_id(list_name)
        body = _task_body(summary, due, priority, description)
        created = self._json("POST", f"/me/todo/lists/{list_id}/tasks", json=body)
        logger.info("Created Graph task %r in %r", summary, list_name)
        return ReminderInfo.from_graph(created or {}, list_name)

    def complete_reminder(self, list_name, uid) -> ReminderInfo:
        list_id = self._list_id(list_name)
        updated = self._json(
            "PATCH",
            f"/me/todo/lists/{list_id}/tasks/{uid}",
            json={"status": "completed"},
            not_found=ObjectNotFoundError(uid),
        )
        logger.info("Completed Graph task uid=%s", uid)
        return ReminderInfo.from_graph(updated or {}, list_name)

    def delete_reminder(self, list_name, uid) -> None:
        list_id = self._list_id(list_name)
        self._json(
            "DELETE", f"/me/todo/lists/{list_id}/tasks/{uid}", not_found=ObjectNotFoundError(uid)
        )
        logger.info("Deleted Graph task uid=%s", uid)


def _event_body(summary, start, end, location, description) -> dict:
    body: dict = {}
    if summary is not None:
        body["subject"] = summary
    if start is not None:
        body["start"] = _graph_datetime(start)
    if end is not None:
        body["end"] = _graph_datetime(end)
    if location is not None:
        body["location"] = {"displayName": location}
    if description is not None:
        body["body"] = {"contentType": "text", "content": description}
    return body


def _task_body(summary, due, priority, description) -> dict:
    body: dict = {}
    if summary is not None:
        body["title"] = summary
    if due is not None:
        body["dueDateTime"] = _graph_datetime(due)
    if description is not None:
        body["body"] = {"contentType": "text", "content": description}
    importance = _priority_to_importance(priority)
    if importance is not None:
        body["importance"] = importance
    return body

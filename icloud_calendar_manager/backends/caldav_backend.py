"""CalDAV backend — speaks to iCloud, Fastmail, Yahoo, Google, Nextcloud, etc.

This is the original :class:`CalendarManager` logic refactored behind the
:class:`~icloud_calendar_manager.backends.base.CalendarBackend` interface. It
operates on a ``caldav`` principal, which may be injected directly (for tests)
or built lazily from an :class:`~icloud_calendar_manager.config.AuthConfig`.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from typing import Any, List, Optional

import caldav
import icalendar

from ..client import EndpointCache, build_caldav_client, get_principal, partition_base_url
from ..config import AuthConfig
from ..exceptions import CalendarNotFoundError, ObjectNotFoundError
from ..models import CalendarInfo, EventInfo, ReminderInfo
from .base import CalendarBackend

logger = logging.getLogger(__name__)

_PRODID = "-//iCloud Calendar Manager//EN//"


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _build_vevent(
    summary: str,
    start: dt.datetime | dt.date,
    end: Optional[dt.datetime | dt.date],
    uid: str,
    location: Optional[str] = None,
    description: Optional[str] = None,
) -> bytes:
    """Render a VEVENT-bearing iCalendar document."""
    cal = icalendar.Calendar()
    cal.add("prodid", _PRODID)
    cal.add("version", "2.0")
    event = icalendar.Event()
    event.add("uid", uid)
    event.add("summary", summary)
    event.add("dtstamp", _utcnow())
    event.add("dtstart", start)
    if end is not None:
        event.add("dtend", end)
    if location:
        event.add("location", location)
    if description:
        event.add("description", description)
    cal.add_component(event)
    return cal.to_ical()


def _build_vtodo(
    summary: str,
    uid: str,
    due: Optional[dt.datetime | dt.date] = None,
    priority: Optional[int] = None,
    description: Optional[str] = None,
) -> bytes:
    """Render a VTODO-bearing iCalendar document (a reminder)."""
    cal = icalendar.Calendar()
    cal.add("prodid", _PRODID)
    cal.add("version", "2.0")
    todo = icalendar.Todo()
    todo.add("uid", uid)
    todo.add("summary", summary)
    todo.add("dtstamp", _utcnow())
    todo.add("status", "NEEDS-ACTION")
    if due is not None:
        todo.add("due", due)
    if priority is not None:
        todo.add("priority", priority)
    if description:
        todo.add("description", description)
    cal.add_component(todo)
    return cal.to_ical()


def _replace(component: Any, key: str, value: Any) -> None:
    """Replace ``key`` on an icalendar component, preserving correct typing."""
    if value is None:
        return
    component.pop(key, None)
    component.add(key, value)


class CalDAVBackend(CalendarBackend):
    """CalendarBackend backed by a ``caldav`` principal."""

    supports_reminders = True

    def __init__(
        self,
        *,
        principal: Any = None,
        client: Optional[caldav.DAVClient] = None,
        auth: Optional[AuthConfig] = None,
        cache: Optional[EndpointCache] = None,
    ):
        self._principal = principal
        self._client = client
        self._auth = auth
        self._cache = cache

    # -- lazy connection -----------------------------------------------------

    @property
    def principal(self):
        if self._principal is not None:
            return self._principal
        if self._client is None:
            if self._auth is None:
                raise ValueError("CalDAVBackend needs a principal, client, or auth.")
            self._client = build_caldav_client(
                url=self._auth.url,
                auth_scheme=self._auth.auth_scheme,
                username=self._auth.username,
                secret=self._auth.secret,
                timeout=self._auth.timeout,
                cache=self._cache,
            )
        self._principal = get_principal(self._client)
        if self._cache is not None:
            base = partition_base_url(self._principal)
            if base:
                self._cache.save(base)
        return self._principal

    def account_identifier(self) -> str:
        return str(self.principal.url)

    # -- calendars -----------------------------------------------------------

    def list_calendars(self) -> List[CalendarInfo]:
        return [CalendarInfo.from_calendar(c) for c in self.principal.calendars()]

    def _find_calendar(self, name: str):
        for calendar in self.principal.calendars():
            if calendar.name == name:
                return calendar
        raise CalendarNotFoundError(name)

    # -- events --------------------------------------------------------------

    def list_events(
        self,
        calendar_name: str,
        start: dt.datetime,
        end: dt.datetime,
        *,
        expand: bool = True,
    ) -> List[EventInfo]:
        calendar = self._find_calendar(calendar_name)
        results = calendar.search(start=start, end=end, event=True, expand=expand)
        return [EventInfo.from_caldav_object(obj, calendar_name) for obj in results]

    def add_event(
        self,
        calendar_name: str,
        summary: str,
        start: dt.datetime | dt.date,
        end: Optional[dt.datetime | dt.date] = None,
        *,
        location: Optional[str] = None,
        description: Optional[str] = None,
        uid: Optional[str] = None,
    ) -> EventInfo:
        calendar = self._find_calendar(calendar_name)
        uid = uid or str(uuid.uuid4())
        ical = _build_vevent(summary, start, end, uid, location, description)
        obj = calendar.save_event(ical=ical)
        logger.info("Created event %r (uid=%s) in %r", summary, uid, calendar_name)
        return EventInfo.from_caldav_object(obj, calendar_name)

    def get_event(self, calendar_name: str, uid: str) -> EventInfo:
        calendar = self._find_calendar(calendar_name)
        obj = self._event_by_uid(calendar, uid)
        return EventInfo.from_caldav_object(obj, calendar_name)

    def update_event(
        self,
        calendar_name: str,
        uid: str,
        *,
        summary: Optional[str] = None,
        start: Optional[dt.datetime | dt.date] = None,
        end: Optional[dt.datetime | dt.date] = None,
        location: Optional[str] = None,
        description: Optional[str] = None,
    ) -> EventInfo:
        calendar = self._find_calendar(calendar_name)
        obj = self._event_by_uid(calendar, uid)
        component = obj.icalendar_component
        _replace(component, "summary", summary)
        _replace(component, "dtstart", start)
        _replace(component, "dtend", end)
        _replace(component, "location", location)
        _replace(component, "description", description)
        _replace(component, "last-modified", _utcnow())
        obj.save()
        logger.info("Updated event uid=%s in %r", uid, calendar_name)
        return EventInfo.from_caldav_object(obj, calendar_name)

    def delete_event(self, calendar_name: str, uid: str) -> None:
        calendar = self._find_calendar(calendar_name)
        obj = self._event_by_uid(calendar, uid)
        obj.delete()
        logger.info("Deleted event uid=%s from %r", uid, calendar_name)

    # -- reminders (VTODO) ---------------------------------------------------

    def list_reminders(
        self, list_name: str, *, include_completed: bool = False
    ) -> List[ReminderInfo]:
        calendar = self._find_calendar(list_name)
        todos = calendar.todos(include_completed=include_completed)
        return [ReminderInfo.from_caldav_object(obj, list_name) for obj in todos]

    def get_reminder(self, list_name: str, uid: str) -> ReminderInfo:
        calendar = self._find_calendar(list_name)
        obj = self._todo_by_uid(calendar, uid)
        return ReminderInfo.from_caldav_object(obj, list_name)

    def add_reminder(
        self,
        list_name: str,
        summary: str,
        *,
        due: Optional[dt.datetime | dt.date] = None,
        priority: Optional[int] = None,
        description: Optional[str] = None,
        uid: Optional[str] = None,
    ) -> ReminderInfo:
        calendar = self._find_calendar(list_name)
        uid = uid or str(uuid.uuid4())
        ical = _build_vtodo(summary, uid, due, priority, description)
        obj = calendar.save_todo(ical=ical)
        logger.info("Created reminder %r (uid=%s) in %r", summary, uid, list_name)
        return ReminderInfo.from_caldav_object(obj, list_name)

    def complete_reminder(self, list_name: str, uid: str) -> ReminderInfo:
        calendar = self._find_calendar(list_name)
        obj = self._todo_by_uid(calendar, uid)
        component = obj.icalendar_component
        _replace(component, "status", "COMPLETED")
        _replace(component, "percent-complete", 100)
        _replace(component, "completed", _utcnow())
        _replace(component, "last-modified", _utcnow())
        obj.save()
        logger.info("Completed reminder uid=%s in %r", uid, list_name)
        return ReminderInfo.from_caldav_object(obj, list_name)

    def delete_reminder(self, list_name: str, uid: str) -> None:
        calendar = self._find_calendar(list_name)
        obj = self._todo_by_uid(calendar, uid)
        obj.delete()
        logger.info("Deleted reminder uid=%s from %r", uid, list_name)

    # -- internal lookups ----------------------------------------------------

    @staticmethod
    def _event_by_uid(calendar, uid: str):
        try:
            return calendar.event_by_uid(uid)
        except caldav.lib.error.NotFoundError as exc:
            raise ObjectNotFoundError(uid) from exc

    @staticmethod
    def _todo_by_uid(calendar, uid: str):
        try:
            return calendar.todo_by_uid(uid)
        except caldav.lib.error.NotFoundError as exc:
            raise ObjectNotFoundError(uid) from exc

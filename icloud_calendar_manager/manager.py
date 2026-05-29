"""High-level operations against iCloud calendars and reminder lists.

:class:`CalendarManager` is the primary entry point. It accepts an injectable
``principal`` (or a ``client``) which makes it trivial to unit-test without a
network connection, while :meth:`CalendarManager.from_credentials` and
:meth:`CalendarManager.from_env` provide the convenient real-world paths.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from typing import Any, List, Optional

import caldav
import icalendar

from .client import EndpointCache, build_client, get_principal, partition_base_url
from .config import DEFAULT_TIMEOUT, Credentials
from .exceptions import CalendarNotFoundError, ObjectNotFoundError
from .models import CalendarInfo, EventInfo, ReminderInfo

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
    """Render a VTODO-bearing iCalendar document (an iCloud reminder)."""
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


class CalendarManager:
    """Manage iCloud calendars, events and reminders over CalDAV."""

    def __init__(
        self,
        *,
        principal: Any = None,
        client: Optional[caldav.DAVClient] = None,
        credentials: Optional[Credentials] = None,
        url: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        cache: Optional[EndpointCache] = None,
    ):
        self._principal = principal
        self._client = client
        self._credentials = credentials
        self._url = url
        self._timeout = timeout
        self._cache = cache

    # -- construction helpers ------------------------------------------------

    @classmethod
    def from_credentials(
        cls,
        credentials: Credentials,
        *,
        url: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        cache: Optional[EndpointCache] = None,
    ) -> "CalendarManager":
        return cls(credentials=credentials, url=url, timeout=timeout, cache=cache)

    @classmethod
    def from_env(
        cls,
        apple_id: Optional[str] = None,
        app_password: Optional[str] = None,
        *,
        url: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        cache: Optional[EndpointCache] = None,
    ) -> "CalendarManager":
        creds = Credentials.from_env(apple_id, app_password)
        return cls.from_credentials(creds, url=url, timeout=timeout, cache=cache)

    # -- lazy connection -----------------------------------------------------

    @property
    def principal(self):
        """Resolve (and memoize) the CalDAV principal."""
        if self._principal is not None:
            return self._principal
        if self._client is None:
            if self._credentials is None:
                raise ValueError(
                    "CalendarManager needs a principal, client, or credentials."
                )
            self._client = build_client(
                self._credentials,
                url=self._url,
                timeout=self._timeout,
                cache=self._cache,
            )
        self._principal = get_principal(self._client)
        # Opportunistically cache the resolved partition URL for next time.
        if self._cache is not None:
            base = partition_base_url(self._principal)
            if base:
                self._cache.save(base)
        return self._principal

    # -- calendars -----------------------------------------------------------

    def list_calendars(self, include_reminder_lists: bool = True) -> List[CalendarInfo]:
        """List calendars (and, by default, reminder lists)."""
        infos = [CalendarInfo.from_calendar(c) for c in self.principal.calendars()]
        if include_reminder_lists:
            return infos
        return [c for c in infos if not c.is_reminder_list]

    def list_reminder_lists(self) -> List[CalendarInfo]:
        """List only the collections that hold reminders (VTODO)."""
        return [c for c in self.list_calendars() if c.is_reminder_list]

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
        """Return events in ``calendar_name`` between ``start`` and ``end``."""
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
        """Create an event and return its parsed representation."""
        calendar = self._find_calendar(calendar_name)
        uid = uid or str(uuid.uuid4())
        ical = _build_vevent(summary, start, end, uid, location, description)
        obj = calendar.save_event(ical=ical)
        logger.info("Created event %r (uid=%s) in %r", summary, uid, calendar_name)
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
        """Update fields of an existing event. Only provided fields change."""
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
        """Delete an event by UID."""
        calendar = self._find_calendar(calendar_name)
        obj = self._event_by_uid(calendar, uid)
        obj.delete()
        logger.info("Deleted event uid=%s from %r", uid, calendar_name)

    # -- reminders (VTODO) ---------------------------------------------------

    def list_reminders(
        self,
        list_name: str,
        *,
        include_completed: bool = False,
    ) -> List[ReminderInfo]:
        """Return reminders from ``list_name``."""
        calendar = self._find_calendar(list_name)
        todos = calendar.todos(include_completed=include_completed)
        return [ReminderInfo.from_caldav_object(obj, list_name) for obj in todos]

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
        """Create a reminder (VTODO) and return its parsed representation."""
        calendar = self._find_calendar(list_name)
        uid = uid or str(uuid.uuid4())
        ical = _build_vtodo(summary, uid, due, priority, description)
        obj = calendar.save_todo(ical=ical)
        logger.info("Created reminder %r (uid=%s) in %r", summary, uid, list_name)
        return ReminderInfo.from_caldav_object(obj, list_name)

    def complete_reminder(self, list_name: str, uid: str) -> ReminderInfo:
        """Mark a reminder complete (STATUS=COMPLETED, 100%)."""
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
        """Delete a reminder by UID."""
        calendar = self._find_calendar(list_name)
        obj = self._todo_by_uid(calendar, uid)
        obj.delete()
        logger.info("Deleted reminder uid=%s from %r", uid, list_name)

    # -- diagnostics ---------------------------------------------------------

    def check_connection(self) -> dict:
        """Verify connectivity and summarize the account."""
        calendars = self.list_calendars()
        reminder_lists = [c for c in calendars if c.is_reminder_list]
        return {
            "principal_url": str(self.principal.url),
            "calendars": len(calendars) - len(reminder_lists),
            "reminder_lists": len(reminder_lists),
        }

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

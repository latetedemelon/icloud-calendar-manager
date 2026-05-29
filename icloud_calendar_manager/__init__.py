"""iCloud Calendar Manager.

A small, tested toolkit and CLI for managing iCloud calendars, events and
reminders over CalDAV.

High-level usage::

    from icloud_calendar_manager import CalendarManager
    mgr = CalendarManager.from_env()
    for cal in mgr.list_calendars():
        print(cal.name)

The module-level functions below are retained for backwards compatibility with
earlier versions of this project and are implemented on top of
:class:`CalendarManager`.
"""

from __future__ import annotations

__version__ = "0.3.0"

import datetime as dt
from typing import List

import caldav

from .client import EndpointCache, build_client
from .config import DEFAULT_CALDAV_URL, Credentials
from .exceptions import (
    AuthenticationError,
    CalendarNotFoundError,
    ConfigurationError,
    ICloudCalendarError,
    ObjectNotFoundError,
)
from .manager import CalendarManager
from .models import CalendarInfo, EventInfo, ReminderInfo

__all__ = [
    "__version__",
    "CalendarManager",
    "Credentials",
    "EndpointCache",
    "CalendarInfo",
    "EventInfo",
    "ReminderInfo",
    "ICloudCalendarError",
    "ConfigurationError",
    "AuthenticationError",
    "CalendarNotFoundError",
    "ObjectNotFoundError",
    "DEFAULT_CALDAV_URL",
    # Backwards-compatible helpers:
    "get_caldav_client",
    "find_calendar",
    "discover_caldav_calendars",
    "list_calendars",
    "get_apple_calendar_events",
    "add_event_to_calendar",
    "update_event_in_calendar",
    "delete_event_from_calendar",
    "list_reminder_lists",
    "get_reminders",
]


def _default_manager() -> CalendarManager:
    return CalendarManager.from_env()


# --------------------------------------------------------------------------
# Backwards-compatible, stateless helpers (mirror the original public API).
# --------------------------------------------------------------------------


def get_caldav_client() -> caldav.DAVClient:
    """Return a CalDAV client built from environment credentials."""
    return build_client(Credentials.from_env())


def find_calendar(principal, calendar_name: str):
    """Return the calendar named ``calendar_name`` from ``principal`` or ``None``."""
    return next((c for c in principal.calendars() if c.name == calendar_name), None)


def discover_caldav_calendars() -> List[CalendarInfo]:
    """List all calendars (and reminder lists) for the configured account."""
    return _default_manager().list_calendars()


def list_calendars() -> List[CalendarInfo]:
    """List all calendars (and reminder lists)."""
    return _default_manager().list_calendars()


def get_apple_calendar_events(
    calendar_name: str, start_date: dt.datetime, end_date: dt.datetime
) -> List[EventInfo]:
    """Return events in ``calendar_name`` between ``start_date`` and ``end_date``."""
    return _default_manager().list_events(calendar_name, start_date, end_date)


def add_event_to_calendar(
    calendar_name: str, summary: str, start_time: dt.datetime, end_time: dt.datetime
) -> bool:
    """Add an event; returns ``True`` on success."""
    _default_manager().add_event(calendar_name, summary, start_time, end_time)
    return True


def update_event_in_calendar(
    calendar_name: str,
    event_uid: str,
    summary: str,
    start_time: dt.datetime,
    end_time: dt.datetime,
) -> bool:
    """Update an event by UID; returns ``True`` on success."""
    _default_manager().update_event(
        calendar_name, event_uid, summary=summary, start=start_time, end=end_time
    )
    return True


def delete_event_from_calendar(calendar_name: str, event_uid: str) -> bool:
    """Delete an event by UID; returns ``True`` on success."""
    _default_manager().delete_event(calendar_name, event_uid)
    return True


def list_reminder_lists() -> List[CalendarInfo]:
    """List reminder lists (collections that hold VTODO items)."""
    return _default_manager().list_reminder_lists()


def get_reminders(reminder_list_name: str, include_completed: bool = False) -> List[ReminderInfo]:
    """Return reminders from ``reminder_list_name``."""
    return _default_manager().list_reminders(
        reminder_list_name, include_completed=include_completed
    )

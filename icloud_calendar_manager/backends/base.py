"""Backend interface for calendar operations.

A backend hides the protocol details of a provider (CalDAV vs Microsoft Graph)
behind a uniform set of operations returning the package's typed models
(:class:`~icloud_calendar_manager.models.CalendarInfo`, ``EventInfo``,
``ReminderInfo``). :class:`~icloud_calendar_manager.manager.CalendarManager`
delegates to whichever backend it was built with.
"""

from __future__ import annotations

import abc
import datetime as dt
from typing import List, Optional

from ..models import CalendarInfo, EventInfo, ReminderInfo


class CalendarBackend(abc.ABC):
    """Abstract operations every provider backend must implement."""

    #: Whether this backend/provider exposes reminders (tasks/VTODO).
    supports_reminders: bool = True

    # -- calendars -----------------------------------------------------------

    @abc.abstractmethod
    def list_calendars(self) -> List[CalendarInfo]:
        """Return all collections (calendars and reminder lists)."""

    @abc.abstractmethod
    def account_identifier(self) -> str:
        """Return a human-readable identifier for the connected account."""

    # -- events --------------------------------------------------------------

    @abc.abstractmethod
    def list_events(
        self,
        calendar_name: str,
        start: dt.datetime,
        end: dt.datetime,
        *,
        expand: bool = True,
    ) -> List[EventInfo]:
        ...

    @abc.abstractmethod
    def get_event(self, calendar_name: str, uid: str) -> EventInfo:
        ...

    @abc.abstractmethod
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
        ...

    @abc.abstractmethod
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
        ...

    @abc.abstractmethod
    def delete_event(self, calendar_name: str, uid: str) -> None:
        ...

    # -- reminders -----------------------------------------------------------

    @abc.abstractmethod
    def list_reminders(
        self, list_name: str, *, include_completed: bool = False
    ) -> List[ReminderInfo]:
        ...

    @abc.abstractmethod
    def get_reminder(self, list_name: str, uid: str) -> ReminderInfo:
        ...

    @abc.abstractmethod
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
        ...

    @abc.abstractmethod
    def complete_reminder(self, list_name: str, uid: str) -> ReminderInfo:
        ...

    @abc.abstractmethod
    def delete_reminder(self, list_name: str, uid: str) -> None:
        ...

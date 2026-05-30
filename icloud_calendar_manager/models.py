"""Typed, serializable representations of CalDAV objects.

These dataclasses decouple the rest of the codebase (and the CLI/JSON output)
from the ``caldav``/``icalendar`` object model, and make results easy to test
and pretty-print.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import asdict, dataclass, field
from typing import Any, List, Optional


def _value(component: Any, key: str) -> Optional[Any]:
    """Return the raw value for ``key`` from an icalendar component, or ``None``."""
    if component is None:
        return None
    try:
        prop = component.get(key)
    except Exception:  # pragma: no cover - defensive
        return None
    return prop


def _text(component: Any, key: str) -> Optional[str]:
    """Return a stringified text property, or ``None`` if absent."""
    prop = _value(component, key)
    if prop is None:
        return None
    return str(prop)


def _datetime(component: Any, key: str) -> Optional[dt.datetime | dt.date]:
    """Return a ``date``/``datetime`` for ``key``, unwrapping icalendar wrappers."""
    prop = _value(component, key)
    if prop is None:
        return None
    # icalendar wraps values in objects exposing ``.dt``; raw values pass through.
    return getattr(prop, "dt", prop)


def _int(component: Any, key: str) -> Optional[int]:
    prop = _value(component, key)
    if prop is None:
        return None
    try:
        return int(prop)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return None


def _iso(value: Optional[dt.datetime | dt.date]) -> Optional[str]:
    """Serialize a date/datetime to an ISO 8601 string (or pass through other types)."""
    if value is None:
        return None
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    return str(value)


def _component_of(obj: Any):
    """Best-effort extraction of the primary icalendar component from a caldav object."""
    component = getattr(obj, "icalendar_component", None)
    if component is not None:
        return component
    # Fallback: walk the icalendar instance for the first VEVENT/VTODO.
    instance = getattr(obj, "icalendar_instance", None)
    if instance is not None:
        for sub in instance.walk():
            if sub.name in ("VEVENT", "VTODO"):
                return sub
    return None


def _parse_graph_datetime(value: Any) -> Optional[dt.datetime]:
    """Parse a Microsoft Graph ``dateTimeTimeZone`` value into a ``datetime``.

    Graph returns ``{"dateTime": "2026-06-01T12:00:00.0000000", "timeZone":
    "UTC"}``; the fractional seconds can exceed what ``fromisoformat`` accepts on
    older Pythons, so they are trimmed to six digits.
    """
    if not value:
        return None
    if isinstance(value, str):
        text, tzname = value, None
    else:
        text, tzname = value.get("dateTime"), value.get("timeZone")
    if not text:
        return None
    if "." in text:
        head, _, frac = text.partition(".")
        text = head + "." + frac.rstrip("Z")[:6]
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None and tzname == "UTC":
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


# Maps Microsoft Graph "importance" to an iCalendar-style PRIORITY integer.
_GRAPH_IMPORTANCE_TO_PRIORITY = {"low": 9, "normal": 5, "high": 1}


@dataclass
class CalendarInfo:
    """A calendar or reminder list."""

    name: str
    url: str
    supported_components: List[str] = field(default_factory=list)

    @property
    def is_reminder_list(self) -> bool:
        """True if the collection holds reminders (VTODO) rather than events."""
        comps = [c.upper() for c in self.supported_components]
        return "VTODO" in comps and "VEVENT" not in comps

    @classmethod
    def from_calendar(cls, calendar: Any) -> "CalendarInfo":
        try:
            components = list(calendar.get_supported_components())
        except Exception:
            components = []
        return cls(
            name=str(calendar.name) if calendar.name else "",
            url=str(calendar.url),
            supported_components=components,
        )

    def to_dict(self) -> dict:
        data = asdict(self)
        data["is_reminder_list"] = self.is_reminder_list
        return data


@dataclass
class EventInfo:
    """A calendar event (VEVENT)."""

    uid: Optional[str]
    summary: Optional[str]
    start: Optional[dt.datetime | dt.date]
    end: Optional[dt.datetime | dt.date]
    location: Optional[str] = None
    description: Optional[str] = None
    all_day: bool = False
    calendar: Optional[str] = None
    url: Optional[str] = None

    @classmethod
    def from_caldav_object(cls, obj: Any, calendar_name: Optional[str] = None) -> "EventInfo":
        comp = _component_of(obj)
        start = _datetime(comp, "dtstart")
        end = _datetime(comp, "dtend")
        all_day = isinstance(start, dt.date) and not isinstance(start, dt.datetime)
        return cls(
            uid=_text(comp, "uid"),
            summary=_text(comp, "summary"),
            start=start,
            end=end,
            location=_text(comp, "location"),
            description=_text(comp, "description"),
            all_day=all_day,
            calendar=calendar_name,
            url=str(getattr(obj, "url", "")) or None,
        )

    @classmethod
    def from_graph(cls, event: dict, calendar_name: Optional[str] = None) -> "EventInfo":
        """Build from a Microsoft Graph event resource."""
        location = (event.get("location") or {}).get("displayName")
        body = (event.get("body") or {}).get("content") or event.get("bodyPreview")
        return cls(
            uid=event.get("id"),
            summary=event.get("subject"),
            start=_parse_graph_datetime(event.get("start")),
            end=_parse_graph_datetime(event.get("end")),
            location=location or None,
            description=body or None,
            all_day=bool(event.get("isAllDay")),
            calendar=calendar_name,
            url=event.get("webLink"),
        )

    def to_dict(self) -> dict:
        return {
            "uid": self.uid,
            "summary": self.summary,
            "start": _iso(self.start),
            "end": _iso(self.end),
            "location": self.location,
            "description": self.description,
            "all_day": self.all_day,
            "calendar": self.calendar,
            "url": self.url,
        }


@dataclass
class ReminderInfo:
    """A reminder / task (VTODO)."""

    uid: Optional[str]
    summary: Optional[str]
    due: Optional[dt.datetime | dt.date] = None
    status: Optional[str] = None
    priority: Optional[int] = None
    percent_complete: Optional[int] = None
    completed: bool = False
    description: Optional[str] = None
    list_name: Optional[str] = None
    url: Optional[str] = None

    @classmethod
    def from_caldav_object(cls, obj: Any, list_name: Optional[str] = None) -> "ReminderInfo":
        comp = _component_of(obj)
        status = _text(comp, "status")
        percent = _int(comp, "percent-complete")
        completed = (status or "").upper() == "COMPLETED" or percent == 100
        return cls(
            uid=_text(comp, "uid"),
            summary=_text(comp, "summary"),
            due=_datetime(comp, "due"),
            status=status,
            priority=_int(comp, "priority"),
            percent_complete=percent,
            completed=completed,
            description=_text(comp, "description"),
            list_name=list_name,
            url=str(getattr(obj, "url", "")) or None,
        )

    @classmethod
    def from_graph(cls, task: dict, list_name: Optional[str] = None) -> "ReminderInfo":
        """Build from a Microsoft Graph To Do task resource."""
        status = task.get("status")
        completed = status == "completed"
        body = (task.get("body") or {}).get("content")
        importance = (task.get("importance") or "").lower()
        return cls(
            uid=task.get("id"),
            summary=task.get("title"),
            due=_parse_graph_datetime(task.get("dueDateTime")),
            status=status,
            priority=_GRAPH_IMPORTANCE_TO_PRIORITY.get(importance),
            percent_complete=100 if completed else None,
            completed=completed,
            description=body or None,
            list_name=list_name,
            url=None,
        )

    def to_dict(self) -> dict:
        return {
            "uid": self.uid,
            "summary": self.summary,
            "due": _iso(self.due),
            "status": self.status,
            "priority": self.priority,
            "percent_complete": self.percent_complete,
            "completed": self.completed,
            "description": self.description,
            "list_name": self.list_name,
            "url": self.url,
        }

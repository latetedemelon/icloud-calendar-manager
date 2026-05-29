"""Command-line interface for the iCloud Calendar Manager.

Examples::

    icloud-calendar check
    icloud-calendar calendars list
    icloud-calendar events list --calendar "Home" --days 7
    icloud-calendar events add --calendar "Home" --summary "Lunch" \
        --start 2026-06-01T12:00 --end 2026-06-01T13:00
    icloud-calendar reminders add --list "Reminders" --summary "Buy milk" \
        --due 2026-06-01
    icloud-calendar --json calendars list
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import sys
from typing import List, Optional, Sequence

from . import __version__
from .client import EndpointCache
from .exceptions import ConfigurationError, ICloudCalendarError
from .manager import CalendarManager

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2


def parse_datetime(value: str) -> dt.datetime:
    """Parse a CLI date/time argument into a ``datetime``.

    Accepts ISO-like forms with or without a time component.
    """
    text = value.strip()
    formats = (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    )
    for fmt in formats:
        try:
            return dt.datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Invalid date/time {value!r}. Use e.g. 2026-06-01 or 2026-06-01T13:30."
        ) from exc


def _resolve_tz(name: Optional[str]):
    """Resolve an IANA timezone name to a ``tzinfo``, or ``None`` if unset."""
    if not name:
        return None
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name)
    except Exception as exc:  # unknown zone or missing tz database
        raise ICloudCalendarError(
            f"Unknown or unavailable timezone {name!r}: {exc}"
        ) from exc


def _localize(value, tzinfo):
    """Attach ``tzinfo`` to a naive datetime; leave aware/None values unchanged."""
    if value is None or tzinfo is None:
        return value
    if isinstance(value, dt.datetime) and value.tzinfo is None:
        return value.replace(tzinfo=tzinfo)
    return value


def _print_json(data, stream) -> None:
    json.dump(data, stream, indent=2, default=str)
    stream.write("\n")


def _print_table(rows: List[dict], columns: Sequence[str], stream) -> None:
    """Print ``rows`` as a simple aligned text table."""
    if not rows:
        stream.write("(none)\n")
        return
    headers = [c.upper() for c in columns]
    widths = [len(h) for h in headers]
    cells = []
    for row in rows:
        cell = []
        for index, col in enumerate(columns):
            text = "" if row.get(col) is None else str(row.get(col))
            cell.append(text)
            widths[index] = max(widths[index], len(text))
        cells.append(cell)
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    stream.write(line.rstrip() + "\n")
    stream.write("  ".join("-" * widths[i] for i in range(len(columns))) + "\n")
    for cell in cells:
        stream.write("  ".join(cell[i].ljust(widths[i]) for i in range(len(columns))).rstrip() + "\n")


def _emit(rows, columns, use_json: bool, stream) -> None:
    if use_json:
        _print_json(rows, stream)
    else:
        _print_table(rows, columns, stream)


# -- command handlers --------------------------------------------------------


def _cmd_check(args, manager: CalendarManager, stream) -> int:
    info = manager.check_connection()
    if args.json:
        _print_json(info, stream)
    else:
        stream.write(f"Connected as principal: {info['principal_url']}\n")
        stream.write(f"  Calendars:      {info['calendars']}\n")
        stream.write(f"  Reminder lists: {info['reminder_lists']}\n")
    return EXIT_OK


def _cmd_calendars_list(args, manager: CalendarManager, stream) -> int:
    calendars = manager.list_calendars(include_reminder_lists=not args.no_reminders)
    rows = []
    for cal in calendars:
        row = cal.to_dict()
        row["type"] = "reminders" if cal.is_reminder_list else "calendar"
        rows.append(row)
    _emit(rows, ["name", "type", "url"], args.json, stream)
    return EXIT_OK


def _cmd_events_list(args, manager: CalendarManager, stream) -> int:
    if args.days is not None:
        start = dt.datetime.now()
        end = start + dt.timedelta(days=args.days)
    else:
        start = args.start or dt.datetime.now()
        end = args.end or (start + dt.timedelta(days=7))
    events = manager.list_events(args.calendar, start, end)
    rows = [e.to_dict() for e in events]
    _emit(rows, ["start", "end", "summary", "uid"], args.json, stream)
    return EXIT_OK


def _cmd_events_get(args, manager: CalendarManager, stream) -> int:
    event = manager.get_event(args.calendar, args.uid)
    _emit([event.to_dict()], ["start", "end", "summary", "uid"], args.json, stream)
    return EXIT_OK


def _cmd_events_add(args, manager: CalendarManager, stream) -> int:
    tzinfo = _resolve_tz(args.tz)
    event = manager.add_event(
        args.calendar,
        args.summary,
        _localize(args.start, tzinfo),
        _localize(args.end, tzinfo),
        location=args.location,
        description=args.description,
    )
    _emit([event.to_dict()], ["start", "end", "summary", "uid"], args.json, stream)
    return EXIT_OK


def _cmd_events_update(args, manager: CalendarManager, stream) -> int:
    tzinfo = _resolve_tz(args.tz)
    event = manager.update_event(
        args.calendar,
        args.uid,
        summary=args.summary,
        start=_localize(args.start, tzinfo),
        end=_localize(args.end, tzinfo),
        location=args.location,
        description=args.description,
    )
    _emit([event.to_dict()], ["start", "end", "summary", "uid"], args.json, stream)
    return EXIT_OK


def _cmd_events_delete(args, manager: CalendarManager, stream) -> int:
    manager.delete_event(args.calendar, args.uid)
    stream.write(f"Deleted event {args.uid} from {args.calendar!r}.\n")
    return EXIT_OK


def _cmd_reminders_lists(args, manager: CalendarManager, stream) -> int:
    lists = manager.list_reminder_lists()
    rows = [c.to_dict() for c in lists]
    _emit(rows, ["name", "url"], args.json, stream)
    return EXIT_OK


def _cmd_reminders_list(args, manager: CalendarManager, stream) -> int:
    reminders = manager.list_reminders(args.list, include_completed=args.all)
    rows = [r.to_dict() for r in reminders]
    _emit(rows, ["due", "status", "summary", "uid"], args.json, stream)
    return EXIT_OK


def _cmd_reminders_get(args, manager: CalendarManager, stream) -> int:
    reminder = manager.get_reminder(args.list, args.uid)
    _emit([reminder.to_dict()], ["due", "status", "summary", "uid"], args.json, stream)
    return EXIT_OK


def _cmd_reminders_add(args, manager: CalendarManager, stream) -> int:
    tzinfo = _resolve_tz(args.tz)
    reminder = manager.add_reminder(
        args.list,
        args.summary,
        due=_localize(args.due, tzinfo),
        priority=args.priority,
        description=args.description,
    )
    _emit([reminder.to_dict()], ["due", "status", "summary", "uid"], args.json, stream)
    return EXIT_OK


def _cmd_reminders_done(args, manager: CalendarManager, stream) -> int:
    reminder = manager.complete_reminder(args.list, args.uid)
    _emit([reminder.to_dict()], ["due", "status", "summary", "uid"], args.json, stream)
    return EXIT_OK


def _cmd_reminders_delete(args, manager: CalendarManager, stream) -> int:
    manager.delete_reminder(args.list, args.uid)
    stream.write(f"Deleted reminder {args.uid} from {args.list!r}.\n")
    return EXIT_OK


# -- parser ------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="icloud-calendar",
        description="Manage iCloud calendars, events and reminders over CalDAV.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase log verbosity.")
    parser.add_argument("--apple-id", help="Apple ID (overrides $APPLE_ID).")
    parser.add_argument("--timeout", type=int, default=30, help="Network timeout in seconds.")
    parser.add_argument("--cache", help="Path to cache the discovered CalDAV endpoint.")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="Verify the connection and summarize the account.").set_defaults(
        func=_cmd_check
    )

    # calendars
    calendars = sub.add_parser("calendars", help="Work with calendars.")
    cal_sub = calendars.add_subparsers(dest="action", required=True)
    cal_list = cal_sub.add_parser("list", help="List calendars and reminder lists.")
    cal_list.add_argument("--no-reminders", action="store_true", help="Exclude reminder lists.")
    cal_list.set_defaults(func=_cmd_calendars_list)

    # events
    events = sub.add_parser("events", help="Work with calendar events.")
    ev_sub = events.add_subparsers(dest="action", required=True)

    ev_list = ev_sub.add_parser("list", help="List events in a calendar.")
    ev_list.add_argument("--calendar", required=True, help="Calendar name.")
    ev_list.add_argument("--days", type=int, help="Window of N days from now.")
    ev_list.add_argument("--start", type=parse_datetime, help="Window start (ISO).")
    ev_list.add_argument("--end", type=parse_datetime, help="Window end (ISO).")
    ev_list.set_defaults(func=_cmd_events_list)

    ev_get = ev_sub.add_parser("get", help="Fetch a single event by UID.")
    ev_get.add_argument("--calendar", required=True)
    ev_get.add_argument("--uid", required=True)
    ev_get.set_defaults(func=_cmd_events_get)

    ev_add = ev_sub.add_parser("add", help="Add an event.")
    ev_add.add_argument("--calendar", required=True)
    ev_add.add_argument("--summary", required=True)
    ev_add.add_argument("--start", required=True, type=parse_datetime)
    ev_add.add_argument("--end", type=parse_datetime)
    ev_add.add_argument("--location")
    ev_add.add_argument("--description")
    ev_add.add_argument("--tz", help="IANA timezone for naive start/end, e.g. America/New_York.")
    ev_add.set_defaults(func=_cmd_events_add)

    ev_update = ev_sub.add_parser("update", help="Update an event by UID.")
    ev_update.add_argument("--calendar", required=True)
    ev_update.add_argument("--uid", required=True)
    ev_update.add_argument("--summary")
    ev_update.add_argument("--start", type=parse_datetime)
    ev_update.add_argument("--end", type=parse_datetime)
    ev_update.add_argument("--location")
    ev_update.add_argument("--description")
    ev_update.add_argument("--tz", help="IANA timezone for naive start/end, e.g. America/New_York.")
    ev_update.set_defaults(func=_cmd_events_update)

    ev_delete = ev_sub.add_parser("delete", help="Delete an event by UID.")
    ev_delete.add_argument("--calendar", required=True)
    ev_delete.add_argument("--uid", required=True)
    ev_delete.set_defaults(func=_cmd_events_delete)

    # reminders
    reminders = sub.add_parser("reminders", help="Work with reminders (VTODO).")
    rem_sub = reminders.add_subparsers(dest="action", required=True)

    rem_lists = rem_sub.add_parser("lists", help="List reminder lists.")
    rem_lists.set_defaults(func=_cmd_reminders_lists)

    rem_list = rem_sub.add_parser("list", help="List reminders in a list.")
    rem_list.add_argument("--list", required=True, help="Reminder list name.")
    rem_list.add_argument("--all", action="store_true", help="Include completed reminders.")
    rem_list.set_defaults(func=_cmd_reminders_list)

    rem_get = rem_sub.add_parser("get", help="Fetch a single reminder by UID.")
    rem_get.add_argument("--list", required=True)
    rem_get.add_argument("--uid", required=True)
    rem_get.set_defaults(func=_cmd_reminders_get)

    rem_add = rem_sub.add_parser("add", help="Add a reminder.")
    rem_add.add_argument("--list", required=True)
    rem_add.add_argument("--summary", required=True)
    rem_add.add_argument("--due", type=parse_datetime)
    rem_add.add_argument("--priority", type=int)
    rem_add.add_argument("--description")
    rem_add.add_argument("--tz", help="IANA timezone for a naive --due, e.g. America/New_York.")
    rem_add.set_defaults(func=_cmd_reminders_add)

    rem_done = rem_sub.add_parser("done", help="Mark a reminder complete.")
    rem_done.add_argument("--list", required=True)
    rem_done.add_argument("--uid", required=True)
    rem_done.set_defaults(func=_cmd_reminders_done)

    rem_delete = rem_sub.add_parser("delete", help="Delete a reminder by UID.")
    rem_delete.add_argument("--list", required=True)
    rem_delete.add_argument("--uid", required=True)
    rem_delete.set_defaults(func=_cmd_reminders_delete)

    return parser


def _configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    manager: Optional[CalendarManager] = None,
    stream=None,
) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    stream = stream or sys.stdout
    _configure_logging(args.verbose)

    try:
        if manager is None:
            cache = EndpointCache(args.cache) if args.cache else None
            manager = CalendarManager.from_env(
                apple_id=args.apple_id, timeout=args.timeout, cache=cache
            )
        return args.func(args, manager, stream)
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except ICloudCalendarError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

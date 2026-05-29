# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-05-29

This release consolidates all outstanding branches (`patch-1`, `Reminders`) and
grows the single script into a tested, installable package with a CLI.

### Added
- **Command-line interface** (`icloud-calendar`): `check`, `calendars list`,
  `events list/get/add/update/delete`, `reminders lists/list/add/done/delete`,
  with human-readable tables or `--json` output.
- **`CalendarManager`** class providing the full API with dependency injection
  for testing.
- **Reminder (VTODO) support**: list, add, complete, and delete reminders, plus
  reminder-list discovery.
- **Typed models** `CalendarInfo`, `EventInfo`, `ReminderInfo` with
  `to_dict()` JSON serialization.
- **Endpoint cache** (`EndpointCache`) to optionally persist and reuse the
  discovered CalDAV partition URL.
- **Packaging**: `pyproject.toml`, `icloud-calendar` console script, `py.typed`
  marker (PEP 561), `LICENSE` (MIT), `.gitignore`, `.flake8`.
- **Tests**: 58 pytest tests covering config, models, client, manager,
  reminders, CLI, backwards compatibility, and the real `caldav` edit idiom — all
  without network access.
- **CI**: matrix across Python 3.9–3.12; installs the package and runs
  flake8 + pytest.

### Changed
- Authentication now uses the reliable base-URL + principal-discovery flow
  (works with app-specific passwords); the partition URL is derived from the
  principal rather than a `setup.icloud.com` login POST.
- Reminders are represented as **VTODO** (via `save_todo()` / `todos()`) instead
  of being read with the calendar `events()` call.
- Reminder lists are detected via the collection's supported components
  (`VTODO`) instead of the brittle `X-APPLE-SUBCALENDAR-TYPE` property.
- README rewritten to document the CLI and library APIs.

### Fixed
- `events list` no longer crashes when invoked without a date window
  (previously `None + timedelta`); it defaults to the next 7 days.
- Endpoint caching no longer crashes on a bare filename
  (`os.makedirs("")` from the original `build_caldav_endpoint`).

### Compatibility
- The original module-level functions (`list_calendars`,
  `get_apple_calendar_events`, `add_event_to_calendar`,
  `update_event_in_calendar`, `delete_event_from_calendar`,
  `list_reminder_lists`, `get_reminders`, plus `get_caldav_client` /
  `find_calendar`) are retained and now delegate to `CalendarManager`.
- **Breaking:** the project is now a package, so `python icloud_calendar_manager.py`
  is replaced by the `icloud-calendar` command or
  `python -m icloud_calendar_manager`.

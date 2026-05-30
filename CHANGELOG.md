# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.6.0] - 2026-05-30

Broaden coverage to the major self-hosted / open-source CalDAV servers via named
presets, and make per-provider capabilities explicit.

### Added
- **Self-hosted CalDAV presets:** `nextcloud`, `owncloud`, `radicale`, `baikal`,
  `sogo`, `davical`, `zimbra`, `synology`, and `vikunja`, plus hosted `posteo`,
  `mailbox` (mailbox.org), and `gmx`. Each carries the correct DAV path and
  capability flags. (Any RFC-4791 server already worked via `generic`; these add
  convenience and accuracy.)
- **URL/path resolution** (`resolve_provider_url`): pass a bare host
  (`--url https://cloud.example.com`) and the provider's conventional DAV path
  (e.g. Nextcloud's `/remote.php/dav`) is appended automatically; idempotent if
  the full path is already given. Trailing slashes are normalized.
- **`/.well-known/caldav` helper** (`well_known_url`) and a `well_known` flag on
  self-hosted providers.
- **Events capability gate:** providers now declare `supports_events`; tasks-only
  servers (Vikunja) reject event operations with a clear `CapabilityError`, the
  mirror of the existing reminders gate.
- **`providers` command** now reports `events`, `self_hosted`, and `experimental`
  columns.
- New docs: `COMPATIBILITY.md` (full provider matrix) and `OBSIDIAN.md`
  (investigation of a possible export bridge — not implemented).

### Changed
- `resolve_auth` combines the supplied host with the provider's preset path and
  normalizes trailing slashes (a bare `https://host/` now yields `https://host`).
- The "missing URL" error now refers to self-hosted providers generally, not
  just `generic`.

### Notes
- **Obsidian** is intentionally **not** a provider — it is not a CalDAV/CardDAV
  server. See `OBSIDIAN.md`.
- **CardDAV / contacts** remain out of scope (calendars + reminders only).
- 129 tests passing; self-hosted and OAuth providers remain unvalidated against
  live instances in CI.

## [0.5.0] - 2026-05-29

Follow-ups to multi-provider support, addressing the three review items from
0.4.0.

### Added
- **OAuth2 refresh-token support** (`oauth.py`): for Google and Microsoft you can
  now supply a refresh token (`--refresh-token` + `--client-id`
  [+ `--client-secret`], or env vars) and the tool mints access tokens
  automatically via the OAuth2 refresh-token grant, caching and renewing them.
  A directly-supplied `--token` still works. The initial interactive consent
  flow remains out of scope.
- **Google Tasks reminders**: the `google` provider now supports reminders via
  the Google Tasks API. `GoogleBackend` is a composite that routes events to
  CalDAV and reminders to Google Tasks using the same OAuth token.
- **`calendar-manager` console-script alias** (provider-neutral) alongside the
  existing `icloud-calendar`. Both invoke the same CLI; the help/usage adapts to
  whichever name was used.
- Shared `BearerTransport` + `json_or_raise` helper (`backends/transport.py`)
  used by both the Graph and Google Tasks backends.
- Public exports: `OAuthRefreshConfig`, `TokenProvider`, `refresh_access_token`.

### Changed
- `google` provider now advertises `supports_reminders=True`.
- `resolve_auth(..., allow_missing_secret=True)` permits constructing auth when a
  refresh token (rather than an access token) will be supplied.

### Tests
- 116 passing (was 93): OAuth refresh/caching, Google Tasks round-trip, the
  composite Google backend routing, `build_backend` wiring, and the CLI alias /
  refresh-token flags — all without network access.

## [0.4.0] - 2026-05-29

Multi-provider support: the tool now manages calendars beyond iCloud.

### Added
- **Provider support** for Fastmail, Yahoo, generic CalDAV (`--url`), Google
  Calendar (CalDAV over an OAuth2 bearer token), and Microsoft 365 / Outlook
  (via the Microsoft Graph REST API). Select with `--provider` (default
  `icloud`).
- **`providers` CLI command** listing the supported providers (no credentials
  required), with `--json` support.
- **Backend abstraction** (`backends/`): a `CalendarBackend` interface with a
  `CalDAVBackend` (all CalDAV providers) and a `GraphBackend` (Microsoft Graph).
- **Provider registry** (`providers.py`) and a generalized `AuthConfig` /
  `resolve_auth` in `config.py` supporting Basic and Bearer authentication,
  with provider-specific and generic environment variables.
- `CalendarManager.from_provider(...)`; bearer-token CalDAV client builder
  `build_caldav_client(...)`; `EventInfo.from_graph` / `ReminderInfo.from_graph`
  parsers; `CapabilityError` for unsupported operations.
- New unit tests (93 passing total) including a full Microsoft Graph round-trip
  exercised through an in-memory fake transport (no network).

### Changed
- `CalendarManager` is now a thin, provider-agnostic facade that delegates to a
  backend. iCloud remains the default and **all existing CLI commands, library
  calls, and backwards-compatible helpers are unchanged.**
- Reminders are gated by provider capability (e.g. Google CalDAV exposes no
  reminders, so those operations raise `CapabilityError`).

### Notes
- Google and Microsoft are **experimental**: unit-tested with mocks, but they
  require a caller-supplied OAuth2 access token and have not been validated
  against live accounts in CI. Token acquisition/refresh is out of scope.
- The distribution/command name remains `icloud-calendar` for compatibility
  despite the broader scope. A rename is tracked in `DECISIONS.md`.

## [0.3.0] - 2026-05-29

Follow-up improvements after the 0.2.0 consolidation.

### Added
- **Timezone support:** `--tz <IANA name>` on `events add`, `events update`, and
  `reminders add` localizes naive start/end/due times (e.g. `America/New_York`).
  Date arguments also accept UTC offsets directly (e.g. `...T09:00-04:00`).
- **`reminders get --list --uid`** (and `CalendarManager.get_reminder`) for
  symmetry with `events get`.
- **Opt-in, read-only integration test** (`tests/test_integration.py`), skipped
  unless `ICLOUD_INTEGRATION=1` and credentials are set; it never mutates the
  account.
- `tzdata` added to the `dev` extras so `zoneinfo` works deterministically
  across platforms.

### Notes
- Without `--tz`, naive times remain "floating" (unchanged behavior).

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

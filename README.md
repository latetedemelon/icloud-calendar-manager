# iCloud Calendar Manager

A small, tested Python toolkit and command-line interface for managing **iCloud
calendars, events, and reminders** over the CalDAV protocol.

It can be used three ways:

- **CLI** — `icloud-calendar events list --calendar "Home" --days 7`
- **Library** — `from icloud_calendar_manager import CalendarManager`
- **Backwards-compatible helpers** — the original module-level functions
  (`list_calendars()`, `get_apple_calendar_events()`, …) still work.

## Features

- 📅 List calendars and reminder lists
- 🔎 List events in a date window (with recurrence expansion)
- ➕ Create / ✏️ update / ❌ delete events
- ✅ Full reminder (VTODO) support: list, add, complete, delete
- 🤖 Human-friendly tables **or** `--json` output for scripting
- 🔐 App-specific-password authentication with clear, actionable errors
- 🧪 Fully unit-tested without needing a live iCloud connection

## Requirements

- Python 3.9+
- An Apple ID with an **app-specific password** (see below)

## Installation

```bash
# From a clone of this repository
pip install .

# Or, for development (editable install + test tooling)
pip install -e ".[dev]"
```

This installs the `icloud-calendar` command and the `icloud_calendar_manager`
package.

## Authentication

iCloud uses two-factor authentication, so you must use an **app-specific
password** rather than your primary Apple ID password.

1. Go to <https://appleid.apple.com/> and sign in.
2. Under **Sign-In and Security → App-Specific Passwords**, click **Generate
   Password**.
3. Use the generated value as `APPLE_PASSWORD`.

Provide credentials via environment variables:

```bash
# macOS / Linux
export APPLE_ID='your_apple_id@example.com'
export APPLE_PASSWORD='your-app-specific-password'
```

```cmd
:: Windows (cmd)
set APPLE_ID=your_apple_id@example.com
set APPLE_PASSWORD=your-app-specific-password
```

You can also pass `--apple-id` on the command line; the password is always read
from `$APPLE_PASSWORD` for safety.

## CLI usage

```bash
# Verify the connection and summarize the account
icloud-calendar check

# List calendars and reminder lists
icloud-calendar calendars list
icloud-calendar calendars list --no-reminders     # calendars only

# Events
icloud-calendar events list --calendar "Home" --days 7
icloud-calendar events list --calendar "Home" --start 2026-06-01 --end 2026-06-30
icloud-calendar events get --calendar "Home" --uid <UID>
icloud-calendar events add --calendar "Home" \
    --summary "Lunch with Sam" \
    --start 2026-06-01T12:00 --end 2026-06-01T13:00 \
    --location "Cafe" --description "Catch up"
icloud-calendar events update --calendar "Home" --uid <UID> --summary "New title"
icloud-calendar events delete --calendar "Home" --uid <UID>

# Reminders
icloud-calendar reminders lists
icloud-calendar reminders list --list "Reminders"
icloud-calendar reminders list --list "Reminders" --all      # include completed
icloud-calendar reminders add --list "Reminders" --summary "Buy milk" --due 2026-06-01
icloud-calendar reminders done --list "Reminders" --uid <UID>
icloud-calendar reminders delete --list "Reminders" --uid <UID>

# Machine-readable output (works with any command)
icloud-calendar --json calendars list
```

Dates accept `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM[:SS]`.

You can also run it as a module: `python -m icloud_calendar_manager ...`.

## Library usage

```python
import datetime as dt
from icloud_calendar_manager import CalendarManager

mgr = CalendarManager.from_env()          # reads $APPLE_ID / $APPLE_PASSWORD

for cal in mgr.list_calendars():
    print(cal.name, "(reminders)" if cal.is_reminder_list else "")

events = mgr.list_events(
    "Home",
    dt.datetime.now(),
    dt.datetime.now() + dt.timedelta(days=7),
)
for event in events:
    print(event.start, event.summary)

event = mgr.add_event(
    "Home", "Standup",
    dt.datetime(2026, 6, 1, 9, 0), dt.datetime(2026, 6, 1, 9, 15),
)
mgr.complete_reminder("Reminders", "<uid>")
```

`list_events`, `list_reminders`, etc. return typed dataclasses
(`EventInfo`, `ReminderInfo`, `CalendarInfo`) with a `.to_dict()` method for
easy JSON serialization.

### Backwards-compatible functions

Earlier versions of this project exposed module-level functions. These are
retained and now delegate to `CalendarManager`:

```python
from icloud_calendar_manager import (
    list_calendars, get_apple_calendar_events,
    add_event_to_calendar, update_event_in_calendar, delete_event_from_calendar,
    list_reminder_lists, get_reminders,
)
```

## Running in GitHub Codespaces

1. **Fork** this repository and create a **Codespace** from your fork
   (`Code → Codespaces → New codespace`).
2. Add your credentials as Codespaces secrets
   (`Settings → Secrets and variables → Codespaces`): `APPLE_ID` and
   `APPLE_PASSWORD`. They become environment variables automatically.
   Alternatively set them in the terminal:

   ```bash
   echo 'export APPLE_ID="your_apple_id@example.com"' >> ~/.bashrc
   echo 'export APPLE_PASSWORD="your-app-specific-password"' >> ~/.bashrc
   source ~/.bashrc
   ```

3. Install and run:

   ```bash
   pip install -e ".[dev]"
   icloud-calendar check
   ```

## Project layout

```
icloud_calendar_manager/
├── __init__.py     # public API + backwards-compatible helpers
├── __main__.py     # `python -m icloud_calendar_manager`
├── cli.py          # argparse command-line interface
├── client.py       # CalDAV client, auth, endpoint discovery + caching
├── config.py       # credential resolution
├── exceptions.py   # typed error hierarchy
├── manager.py      # CalendarManager: events + reminders operations
└── models.py       # CalendarInfo / EventInfo / ReminderInfo dataclasses
tests/              # pytest suite (no network required)
```

## Development

```bash
pip install -e ".[dev]"
pytest                # run the test suite
flake8 .              # lint
python -m build       # build wheel + sdist (requires the `build` package)
```

See [`CHANGELOG.md`](CHANGELOG.md) for release notes and
[`DECISIONS.md`](DECISIONS.md) for the rationale behind key design choices.

## Notes & security

- Uses CalDAV; ensure your iCloud account has CalDAV access enabled.
- Keep your Apple ID and app-specific password secret — never commit them.
- The app-specific password can be revoked at any time from your Apple ID
  account page.

## Troubleshooting

- **Authentication errors:** confirm you are using an *app-specific* password,
  not your Apple ID password, and that two-factor authentication is set up.
- **Calendar not found:** names are case-sensitive; run
  `icloud-calendar calendars list` to see exact names.
- **Connection errors:** check network access to `*.icloud.com` over HTTPS.
- If problems persist, Apple Support can help with CalDAV access for your
  account.

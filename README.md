# Calendar Manager (iCloud, Google, Microsoft, Fastmail & more)

A small, tested Python toolkit and command-line interface for managing
**calendars, events, and reminders** across multiple providers — over CalDAV
and Microsoft Graph.

It can be used three ways:

- **CLI** — `icloud-calendar events list --calendar "Home" --days 7`
- **Library** — `from icloud_calendar_manager import CalendarManager`
- **Backwards-compatible helpers** — the original module-level functions
  (`list_calendars()`, `get_apple_calendar_events()`, …) still work.

> The package/command is still named `icloud-calendar` for backward
> compatibility, but it now supports several providers (see below).

## Supported providers

| Provider | `--provider` | Backend | Auth | Reminders |
| --- | --- | --- | --- | --- |
| Apple iCloud *(default)* | `icloud` | CalDAV | app password | ✅ |
| Fastmail | `fastmail` | CalDAV | app password | ✅ |
| Yahoo | `yahoo` | CalDAV | app password | ✅ |
| Generic / Nextcloud | `generic` | CalDAV (`--url`) | password | ✅ |
| Google Calendar | `google` | CalDAV + Tasks API | OAuth token | ✅ (Google Tasks) |
| Microsoft 365 / Outlook | `microsoft` | Microsoft Graph | OAuth token | ✅ (To Do) |

Run `icloud-calendar providers` to see this list at any time. Google and
Microsoft are marked **experimental**: they are unit-tested with mocks but
require you to supply OAuth2 credentials, and have not been validated against
live accounts in CI.

The command is available under two names: **`icloud-calendar`** (kept for
backward compatibility) and **`calendar-manager`** (provider-neutral alias).
They are identical.

## Features

- 🌐 Multiple providers behind one interface (iCloud, Fastmail, Yahoo, Google,
  Microsoft, generic CalDAV)
- 📅 List calendars and reminder lists
- 🔎 List events in a date window (with recurrence expansion)
- ➕ Create / ✏️ update / ❌ delete events
- ✅ Reminder support (VTODO for CalDAV, Microsoft To Do for Graph): list, add,
  complete, delete
- 🕑 Timezone-aware (`--tz`)
- 🤖 Human-friendly tables **or** `--json` output for scripting
- 🔐 App-password and OAuth-token authentication with clear, actionable errors
- 🧪 Fully unit-tested without needing a live connection to any provider

## Requirements

- Python 3.9+
- Credentials for your chosen provider (an app-specific password for
  iCloud/Fastmail/Yahoo, or an OAuth2 token for Google/Microsoft)
- For the Microsoft Graph backend: `requests` (install with
  `pip install ".[graph]"`)

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

## Using other providers

Select a provider with `--provider`. Credentials can be passed as flags or via
environment variables (provider-specific aliases, or the generic
`CALENDAR_USERNAME` / `CALENDAR_PASSWORD` / `CALENDAR_TOKEN` / `CALDAV_URL`).

```bash
# Fastmail (app password with the CalDAV scope)
export FASTMAIL_USERNAME='you@fastmail.com'
export FASTMAIL_PASSWORD='app-password'
icloud-calendar --provider fastmail check

# Yahoo (app password)
icloud-calendar --provider yahoo --username you@yahoo.com check   # reads $YAHOO_PASSWORD

# Generic CalDAV / Nextcloud (you supply the URL)
icloud-calendar --provider generic --url https://cloud.example.com/remote.php/dav/ \
    --username you --token ''   # or set CALENDAR_PASSWORD

# Google (events via CalDAV + reminders via Google Tasks)
export GOOGLE_EMAIL='you@gmail.com'
export GOOGLE_CALENDAR_TOKEN='ya29....'      # an OAuth2 access token you obtained
icloud-calendar --provider google check

# Microsoft 365 / Outlook via Microsoft Graph (OAuth2 access token)
export MICROSOFT_TOKEN='eyJ0eXAi....'         # token with Calendars.ReadWrite, Tasks.ReadWrite
icloud-calendar --provider microsoft check
```

### OAuth2 for Google and Microsoft

You can authenticate the bearer providers two ways:

1. **Supply an access token directly** with `--token` (or the provider env var
   above). Simplest, but access tokens are short-lived.
2. **Supply a refresh token** and let the tool mint access tokens for you. Pass
   `--refresh-token` with `--client-id` (and `--client-secret` for confidential
   clients), or set the env vars:

   ```bash
   # Google
   export GOOGLE_CLIENT_ID='...' GOOGLE_CLIENT_SECRET='...' GOOGLE_REFRESH_TOKEN='...'
   icloud-calendar --provider google --username you@gmail.com check

   # Microsoft (optionally set MICROSOFT_TENANT, default "common")
   export MICROSOFT_CLIENT_ID='...' MICROSOFT_CLIENT_SECRET='...' MICROSOFT_REFRESH_TOKEN='...'
   icloud-calendar --provider microsoft check
   ```

The tool performs the OAuth2 **refresh-token grant** to obtain access tokens; it
does **not** run the initial interactive consent flow. Obtain the refresh token
once with your own tooling (e.g. `oauth2l`, the Google OAuth Playground, or the
Azure CLI / MSAL) and provide it as above.

Scopes required: Google — `https://www.googleapis.com/auth/calendar` and
`https://www.googleapis.com/auth/tasks`; Microsoft — `Calendars.ReadWrite` and
`Tasks.ReadWrite`.

## CLI usage

```bash
# List the supported providers (no credentials required)
icloud-calendar providers

# Verify the connection and summarize the account
icloud-calendar check
icloud-calendar --provider fastmail check         # any provider

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
icloud-calendar events add --calendar "Home" --summary "Call" \
    --start 2026-06-01T09:00 --tz America/New_York   # localize a naive time
icloud-calendar events update --calendar "Home" --uid <UID> --summary "New title"
icloud-calendar events delete --calendar "Home" --uid <UID>

# Reminders
icloud-calendar reminders lists
icloud-calendar reminders list --list "Reminders"
icloud-calendar reminders list --list "Reminders" --all      # include completed
icloud-calendar reminders get --list "Reminders" --uid <UID>
icloud-calendar reminders add --list "Reminders" --summary "Buy milk" --due 2026-06-01
icloud-calendar reminders done --list "Reminders" --uid <UID>
icloud-calendar reminders delete --list "Reminders" --uid <UID>

# Machine-readable output (works with any command)
icloud-calendar --json calendars list
```

Dates accept `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM[:SS]`, optionally with a UTC
offset (e.g. `2026-06-01T09:00-04:00`). For naive times you can pass `--tz`
with an IANA name (e.g. `America/New_York`) to localize them; without it, times
are "floating" (interpreted in the viewing device's timezone).

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
├── __init__.py             # public API + backwards-compatible helpers
├── __main__.py             # `python -m icloud_calendar_manager`
├── cli.py                  # argparse command-line interface
├── client.py               # CalDAV client builders, discovery + caching
├── config.py               # multi-provider credential resolution (AuthConfig)
├── providers.py            # provider registry (iCloud, Google, Microsoft, …)
├── oauth.py                # OAuth2 refresh-token grant + token caching
├── exceptions.py           # typed error hierarchy
├── manager.py              # CalendarManager: provider-agnostic facade
├── models.py               # CalendarInfo / EventInfo / ReminderInfo dataclasses
└── backends/
    ├── base.py             # CalendarBackend interface
    ├── transport.py        # shared bearer-token REST transport
    ├── caldav_backend.py   # CalDAV backend (iCloud/Fastmail/Yahoo/Google/generic)
    ├── google_tasks.py     # Google Tasks + composite Google backend
    └── graph_backend.py    # Microsoft Graph backend (Microsoft 365 / Outlook)
tests/                      # pytest suite (no network required)
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

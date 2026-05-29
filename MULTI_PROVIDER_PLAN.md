# Multi-provider support — design & plan

> Status: **planning only — not implemented.** Today the tool is iCloud-only
> through the CLI. This document captures the intended design so it can be
> reviewed and picked up later. Tracked from `DECISIONS.md §10`.

## Goal

Let the existing calendar/event/reminder operations target **major calendar
providers** beyond iCloud, with the smallest possible change to the public API
and full backward compatibility (iCloud remains the default).

## Provider tiers (grouped by what the integration actually requires)

### Tier 1 — CalDAV + Basic auth (app-specific password)
These work through the **existing** code path almost unchanged; only the base
URL and credentials differ. This is the bulk of the value for the least risk.

| Provider | Base URL | Secret |
|---|---|---|
| iCloud *(done)* | `https://caldav.icloud.com` | app-specific password |
| Fastmail | `https://caldav.fastmail.com/dav/` | app password |
| Yahoo | `https://caldav.calendar.yahoo.com` | app password |
| Nextcloud / generic | user-supplied `--url` | password / app password |
| mailbox.org, Zoho, Zimbra, … | user-supplied `--url` | password |

### Tier 2 — CalDAV + OAuth2 Bearer token
Same CalDAV protocol, but the server wants an `Authorization: Bearer <token>`
header instead of Basic auth.

| Provider | Base URL | Secret |
|---|---|---|
| Google Calendar | `https://apidata.googleusercontent.com/caldav/v2/` | OAuth2 access token |

Google removed Basic-auth CalDAV; a valid OAuth2 access token is required.
Acquiring/refreshing the token (browser consent, `google-auth`) is out of scope
for v1 — the user supplies a token via `--token`/env, and we attach the bearer
header. A token helper can come later.

### Tier 3 — Non-CalDAV REST APIs (separate backend, larger effort)
These do **not** speak CalDAV and need a different client entirely.

| Provider | API | Notes |
|---|---|---|
| Microsoft 365 / Outlook.com | Microsoft Graph | OAuth2; Outlook dropped CalDAV |
| Google (alternative) | Google Calendar API | OAuth2; richer than CalDAV |

Recommendation: defer Tier 3. If/when added, introduce a `CalendarBackend`
interface so `CalendarManager` can sit on top of either a CalDAV backend or a
Graph/REST backend.

## Proposed architecture

1. **`providers.py`** — a `Provider` dataclass and a registry:
   ```python
   @dataclass(frozen=True)
   class Provider:
       key: str                 # "icloud", "fastmail", "google", "generic"
       label: str
       base_url: str | None     # None => requires --url
       auth_scheme: str         # "basic" | "bearer"
       secret_kind: str         # "app-password" | "oauth-token" | "password"
       help_url: str
       notes: str = ""
   PROVIDERS: dict[str, Provider] = { ... }
   ```

2. **`config.py`** — generalize credential resolution:
   - Add `provider` + optional `url` + `username`.
   - Generic env vars `CALDAV_URL` / `CALDAV_USERNAME` / `CALDAV_PASSWORD` /
     `CALDAV_TOKEN`, with provider-specific aliases (`APPLE_ID` / `APPLE_PASSWORD`
     keep working for iCloud).
   - Validate per `secret_kind` (e.g. bearer providers need a token, not a
     password).

3. **`client.build_client`** — choose auth by `auth_scheme`:
   - `basic` → `DAVClient(url, username=…, password=…)` *(current behavior)*.
   - `bearer` → `DAVClient(url, headers={"Authorization": f"Bearer {token}"})`.
   - The `DAVClient.__init__` signature already exposes `headers` and `auth`
     params (verified by introspection), so no library change is needed; the
     bearer path should be validated against a real Google token during
     implementation.

4. **`cli.py`** — add global flags: `--provider` (default `icloud`), `--url`
   (for `generic`/overrides), `--username`, `--token`. Everything else (the
   `calendars`/`events`/`reminders` subcommands) is unchanged because it operates
   on a `CalendarManager` regardless of provider.

5. **`manager.py` / `__init__.py`** — thread `provider`/`url`/`username`/`token`
   through `from_env`/`from_credentials`. Default provider `icloud` keeps all
   existing calls and the backward-compatible module functions working.

## Backward compatibility

- Default `--provider icloud`; `APPLE_ID` / `APPLE_PASSWORD` continue to work.
- All existing CLI invocations and library calls are unchanged.

## Testing strategy

- Unit tests (mocked, no network): provider registry lookups; `build_client`
  selecting Basic vs Bearer; config validation per `secret_kind`; CLI
  `--provider`/`--url` plumbing.
- Per-provider **opt-in, read-only** integration tests mirroring the existing
  iCloud one (credential-gated, skipped in CI, never mutate the account).

## Open decisions / risks

- **Package name:** `icloud_calendar_manager` becomes a misnomer once it's
  multi-provider. Options: (a) keep the import name, document the broader scope;
  (b) rename to e.g. `caldav_calendar_manager` with `icloud_calendar_manager`
  kept as a thin alias for compatibility. ⚑ Needs a call.
- **Console script name:** keep `icloud-calendar`, or add a neutral alias
  (e.g. `caldav-cal`). ⚑ Needs a call.
- **Untestable providers:** Google (OAuth) and Microsoft (Graph) can't be
  exercised in CI without real credentials/OAuth. They'll ship clearly marked
  *experimental* until validated against live accounts.

## Suggested phasing

1. **Phase 1 (low risk, high value):** provider registry + Basic-auth providers
   (Fastmail, Yahoo, generic/`--url`). Fully testable.
2. **Phase 2:** Bearer auth for Google CalDAV (token supplied by user);
   experimental.
3. **Phase 3 (optional, large):** Microsoft Graph backend behind a
   `CalendarBackend` interface; optional Google REST backend; OAuth token
   helpers.

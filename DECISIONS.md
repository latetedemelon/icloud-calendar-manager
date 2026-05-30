# Engineering decisions & notes (for review)

This document records the decisions made while merging the branches and
extending the project, so they can be reviewed and reversed if desired. It was
written during an autonomous working session; items marked **⚑ REVIEW** are
choices I'd especially like a human to confirm.

## 1. Branch merge

All four branches were reconciled onto `claude/jolly-gates-k3jk5`:

- `main` — original script (baseline).
- `patch-1` — refactor adding logging, type hints, `safe_request`,
  `find_calendar`, structured error handling. Merged with `--no-ff`.
- `Reminders` — added `list_reminder_lists()` / `get_reminders()`. It had
  branched from `main`, so it referenced `safe_request` / `find_calendar` /
  `logger` that only existed on `patch-1`; on its own it would fail flake8's
  `F82 undefined name` gate. Merged with `--no-ff` on top of `patch-1`, which
  resolves the dependency.

`git branch -r --merged` confirms `main`, `patch-1`, and `Reminders` are all
contained in the working branch with no unmerged commits.

**Branch cleanup:** I did **not** delete the now-redundant `patch-1` /
`Reminders` remote branches — deleting branches is the owner's call. They can be
deleted after the PR merges since their content is fully incorporated.

## 2. Single script → package

The flat `icloud_calendar_manager.py` was replaced by an
`icloud_calendar_manager/` package (`config`, `exceptions`, `client`, `models`,
`manager`, `cli`, `__init__`, `__main__`). Rationale: testability, a real CLI,
and distribution. Backwards compatibility is preserved via module-level
functions re-exported from `__init__.py`.

- A package directory and a module file of the same name can't coexist, so the
  flat file was removed. `import icloud_calendar_manager` and the documented
  functions still work; only `python icloud_calendar_manager.py` is replaced by
  `icloud-calendar` / `python -m icloud_calendar_manager`.

## 3. Authentication — changed from `patch-1`'s approach  ⚑ REVIEW

`patch-1` authenticated by POSTing to `https://setup.icloud.com/setup/ws/1/login`
and constructing `https://p{p}-caldav.icloud.com/{dsid}/calendars/` manually.
That endpoint is the iCloud *web* login flow and generally does **not** work
with app-specific passwords (it expects the real password + SRP/2FA).

I switched to the reliable, documented path: connect to
`https://caldav.icloud.com` with the app-specific password and let the library
follow iCloud's redirect during principal discovery. The partition host is then
*derived from the principal* and cached (optionally) — preserving `patch-1`'s
"discover once, reuse" intent without the fragile login POST.

This means `authenticate_icloud()` / `build_caldav_endpoint()` from `patch-1`
were **not** carried over as public functions. If you depended on them, let me
know and I can provide compatible shims.

## 4. Reminders use VTODO, not events

The `Reminders` branch read reminders via `reminder_list.events()`. In CalDAV,
reminders are **VTODO** components, so listing is done with `todos()` and
creation with `save_todo()`. Completion sets `STATUS=COMPLETED`,
`PERCENT-COMPLETE=100`, and `COMPLETED=<now>`.

Reminder lists are detected via `get_supported_components()` returning `VTODO`
(and not `VEVENT`), rather than the `X-APPLE-SUBCALENDAR-TYPE` private property
the branch used, which isn't reliably exposed.

## 5. Verified: the caldav edit idiom actually persists

`update_event` / `complete_reminder` mutate `obj.icalendar_component` then call
`obj.save()`. I confirmed (by reading `caldav` source **and** an executable
test, `tests/test_caldav_idiom.py`) that accessing `icalendar_component` clears
the object's cached `_data` (via the `icalendar_instance` setter), so `save()`
serializes the **mutated** instance into the PUT body. Without that, edits would
have silently PUT stale data. This is now covered by a regression test.

## 6. Licensing  ⚑ REVIEW

`pyproject.toml` declares the project MIT-licensed, so I added a matching
`LICENSE` file (`Copyright (c) 2026 latetedemelon and contributors`). If you
prefer a different license or copyright holder, change both `LICENSE` and the
`license` field in `pyproject.toml`.

## 7. Merging the PR to `main`  ⚑ REVIEW

You asked to "merge all branches." I interpreted that as: once CI is green,
merge PR #1 into `main` so everything is consolidated on the default branch.
This is reversible with `git revert` and the PR remains as a record. If you
wanted the PR left open for manual review instead, revert the merge — the diff
is unchanged.

## 8. Bugs fixed during review

- `events list` with no `--days`/`--start` crashed (`None + timedelta`); now
  defaults to the next 7 days.
- `EndpointCache.save` handles a bare filename; `patch-1`'s
  `os.makedirs(os.path.dirname("caldav_endpoint.json"))` raised on `""`.

## 9. Tests & CI

- 58 tests, fully mocked via in-memory CalDAV fakes (`tests/conftest.py`); no
  network needed. The real-library idiom is additionally checked in
  `tests/test_caldav_idiom.py`.
- CI runs a Python 3.9–3.12 matrix, installs the package (`pip install -e .[dev]`),
  and runs flake8 + pytest.

## 10. Known limitations / future work

Addressed in 0.3.0 (follow-up PR):

- **Time zones** — added `--tz <IANA>` on `events add/update` and
  `reminders add` to localize naive times; date args also accept UTC offsets.
  Decision: without `--tz`, times stay "floating" (backward compatible) rather
  than imposing a possibly-wrong default local zone. ⚑ Confirm this default is
  what you want.
- **`reminders get`** — added for symmetry with `events get`.
- **Live integration test** — added as opt-in/read-only
  (`tests/test_integration.py`), skipped unless `ICLOUD_INTEGRATION=1` and
  credentials are present; never mutates the account.

Still open:

- **Recurring events:** listing expands recurrences (`expand=True`), but editing
  a single occurrence of a recurring series isn't specially handled.
- **Config file:** only env vars + CLI flags are supported for credentials; a
  config-file option could be added.

## 11. Multi-provider support (0.4.0)

Implemented the expansion designed in `MULTI_PROVIDER_PLAN.md`. Key decisions:

- **Backend abstraction.** Introduced a `CalendarBackend` interface with two
  implementations: `CalDAVBackend` (iCloud, Fastmail, Yahoo, Google, generic)
  and `GraphBackend` (Microsoft 365 via Microsoft Graph REST). `CalendarManager`
  became a thin provider-agnostic facade delegating to a backend. This keeps the
  CLI and the public API identical across providers.
- **Backward compatibility preserved.** Default provider is `icloud`;
  `from_env`, `from_credentials`, the `principal=`/`client=` injection used by
  tests, and all module-level helper functions still work. The original 64 tests
  pass unchanged; total is now 93.
- **Auth.** `resolve_auth` supports Basic (username + app password) and Bearer
  (OAuth2 access token) schemes, resolved from explicit args → provider-specific
  env vars → generic `CALENDAR_*` / `CALDAV_URL` vars → provider defaults.
  Secrets are never shown in `repr`.
- **Microsoft is REST, not CalDAV.** Outlook dropped CalDAV, so `GraphBackend`
  talks to Microsoft Graph over HTTPS. Reminders map to **Microsoft To Do**
  tasks. The HTTP layer is injected (`transport`) so it is fully unit-tested
  with a fake; `requests` is an optional `[graph]` extra (also pulled by
  `caldav`).
- **Experimental labelling.** `google` and `microsoft` are flagged
  `experimental` (shown by `providers`): unit-tested with mocks but not
  validated against live accounts in CI.

## 12. 0.5.0 — resolved the three 0.4.0 review items

All three items you approved are implemented:

- **OAuth token helper (was: out of scope).** `oauth.py` implements the OAuth2
  *refresh-token grant* with a caching `TokenProvider`. Users supply a refresh
  token + client id/secret (flags or env) and the tool mints/renews access
  tokens. A direct `--token` still works. Decision: we implement *refresh* only,
  not the initial interactive *consent* flow — obtaining the first refresh token
  is a one-time browser step best done with dedicated tooling, and baking a
  local web-server/consent flow into a CLI adds significant surface area for
  little gain. ⚑ Revisit if you want full interactive login.
- **Google reminders (was: unsupported).** Implemented via the Google Tasks REST
  API. `GoogleBackend` is a **composite**: events go through CalDAV, reminders
  through `GoogleTasksBackend`, sharing one OAuth token. `google` now reports
  `supports_reminders=True`. Decision: compose rather than fold Tasks into the
  CalDAV backend, keeping each backend single-responsibility and independently
  testable.
- **Naming (was: undecided).** Added a provider-neutral **`calendar-manager`**
  console-script alias while **keeping `icloud-calendar`** and the
  `icloud_calendar_manager` import name for full backward compatibility. The CLI
  `prog` is derived from the invoked name, so help text reads correctly under
  either. Decision: an alias (not a rename) avoids breaking existing users,
  scripts, and imports. A full distribution rename remains possible later if you
  want it.

Still open (unchanged): interactive OAuth consent flow; editing single
occurrences of recurring events; a credentials config-file.

## 13. 0.6.0 — self-hosted CalDAV presets, capability gating, Obsidian

Scope was chosen with the user: **CalDAV presets + discovery now; no CardDAV;
investigate (not build) an Obsidian bridge.**

- **Presets over new protocols.** Every RFC-4791 server already worked through
  `generic --url`. Rather than add protocols, 0.6.0 adds *named presets*
  (Nextcloud, ownCloud, Radicale, Baïkal, SOGo, DAViCal, Zimbra, Synology,
  Vikunja; plus hosted Posteo/mailbox.org/GMX) that supply the right DAV path
  and accurate capability flags. Decision: presets are data in the registry, so
  adding more is a one-entry change, and `generic` remains the catch-all.
- **URL resolution is a pure function** (`resolve_provider_url`) that appends a
  provider's `path_suffix` to a bare host and is idempotent. Kept pure so it is
  unit-tested without a network. Trailing-slash normalization is intentional and
  harmless for CalDAV.
- **Events capability gate.** Added `supports_events` to mirror
  `supports_reminders`, so tasks-only servers (**Vikunja**) reject event
  operations with `CapabilityError` instead of confusing server errors.
- **CardDAV / contacts: deliberately excluded.** The user chose calendars-only
  for now. Contacts would be a new domain (address books, vCards) and overlaps a
  separate private contact-merge client; revisit if those should converge.
- **Obsidian: not a provider.** It is not a CalDAV/CardDAV server, so it cannot
  be added to the registry. Per the user's choice, `OBSIDIAN.md` records an
  investigation of a one-directional Markdown/ICS **export bridge** as a possible
  future, separate feature; nothing was implemented.
- **`.well-known` discovery.** A `well_known_url` helper and provider flag are in
  place; the `caldav` library already follows the server's redirects during
  principal discovery, so this is a thin, mostly-future-proofing addition rather
  than a custom discovery client.

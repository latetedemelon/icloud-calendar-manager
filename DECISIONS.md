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

- **Time zones:** datetimes are passed through as given. Naive datetimes become
  "floating" time in iCalendar. A `--tz` option (or tz-aware defaults) would be
  a good follow-up.
- **Recurring events:** listing expands recurrences (`expand=True`), but editing
  a single occurrence of a recurring series isn't specially handled.
- **No live integration test:** by design, CI never contacts iCloud. A manual or
  opt-in (credential-gated) integration test could be added.
- **Config file:** only env vars + CLI flags are supported for credentials; a
  config-file option could be added.
- **Reminder fetch-by-uid in CLI:** `events get` exists; a `reminders get` could
  be added for symmetry.

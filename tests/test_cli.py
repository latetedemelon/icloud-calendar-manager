"""Tests for the argparse CLI, driven through a fake-backed manager."""

from __future__ import annotations

import datetime as dt
import io
import json

import argparse
import pytest

from icloud_calendar_manager import cli


def run(argv, manager):
    stream = io.StringIO()
    code = cli.main(argv, manager=manager, stream=stream)
    return code, stream.getvalue()


def test_parse_datetime_formats():
    assert cli.parse_datetime("2026-06-01") == dt.datetime(2026, 6, 1, 0, 0)
    assert cli.parse_datetime("2026-06-01T13:30") == dt.datetime(2026, 6, 1, 13, 30)
    assert cli.parse_datetime("2026-06-01 13:30:45") == dt.datetime(2026, 6, 1, 13, 30, 45)


def test_parser_prog_name_follows_invocation():
    # When prog is None, argparse derives it from sys.argv[0]; an explicit prog
    # (as the console-script wrappers effectively provide) is honored.
    parser = cli.build_parser(prog="calendar-manager")
    assert parser.prog == "calendar-manager"
    parser_icloud = cli.build_parser(prog="icloud-calendar")
    assert parser_icloud.prog == "icloud-calendar"


def test_refresh_token_flags_reach_from_provider(monkeypatch):
    captured = {}

    def fake_from_provider(provider, **kwargs):
        captured["provider"] = provider
        captured.update(kwargs)
        raise cli.ConfigurationError("stop here")  # short-circuit after capture

    monkeypatch.setattr(cli.CalendarManager, "from_provider", staticmethod(fake_from_provider))
    code = cli.main(
        [
            "--provider", "google", "--username", "me@gmail.com",
            "--refresh-token", "rt", "--client-id", "cid", "--client-secret", "sec",
            "check",
        ]
    )
    assert code == 2  # ConfigurationError -> EXIT_CONFIG
    assert captured["provider"] == "google"
    assert captured["refresh_token"] == "rt"
    assert captured["client_id"] == "cid"
    assert captured["client_secret"] == "sec"


def test_parse_datetime_invalid():
    with pytest.raises(argparse.ArgumentTypeError):
        cli.parse_datetime("not-a-date")


def test_providers_command_needs_no_credentials(monkeypatch):
    # 'providers' is static; it must work with no manager and no credentials.
    monkeypatch.delenv("APPLE_ID", raising=False)
    monkeypatch.delenv("APPLE_PASSWORD", raising=False)
    stream = io.StringIO()
    code = cli.main(["providers"], stream=stream)
    assert code == 0
    out = stream.getvalue()
    assert "icloud" in out and "microsoft" in out and "fastmail" in out


def test_providers_command_json(monkeypatch):
    monkeypatch.delenv("APPLE_ID", raising=False)
    monkeypatch.delenv("APPLE_PASSWORD", raising=False)
    stream = io.StringIO()
    code = cli.main(["--json", "providers"], stream=stream)
    assert code == 0
    data = json.loads(stream.getvalue())
    assert {p["key"] for p in data} == {
        "icloud", "fastmail", "yahoo", "google", "microsoft", "generic"
    }


def test_check_command(manager):
    code, out = run(["check"], manager)
    assert code == 0
    assert "principal" in out
    assert "Calendars" in out


def test_calendars_list_table(manager):
    code, out = run(["calendars", "list"], manager)
    assert code == 0
    assert "Home" in out
    assert "Reminders" in out
    assert "reminders" in out  # the type column for the reminder list


def test_calendars_list_json(manager):
    code, out = run(["--json", "calendars", "list"], manager)
    assert code == 0
    data = json.loads(out)
    names = {row["name"] for row in data}
    assert names == {"Home", "Reminders"}


def test_events_add_then_list(manager):
    code, out = run(
        [
            "--json",
            "events",
            "add",
            "--calendar",
            "Home",
            "--summary",
            "Demo",
            "--start",
            "2026-06-01T09:00",
            "--end",
            "2026-06-01T10:00",
        ],
        manager,
    )
    assert code == 0
    created = json.loads(out)[0]
    assert created["summary"] == "Demo"

    code, out = run(
        ["--json", "events", "list", "--calendar", "Home", "--days", "3650"], manager
    )
    assert code == 0
    listed = json.loads(out)
    assert any(e["summary"] == "Demo" for e in listed)


def test_events_list_defaults_without_window(manager):
    # Regression: `events list` with no --days/--start must not crash.
    code, out = run(["events", "list", "--calendar", "Home"], manager)
    assert code == 0
    assert "(none)" in out


def test_events_get(manager):
    code, out = run(
        [
            "--json", "events", "add", "--calendar", "Home", "--summary", "Findme",
            "--start", "2026-06-01T09:00", "--end", "2026-06-01T10:00",
        ],
        manager,
    )
    uid = json.loads(out)[0]["uid"]
    code, out = run(
        ["--json", "events", "get", "--calendar", "Home", "--uid", uid], manager
    )
    assert code == 0
    assert json.loads(out)[0]["summary"] == "Findme"


def test_events_get_missing_returns_error(manager):
    code, _ = run(["events", "get", "--calendar", "Home", "--uid", "nope"], manager)
    assert code == 1


def test_reminders_add_list_done(manager):
    code, _ = run(
        ["reminders", "add", "--list", "Reminders", "--summary", "Task A"], manager
    )
    assert code == 0

    code, out = run(["--json", "reminders", "list", "--list", "Reminders"], manager)
    reminders = json.loads(out)
    assert len(reminders) == 1
    uid = reminders[0]["uid"]

    code, out = run(
        ["--json", "reminders", "done", "--list", "Reminders", "--uid", uid], manager
    )
    assert code == 0
    assert json.loads(out)[0]["completed"] is True

    # Now hidden from the default listing.
    code, out = run(["--json", "reminders", "list", "--list", "Reminders"], manager)
    assert json.loads(out) == []


def test_reminders_delete(manager):
    code, out = run(
        ["--json", "reminders", "add", "--list", "Reminders", "--summary", "Temp"], manager
    )
    uid = json.loads(out)[0]["uid"]
    code, out = run(
        ["reminders", "delete", "--list", "Reminders", "--uid", uid], manager
    )
    assert code == 0
    assert "Deleted reminder" in out


def test_missing_credentials_returns_config_exit(monkeypatch):
    monkeypatch.delenv("APPLE_ID", raising=False)
    monkeypatch.delenv("APPLE_PASSWORD", raising=False)
    # manager is None -> main builds one from env, which fails cleanly.
    code = cli.main(["calendars", "list"])
    assert code == 2


def test_table_output_for_empty_results(manager):
    code, out = run(["events", "list", "--calendar", "Home", "--days", "1"], manager)
    assert code == 0
    assert "(none)" in out


def test_events_add_with_timezone(manager):
    code, out = run(
        [
            "--json", "events", "add", "--calendar", "Home", "--summary", "TZ",
            "--start", "2026-06-01T09:00", "--end", "2026-06-01T10:00",
            "--tz", "America/New_York",
        ],
        manager,
    )
    assert code == 0
    start = json.loads(out)[0]["start"]
    # ISO string should now carry a UTC offset (e.g. -04:00 in June / DST).
    assert "-04:00" in start or "-05:00" in start


def test_events_add_unknown_timezone_errors(manager):
    code, _ = run(
        [
            "events", "add", "--calendar", "Home", "--summary", "Bad",
            "--start", "2026-06-01T09:00", "--tz", "Not/AZone",
        ],
        manager,
    )
    assert code == 1


def test_reminders_get(manager):
    code, out = run(
        ["--json", "reminders", "add", "--list", "Reminders", "--summary", "G"], manager
    )
    uid = json.loads(out)[0]["uid"]
    code, out = run(
        ["--json", "reminders", "get", "--list", "Reminders", "--uid", uid], manager
    )
    assert code == 0
    assert json.loads(out)[0]["summary"] == "G"


def test_resolve_and_localize_helpers():
    assert cli._resolve_tz(None) is None
    tz = cli._resolve_tz("America/New_York")
    naive = dt.datetime(2026, 6, 1, 9, 0)
    localized = cli._localize(naive, tz)
    assert localized.tzinfo is not None
    # An already-aware datetime is left unchanged.
    aware = dt.datetime(2026, 6, 1, 9, 0, tzinfo=dt.timezone.utc)
    assert cli._localize(aware, tz) is aware

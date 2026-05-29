"""Opt-in, read-only integration test against a real iCloud account.

This test is skipped unless you explicitly opt in, so it never runs in CI:

    ICLOUD_INTEGRATION=1 APPLE_ID=... APPLE_PASSWORD=... pytest tests/test_integration.py

It performs only read-only operations (connect + list calendars) and never
creates, modifies, or deletes anything in your account.
"""

from __future__ import annotations

import os

import pytest

from icloud_calendar_manager import CalendarManager

_OPT_IN = os.getenv("ICLOUD_INTEGRATION") == "1"
_HAS_CREDS = bool(os.getenv("APPLE_ID") and os.getenv("APPLE_PASSWORD"))

pytestmark = pytest.mark.skipif(
    not (_OPT_IN and _HAS_CREDS),
    reason="Set ICLOUD_INTEGRATION=1 with APPLE_ID/APPLE_PASSWORD to run live tests.",
)


def test_can_connect_and_list_calendars():
    manager = CalendarManager.from_env()
    info = manager.check_connection()
    assert info["principal_url"]
    # Listing should succeed and return CalendarInfo objects with names.
    calendars = manager.list_calendars()
    assert all(hasattr(c, "name") for c in calendars)

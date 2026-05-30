"""Custom exceptions for the calendar manager."""

from __future__ import annotations


class ICloudCalendarError(Exception):
    """Base class for all errors raised by this package."""


#: Provider-neutral alias for the base error (the package is multi-provider now).
CalendarManagerError = ICloudCalendarError


class ConfigurationError(ICloudCalendarError):
    """Raised when required configuration (e.g. credentials) is missing or invalid."""


class AuthenticationError(ICloudCalendarError):
    """Raised when iCloud rejects the supplied credentials."""


class ConnectionError(ICloudCalendarError):
    """Raised when the CalDAV server cannot be reached."""


class CalendarNotFoundError(ICloudCalendarError):
    """Raised when a calendar or reminder list cannot be located by name."""

    def __init__(self, name: str):
        self.name = name
        super().__init__(f"Calendar or list {name!r} was not found.")


class ObjectNotFoundError(ICloudCalendarError):
    """Raised when an event or reminder cannot be located by UID."""

    def __init__(self, uid: str):
        self.uid = uid
        super().__init__(f"No object with UID {uid!r} was found.")


class CapabilityError(ICloudCalendarError):
    """Raised when a provider does not support a requested operation."""

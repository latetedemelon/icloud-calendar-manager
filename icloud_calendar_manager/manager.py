"""High-level, provider-agnostic calendar operations.

:class:`CalendarManager` is the primary entry point. It delegates the actual
work to a :class:`~icloud_calendar_manager.backends.base.CalendarBackend`
(CalDAV for iCloud/Fastmail/Yahoo/Google/generic, or Microsoft Graph for
Microsoft 365). A backend, ``principal``, ``client``, ``credentials``, or
``auth`` may be injected, which keeps the class easy to unit-test, while
:meth:`from_provider`, :meth:`from_env`, and :meth:`from_credentials` provide
the convenient real-world paths.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, List, Optional

from .backends import CalDAVBackend, CalendarBackend, build_backend
from .client import EndpointCache, build_client
from .config import DEFAULT_TIMEOUT, AuthConfig, Credentials, resolve_auth
from .exceptions import CapabilityError
from .models import CalendarInfo, EventInfo, ReminderInfo
from .oauth import oauth_config_from_env
from .providers import DEFAULT_PROVIDER

# Re-exported for backwards compatibility (these moved to the CalDAV backend).
from .backends.caldav_backend import (  # noqa: F401  (public re-export)
    _build_vevent,
    _build_vtodo,
    _replace,
    _utcnow,
)


class CalendarManager:
    """Manage calendars, events, and reminders across providers."""

    def __init__(
        self,
        *,
        backend: Optional[CalendarBackend] = None,
        principal: Any = None,
        client: Any = None,
        credentials: Optional[Credentials] = None,
        auth: Optional[AuthConfig] = None,
        url: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        cache: Optional[EndpointCache] = None,
        session: Any = None,
        oauth: Any = None,
        supports_reminders: bool = True,
        supports_events: bool = True,
    ):
        self._backend = backend
        self._principal = principal
        self._client = client
        self._credentials = credentials
        self._auth = auth
        self._url = url
        self._timeout = timeout
        self._cache = cache
        self._session = session
        self._oauth = oauth
        self._supports_reminders = supports_reminders
        self._supports_events = supports_events

    # -- construction helpers ------------------------------------------------

    @classmethod
    def from_provider(
        cls,
        provider: str = DEFAULT_PROVIDER,
        *,
        url: Optional[str] = None,
        username: Optional[str] = None,
        secret: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        cache: Optional[EndpointCache] = None,
        session: Any = None,
        refresh_token: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> "CalendarManager":
        """Build a manager for ``provider``, resolving auth from args/env.

        For bearer providers (Google, Microsoft) you may pass either a
        ready-made access token (``secret``) or OAuth2 refresh-token credentials
        (``refresh_token`` + ``client_id`` [+ ``client_secret``]), which are
        exchanged for an access token automatically.
        """
        # A refresh token is acceptable in place of an access token; defer the
        # secret requirement to the OAuth exchange in that case.
        auth = resolve_auth(
            provider,
            url=url,
            username=username,
            secret=secret,
            timeout=timeout,
            allow_missing_secret=bool(refresh_token),
        )
        oauth = None
        if refresh_token or client_id or client_secret:
            oauth = oauth_config_from_env(
                provider,
                client_id=client_id,
                client_secret=client_secret,
                refresh_token=refresh_token,
            )
        return cls(
            auth=auth,
            cache=cache,
            session=session,
            oauth=oauth,
            supports_reminders=auth.provider.supports_reminders,
            supports_events=auth.provider.supports_events,
        )

    @classmethod
    def from_credentials(
        cls,
        credentials: Credentials,
        *,
        url: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        cache: Optional[EndpointCache] = None,
    ) -> "CalendarManager":
        return cls(credentials=credentials, url=url, timeout=timeout, cache=cache)

    @classmethod
    def from_env(
        cls,
        apple_id: Optional[str] = None,
        app_password: Optional[str] = None,
        *,
        url: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        cache: Optional[EndpointCache] = None,
    ) -> "CalendarManager":
        """Build an iCloud manager from arguments / ``APPLE_ID`` / ``APPLE_PASSWORD``."""
        auth = resolve_auth(
            DEFAULT_PROVIDER, url=url, username=apple_id, secret=app_password, timeout=timeout
        )
        return cls(
            auth=auth,
            cache=cache,
            supports_reminders=auth.provider.supports_reminders,
            supports_events=auth.provider.supports_events,
        )

    # -- backend resolution --------------------------------------------------

    @property
    def backend(self) -> CalendarBackend:
        if self._backend is not None:
            return self._backend
        if self._principal is not None or self._client is not None:
            self._backend = CalDAVBackend(
                principal=self._principal, client=self._client, cache=self._cache
            )
        elif self._auth is not None:
            self._backend = build_backend(
                self._auth, cache=self._cache, session=self._session, oauth=self._oauth
            )
        elif self._credentials is not None:
            client = build_client(
                self._credentials, url=self._url, timeout=self._timeout, cache=self._cache
            )
            self._backend = CalDAVBackend(client=client, cache=self._cache)
        else:
            raise ValueError(
                "CalendarManager needs a backend, principal, client, credentials, or auth."
            )
        return self._backend

    @property
    def principal(self):
        """The CalDAV principal (only available for CalDAV providers)."""
        backend = self.backend
        if isinstance(backend, CalDAVBackend):
            return backend.principal
        raise AttributeError("principal is only available for CalDAV-based providers.")

    # -- calendars -----------------------------------------------------------

    def list_calendars(self, include_reminder_lists: bool = True) -> List[CalendarInfo]:
        """List calendars (and, by default, reminder lists)."""
        infos = self.backend.list_calendars()
        if include_reminder_lists:
            return infos
        return [c for c in infos if not c.is_reminder_list]

    def list_reminder_lists(self) -> List[CalendarInfo]:
        """List only the collections that hold reminders."""
        return [c for c in self.backend.list_calendars() if c.is_reminder_list]

    # -- events --------------------------------------------------------------

    def _require_events(self) -> None:
        if not self._supports_events:
            raise CapabilityError(
                "This provider does not support calendar events via this tool "
                "(it is tasks/reminders only)."
            )

    def list_events(
        self,
        calendar_name: str,
        start: dt.datetime,
        end: dt.datetime,
        *,
        expand: bool = True,
    ) -> List[EventInfo]:
        """Return events in ``calendar_name`` between ``start`` and ``end``."""
        self._require_events()
        return self.backend.list_events(calendar_name, start, end, expand=expand)

    def get_event(self, calendar_name: str, uid: str) -> EventInfo:
        """Fetch a single event by UID."""
        self._require_events()
        return self.backend.get_event(calendar_name, uid)

    def add_event(
        self,
        calendar_name: str,
        summary: str,
        start: dt.datetime | dt.date,
        end: Optional[dt.datetime | dt.date] = None,
        *,
        location: Optional[str] = None,
        description: Optional[str] = None,
        uid: Optional[str] = None,
    ) -> EventInfo:
        """Create an event and return its parsed representation."""
        self._require_events()
        return self.backend.add_event(
            calendar_name, summary, start, end,
            location=location, description=description, uid=uid,
        )

    def update_event(
        self,
        calendar_name: str,
        uid: str,
        *,
        summary: Optional[str] = None,
        start: Optional[dt.datetime | dt.date] = None,
        end: Optional[dt.datetime | dt.date] = None,
        location: Optional[str] = None,
        description: Optional[str] = None,
    ) -> EventInfo:
        """Update fields of an existing event. Only provided fields change."""
        self._require_events()
        return self.backend.update_event(
            calendar_name, uid, summary=summary, start=start, end=end,
            location=location, description=description,
        )

    def delete_event(self, calendar_name: str, uid: str) -> None:
        """Delete an event by UID."""
        self._require_events()
        self.backend.delete_event(calendar_name, uid)

    # -- reminders -----------------------------------------------------------

    def _require_reminders(self) -> None:
        if not self._supports_reminders:
            raise CapabilityError(
                "This provider does not support reminders/tasks via this tool."
            )

    def list_reminders(
        self, list_name: str, *, include_completed: bool = False
    ) -> List[ReminderInfo]:
        """Return reminders from ``list_name``."""
        self._require_reminders()
        return self.backend.list_reminders(list_name, include_completed=include_completed)

    def get_reminder(self, list_name: str, uid: str) -> ReminderInfo:
        """Fetch a single reminder by UID."""
        self._require_reminders()
        return self.backend.get_reminder(list_name, uid)

    def add_reminder(
        self,
        list_name: str,
        summary: str,
        *,
        due: Optional[dt.datetime | dt.date] = None,
        priority: Optional[int] = None,
        description: Optional[str] = None,
        uid: Optional[str] = None,
    ) -> ReminderInfo:
        """Create a reminder and return its parsed representation."""
        self._require_reminders()
        return self.backend.add_reminder(
            list_name, summary, due=due, priority=priority, description=description, uid=uid
        )

    def complete_reminder(self, list_name: str, uid: str) -> ReminderInfo:
        """Mark a reminder complete."""
        self._require_reminders()
        return self.backend.complete_reminder(list_name, uid)

    def delete_reminder(self, list_name: str, uid: str) -> None:
        """Delete a reminder by UID."""
        self._require_reminders()
        self.backend.delete_reminder(list_name, uid)

    # -- diagnostics ---------------------------------------------------------

    def check_connection(self) -> dict:
        """Verify connectivity and summarize the account."""
        calendars = self.list_calendars()
        reminder_lists = [c for c in calendars if c.is_reminder_list]
        return {
            "principal_url": self.backend.account_identifier(),
            "calendars": len(calendars) - len(reminder_lists),
            "reminder_lists": len(reminder_lists),
        }

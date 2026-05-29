"""Registry of supported calendar providers.

Each :class:`Provider` describes how to reach a service: which backend speaks to
it (CalDAV or Microsoft Graph), the default base URL, the authentication scheme,
and what kind of secret it needs. The CLI and config layers use this registry so
that adding a provider is mostly a matter of adding an entry here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

# Backend identifiers.
BACKEND_CALDAV = "caldav"
BACKEND_GRAPH = "graph"

# Authentication schemes.
AUTH_BASIC = "basic"
AUTH_BEARER = "bearer"

# Secret kinds (used for friendly validation messages).
SECRET_APP_PASSWORD = "app-password"
SECRET_PASSWORD = "password"
SECRET_OAUTH_TOKEN = "oauth-token"


@dataclass(frozen=True)
class Provider:
    """Static description of a calendar provider."""

    key: str
    label: str
    backend: str
    auth_scheme: str
    secret_kind: str
    help_url: str
    base_url: Optional[str] = None  # None => the user must supply --url
    requires_username: bool = True
    supports_reminders: bool = True
    experimental: bool = False
    notes: str = ""


PROVIDERS: Dict[str, Provider] = {
    "icloud": Provider(
        key="icloud",
        label="Apple iCloud",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_APP_PASSWORD,
        help_url="https://appleid.apple.com",
        base_url="https://caldav.icloud.com",
        supports_reminders=True,
        notes="Use an app-specific password (Apple ID -> Security).",
    ),
    "fastmail": Provider(
        key="fastmail",
        label="Fastmail",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_APP_PASSWORD,
        help_url="https://www.fastmail.help/hc/en-us/articles/360058752854",
        base_url="https://caldav.fastmail.com/dav/",
        supports_reminders=True,
        notes="Create an app password with the 'Calendars (CalDAV)' scope.",
    ),
    "yahoo": Provider(
        key="yahoo",
        label="Yahoo Calendar",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_APP_PASSWORD,
        help_url="https://help.yahoo.com/kb/SLN15241.html",
        base_url="https://caldav.calendar.yahoo.com",
        supports_reminders=True,
        notes="Use an app password generated from your Yahoo account security page.",
    ),
    "google": Provider(
        key="google",
        label="Google Calendar + Tasks",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BEARER,
        secret_kind=SECRET_OAUTH_TOKEN,
        help_url="https://developers.google.com/calendar/caldav/v2/guide",
        base_url="https://apidata.googleusercontent.com/caldav/v2/",
        requires_username=True,
        supports_reminders=True,
        experimental=True,
        notes=(
            "Supply an OAuth2 access token (or refresh-token credentials) and "
            "your account email as the username. Events use CalDAV; reminders "
            "use the Google Tasks API."
        ),
    ),
    "microsoft": Provider(
        key="microsoft",
        label="Microsoft 365 / Outlook (Graph)",
        backend=BACKEND_GRAPH,
        auth_scheme=AUTH_BEARER,
        secret_kind=SECRET_OAUTH_TOKEN,
        help_url="https://learn.microsoft.com/graph/auth/auth-concepts",
        base_url="https://graph.microsoft.com/v1.0",
        requires_username=False,
        supports_reminders=True,
        experimental=True,
        notes=(
            "Supply an OAuth2 access token with Calendars.ReadWrite and "
            "Tasks.ReadWrite scopes. Reminders map to Microsoft To Do."
        ),
    ),
    "generic": Provider(
        key="generic",
        label="Generic CalDAV server",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_PASSWORD,
        help_url="https://en.wikipedia.org/wiki/CalDAV",
        base_url=None,
        supports_reminders=True,
        notes="Provide the server URL with --url (e.g. a Nextcloud DAV endpoint).",
    ),
}

DEFAULT_PROVIDER = "icloud"


def get_provider(key: str) -> Provider:
    """Return the :class:`Provider` for ``key``.

    Raises:
        KeyError: with a helpful message listing valid providers.
    """
    try:
        return PROVIDERS[key]
    except KeyError:
        valid = ", ".join(sorted(PROVIDERS))
        raise KeyError(f"Unknown provider {key!r}. Choose one of: {valid}.") from None

"""Registry of supported calendar providers.

Each :class:`Provider` describes how to reach a service: which backend speaks to
it (CalDAV or Microsoft Graph), the default base URL, the authentication scheme,
and what kind of secret it needs. The CLI and config layers use this registry so
that adding a provider is mostly a matter of adding an entry here.

Self-hosted servers (Nextcloud, Radicale, Baikal, SOGo, DAViCal, Vikunja, ...)
have no fixed host, so they declare ``base_url=None`` and require the user to
pass ``--url``. They may declare a ``path_suffix`` (e.g. Nextcloud's
``/remote.php/dav``) that is appended to the host the user gives, and/or
``well_known=True`` to opt into ``/.well-known/caldav`` auto-discovery.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import urlsplit, urlunsplit

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
    path_suffix: Optional[str] = None  # appended to a user-supplied host
    requires_username: bool = True
    supports_events: bool = True
    supports_reminders: bool = True
    self_hosted: bool = False
    well_known: bool = False  # try /.well-known/caldav discovery when given a bare host
    experimental: bool = False
    notes: str = ""


PROVIDERS: Dict[str, Provider] = {
    # -- hosted, well-known services -----------------------------------------
    "icloud": Provider(
        key="icloud",
        label="Apple iCloud",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_APP_PASSWORD,
        help_url="https://appleid.apple.com",
        base_url="https://caldav.icloud.com",
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
        notes="Use an app password generated from your Yahoo account security page.",
    ),
    "posteo": Provider(
        key="posteo",
        label="Posteo",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_PASSWORD,
        help_url="https://posteo.de/en/help/how-do-i-synchronise-calendars-and-contacts",
        base_url="https://posteo.de:8443/",
        notes="Use your Posteo login; enable calendar access in settings.",
    ),
    "mailbox": Provider(
        key="mailbox",
        label="mailbox.org",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_PASSWORD,
        help_url="https://kb.mailbox.org/en/private/calendar-and-address-book",
        base_url="https://dav.mailbox.org/",
        notes="Use your mailbox.org login.",
    ),
    "gmx": Provider(
        key="gmx",
        label="GMX Calendar",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_PASSWORD,
        help_url="https://www.gmx.com",
        base_url="https://caldav.gmx.net/",
        notes="Use your GMX login.",
    ),
    "google": Provider(
        key="google",
        label="Google Calendar + Tasks",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BEARER,
        secret_kind=SECRET_OAUTH_TOKEN,
        help_url="https://developers.google.com/calendar/caldav/v2/guide",
        base_url="https://apidata.googleusercontent.com/caldav/v2/",
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
        experimental=True,
        notes=(
            "Supply an OAuth2 access token with Calendars.ReadWrite and "
            "Tasks.ReadWrite scopes. Reminders map to Microsoft To Do."
        ),
    ),
    # -- self-hosted open-source servers (require --url) ---------------------
    "nextcloud": Provider(
        key="nextcloud",
        label="Nextcloud",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_APP_PASSWORD,
        help_url="https://docs.nextcloud.com/server/latest/user_manual/en/groupware/sync_ios.html",
        base_url=None,
        path_suffix="/remote.php/dav",
        self_hosted=True,
        well_known=True,
        notes="Pass --url https://your-nextcloud.example. Use an app password.",
    ),
    "owncloud": Provider(
        key="owncloud",
        label="ownCloud",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_APP_PASSWORD,
        help_url="https://doc.owncloud.com",
        base_url=None,
        path_suffix="/remote.php/dav",
        self_hosted=True,
        well_known=True,
        notes="Pass --url https://your-owncloud.example. Use an app password.",
    ),
    "radicale": Provider(
        key="radicale",
        label="Radicale",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_PASSWORD,
        help_url="https://radicale.org/v3.html",
        base_url=None,
        self_hosted=True,
        well_known=True,
        notes="Pass --url https://your-radicale.example (the collection root).",
    ),
    "baikal": Provider(
        key="baikal",
        label="Baikal",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_PASSWORD,
        help_url="https://sabre.io/baikal/",
        base_url=None,
        path_suffix="/dav.php",
        self_hosted=True,
        well_known=True,
        notes="Pass --url https://your-baikal.example.",
    ),
    "sogo": Provider(
        key="sogo",
        label="SOGo",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_PASSWORD,
        help_url="https://www.sogo.nu/support.html",
        base_url=None,
        path_suffix="/SOGo/dav",
        self_hosted=True,
        well_known=True,
        notes="Pass --url https://your-sogo.example.",
    ),
    "davical": Provider(
        key="davical",
        label="DAViCal",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_PASSWORD,
        help_url="https://www.davical.org/",
        base_url=None,
        path_suffix="/caldav.php",
        self_hosted=True,
        well_known=True,
        notes="Pass --url https://your-davical.example.",
    ),
    "zimbra": Provider(
        key="zimbra",
        label="Zimbra",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_PASSWORD,
        help_url="https://wiki.zimbra.com/wiki/CalDAV",
        base_url=None,
        path_suffix="/dav",
        self_hosted=True,
        well_known=True,
        notes="Pass --url https://your-zimbra.example.",
    ),
    "synology": Provider(
        key="synology",
        label="Synology Calendar",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_PASSWORD,
        help_url="https://www.synology.com/en-global/dsm/feature/calendar",
        base_url=None,
        self_hosted=True,
        well_known=True,
        notes="Pass --url https://your-nas.example:5001 (Calendar's CalDAV port).",
    ),
    "vikunja": Provider(
        key="vikunja",
        label="Vikunja (tasks only)",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_PASSWORD,
        help_url="https://vikunja.io/help/caldav/",
        base_url=None,
        path_suffix="/dav",
        requires_username=True,
        supports_events=False,  # Vikunja exposes VTODO (tasks) only, no events
        supports_reminders=True,
        self_hosted=True,
        experimental=True,
        notes="Tasks-only (no events). Pass --url https://your-vikunja.example.",
    ),
    # -- escape hatch --------------------------------------------------------
    "generic": Provider(
        key="generic",
        label="Generic CalDAV server",
        backend=BACKEND_CALDAV,
        auth_scheme=AUTH_BASIC,
        secret_kind=SECRET_PASSWORD,
        help_url="https://en.wikipedia.org/wiki/CalDAV",
        base_url=None,
        self_hosted=True,
        well_known=True,
        notes="Any RFC-4791 server. Provide the full DAV URL with --url.",
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


def resolve_provider_url(provider: Provider, url: Optional[str]) -> Optional[str]:
    """Combine a user-supplied ``url`` with the provider's preset path.

    * If the user gives a URL and the provider declares a ``path_suffix`` that
      the URL does not already include, the suffix is appended (so a user can
      pass just ``https://cloud.example.com`` for Nextcloud).
    * If the user gives no URL, the provider's fixed ``base_url`` is used.

    This function is pure (no network) and safe to unit-test.
    """
    if url:
        base = url.rstrip("/")
        suffix = provider.path_suffix
        if suffix and not _has_suffix(base, suffix):
            return base + suffix
        return base
    return provider.base_url


def _has_suffix(url: str, suffix: str) -> bool:
    """True if ``url``'s path already contains ``suffix`` (ignoring trailing /)."""
    path = urlsplit(url).path.rstrip("/")
    return path.endswith(suffix.rstrip("/"))


def well_known_url(url: str) -> str:
    """Return the ``/.well-known/caldav`` URL for the host of ``url``."""
    parts = urlsplit(url if "//" in url else "https://" + url)
    return urlunsplit((parts.scheme or "https", parts.netloc, "/.well-known/caldav", "", ""))

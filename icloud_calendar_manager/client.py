"""CalDAV client construction, authentication and endpoint discovery.

The reliable way to reach iCloud CalDAV with an app-specific password is to
connect to the generic host (:data:`~icloud_calendar_manager.config.DEFAULT_CALDAV_URL`)
and let the library follow iCloud's redirect to the account's partition host
during *principal discovery*. This module wraps that flow with friendly error
handling and an optional cache of the discovered partition URL so subsequent
runs can connect directly.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import caldav

from .config import DEFAULT_CALDAV_URL, DEFAULT_TIMEOUT, Credentials
from .exceptions import AuthenticationError
from .exceptions import ConnectionError as ICloudConnectionError

logger = logging.getLogger(__name__)


class EndpointCache:
    """Persist the discovered CalDAV partition base URL between runs.

    This is a correctness-preserving reimplementation of the original
    ``build_caldav_endpoint`` idea: discover the partition host once, then reuse
    it. Unlike the original it handles a bare filename (no directory) safely and
    never raises on cache I/O failures.
    """

    def __init__(self, path: str):
        self.path = path

    def load(self) -> Optional[str]:
        try:
            if not os.path.exists(self.path):
                return None
            with open(self.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            return data.get("base_url")
        except (OSError, ValueError) as exc:
            logger.warning("Ignoring unreadable endpoint cache %s: %s", self.path, exc)
            return None

    def save(self, base_url: str) -> None:
        try:
            directory = os.path.dirname(self.path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as handle:
                json.dump({"base_url": base_url}, handle, indent=2)
            logger.debug("Cached CalDAV endpoint %s -> %s", base_url, self.path)
        except OSError as exc:  # pragma: no cover - defensive
            logger.warning("Could not write endpoint cache %s: %s", self.path, exc)


def build_client(
    credentials: Credentials,
    *,
    url: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    cache: Optional[EndpointCache] = None,
) -> caldav.DAVClient:
    """Construct a :class:`caldav.DAVClient` for the given credentials.

    Backwards-compatible iCloud-oriented helper. For multi-provider use see
    :func:`build_caldav_client`.

    Args:
        credentials: Resolved Apple ID + app-specific password.
        url: Explicit base URL. Defaults to the cached partition URL (if a
            cache is supplied and populated) or the generic iCloud host.
        timeout: Per-request timeout in seconds.
        cache: Optional :class:`EndpointCache` used to seed the base URL.
    """
    base_url = url or (cache.load() if cache else None) or DEFAULT_CALDAV_URL
    logger.debug("Creating CalDAV client for %s at %s", credentials.apple_id, base_url)
    return caldav.DAVClient(
        url=base_url,
        username=credentials.apple_id,
        password=credentials.app_password,
        timeout=timeout,
    )


def build_caldav_client(
    *,
    url: str,
    auth_scheme: str = "basic",
    username: Optional[str] = None,
    secret: str,
    timeout: int = DEFAULT_TIMEOUT,
    cache: Optional[EndpointCache] = None,
) -> caldav.DAVClient:
    """Construct a :class:`caldav.DAVClient` for any CalDAV provider.

    Supports both Basic auth (username + password) and Bearer auth (an OAuth2
    access token passed as ``secret``), the latter being how Google CalDAV is
    reached.

    Args:
        url: Base URL of the CalDAV server.
        auth_scheme: ``"basic"`` or ``"bearer"``.
        username: Account username (Basic auth; also used by some bearer hosts).
        secret: Password (Basic) or OAuth2 access token (Bearer).
        timeout: Per-request timeout in seconds.
        cache: Optional cache used to seed a previously discovered base URL.
    """
    base_url = (cache.load() if cache else None) or url
    if auth_scheme == "bearer":
        logger.debug("Creating CalDAV client (bearer) at %s", base_url)
        return caldav.DAVClient(
            url=base_url,
            headers={"Authorization": f"Bearer {secret}"},
            timeout=timeout,
        )
    logger.debug("Creating CalDAV client (basic) for %s at %s", username, base_url)
    return caldav.DAVClient(
        url=base_url,
        username=username,
        password=secret,
        timeout=timeout,
    )


def get_principal(client: caldav.DAVClient):
    """Return the CalDAV principal, mapping library errors to our exceptions.

    Raises:
        AuthenticationError: If iCloud rejects the credentials.
        ICloudConnectionError: If the server cannot be reached.
    """
    try:
        return client.principal()
    except caldav.lib.error.AuthorizationError as exc:
        raise AuthenticationError(
            "iCloud rejected the credentials. Confirm the Apple ID and that the "
            "password is an app-specific password (not your Apple ID password)."
        ) from exc
    except Exception as exc:  # network/DNS/SSL and other transport failures
        # caldav surfaces transport problems as plain requests exceptions.
        raise ICloudConnectionError(f"Could not reach the CalDAV server: {exc}") from exc


def partition_base_url(principal) -> Optional[str]:
    """Derive the account's partition base URL (scheme://host) from the principal.

    iCloud serves each account from a host such as ``p123-caldav.icloud.com``.
    We read it from the principal's calendars so it can be cached and reused.
    """
    try:
        calendars = principal.calendars()
    except Exception:  # pragma: no cover - defensive
        return None
    for calendar in calendars:
        parts = urlsplit(str(calendar.url))
        if parts.scheme and parts.netloc:
            return urlunsplit((parts.scheme, parts.netloc, "", "", ""))
    return None

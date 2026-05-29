"""Configuration and credential resolution for the iCloud Calendar Manager.

Credentials are resolved, in order of precedence, from:

1. Explicit arguments passed to :class:`Credentials`.
2. Environment variables ``APPLE_ID`` and ``APPLE_PASSWORD``.

Apple requires an *app-specific password* (created at https://appleid.apple.com)
rather than your primary Apple ID password, because iCloud accounts use
two-factor authentication.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from .exceptions import ConfigurationError

# Base CalDAV endpoint. iCloud redirects this to the account's "partition"
# host (e.g. ``p123-caldav.icloud.com``) during principal discovery, so the
# generic host below is a safe, documented default.
DEFAULT_CALDAV_URL = "https://caldav.icloud.com"

#: Default network timeout (seconds) for CalDAV requests.
DEFAULT_TIMEOUT = 30

ENV_APPLE_ID = "APPLE_ID"
ENV_APPLE_PASSWORD = "APPLE_PASSWORD"  # noqa: S105 - name of an env var, not a secret


@dataclass(frozen=True)
class Credentials:
    """Resolved iCloud credentials.

    Use :meth:`from_env` to build an instance from arguments and/or the
    environment with validation.
    """

    apple_id: str
    app_password: str

    @classmethod
    def from_env(
        cls,
        apple_id: Optional[str] = None,
        app_password: Optional[str] = None,
    ) -> "Credentials":
        """Resolve credentials from explicit arguments then the environment.

        Args:
            apple_id: Apple ID (email). Falls back to ``$APPLE_ID``.
            app_password: App-specific password. Falls back to ``$APPLE_PASSWORD``.

        Raises:
            ConfigurationError: If either value is missing after resolution.
        """
        apple_id = apple_id or os.getenv(ENV_APPLE_ID)
        app_password = app_password or os.getenv(ENV_APPLE_PASSWORD)

        missing = []
        if not apple_id:
            missing.append(ENV_APPLE_ID)
        if not app_password:
            missing.append(ENV_APPLE_PASSWORD)
        if missing:
            raise ConfigurationError(
                "Missing iCloud credentials: "
                + ", ".join(missing)
                + ". Set the environment variables or pass them explicitly. "
                "Note that APPLE_PASSWORD must be an app-specific password "
                "(https://appleid.apple.com -> Security -> App-Specific Passwords)."
            )
        return cls(apple_id=apple_id, app_password=app_password)

    def __repr__(self) -> str:  # pragma: no cover - trivial
        # Never leak the password in logs or tracebacks.
        return f"Credentials(apple_id={self.apple_id!r}, app_password='***')"

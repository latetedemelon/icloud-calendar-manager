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
from .providers import (
    AUTH_BEARER,
    DEFAULT_PROVIDER,
    SECRET_APP_PASSWORD,
    SECRET_OAUTH_TOKEN,
    Provider,
    get_provider,
)

# Base CalDAV endpoint. iCloud redirects this to the account's "partition"
# host (e.g. ``p123-caldav.icloud.com``) during principal discovery, so the
# generic host below is a safe, documented default.
DEFAULT_CALDAV_URL = "https://caldav.icloud.com"

#: Default network timeout (seconds) for CalDAV requests.
DEFAULT_TIMEOUT = 30

ENV_APPLE_ID = "APPLE_ID"
ENV_APPLE_PASSWORD = "APPLE_PASSWORD"  # noqa: S105 - name of an env var, not a secret

# Generic, provider-agnostic environment variables.
ENV_PROVIDER = "CALENDAR_PROVIDER"
ENV_URL = "CALDAV_URL"
ENV_USERNAME = "CALENDAR_USERNAME"
ENV_PASSWORD = "CALENDAR_PASSWORD"  # noqa: S105 - env var name
ENV_TOKEN = "CALENDAR_TOKEN"  # noqa: S105 - env var name

# Per-provider environment aliases (username, secret) checked before the
# generic variables above. Lets each service keep its conventional names.
_PROVIDER_ENV = {
    "icloud": (ENV_APPLE_ID, ENV_APPLE_PASSWORD),
    "fastmail": ("FASTMAIL_USERNAME", "FASTMAIL_PASSWORD"),
    "yahoo": ("YAHOO_USERNAME", "YAHOO_PASSWORD"),
    "google": ("GOOGLE_EMAIL", "GOOGLE_CALENDAR_TOKEN"),
    "microsoft": (None, "MICROSOFT_TOKEN"),
}


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


@dataclass(frozen=True)
class AuthConfig:
    """Resolved authentication for any provider.

    ``secret`` holds a password (for Basic auth) or a bearer token (for OAuth
    providers). Use :func:`resolve_auth` to build one with validation.
    """

    provider: Provider
    url: Optional[str]
    username: Optional[str]
    secret: str
    timeout: int = DEFAULT_TIMEOUT

    @property
    def auth_scheme(self) -> str:
        return self.provider.auth_scheme

    @property
    def backend(self) -> str:
        return self.provider.backend

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            "AuthConfig(provider={!r}, url={!r}, username={!r}, secret='***')".format(
                self.provider.key, self.url, self.username
            )
        )


def _first_env(*names: Optional[str]) -> Optional[str]:
    for name in names:
        if name:
            value = os.getenv(name)
            if value:
                return value
    return None


def _secret_hint(provider: Provider) -> str:
    if provider.secret_kind == SECRET_APP_PASSWORD:
        return f"an app-specific password (see {provider.help_url})"
    if provider.secret_kind == SECRET_OAUTH_TOKEN:
        return f"an OAuth2 access token (see {provider.help_url})"
    return "the account password"


def resolve_auth(
    provider_key: str = DEFAULT_PROVIDER,
    *,
    url: Optional[str] = None,
    username: Optional[str] = None,
    secret: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    allow_missing_secret: bool = False,
) -> AuthConfig:
    """Resolve authentication for ``provider_key`` from arguments then env vars.

    Precedence for each field: explicit argument, then the provider-specific
    environment alias, then the generic ``CALENDAR_*`` / ``CALDAV_URL`` vars,
    then the provider's default URL.

    Args:
        allow_missing_secret: When True, a missing access token/password is not
            an error (used when an OAuth refresh token will mint the access
            token instead). The resulting ``AuthConfig.secret`` may be ``""``.

    Raises:
        ConfigurationError: if the URL, username, or secret cannot be resolved.
    """
    try:
        provider = get_provider(provider_key)
    except KeyError as exc:
        raise ConfigurationError(str(exc)) from exc

    env_user, env_secret = _PROVIDER_ENV.get(provider.key, (None, None))
    is_bearer = provider.auth_scheme == AUTH_BEARER

    resolved_url = url or os.getenv(ENV_URL) or provider.base_url
    resolved_user = username or _first_env(env_user, ENV_USERNAME)
    if is_bearer:
        resolved_secret = secret or _first_env(env_secret, ENV_TOKEN)
    else:
        resolved_secret = secret or _first_env(env_secret, ENV_PASSWORD)

    missing = []
    if not resolved_url:
        missing.append("URL (pass --url; required for the 'generic' provider)")
    if provider.requires_username and not resolved_user:
        missing.append("username (pass --username or set the provider's env var)")
    if not resolved_secret and not allow_missing_secret:
        kind = "token" if is_bearer else "password"
        missing.append(f"{kind} ({_secret_hint(provider)})")

    if missing:
        raise ConfigurationError(
            f"Cannot authenticate to {provider.label}. Missing: "
            + "; ".join(missing)
            + "."
        )

    return AuthConfig(
        provider=provider,
        url=resolved_url,
        username=resolved_user,
        secret=resolved_secret or "",
        timeout=timeout,
    )

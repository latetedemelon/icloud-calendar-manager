"""Minimal OAuth2 access-token acquisition for bearer providers.

This helper performs the OAuth2 *refresh-token* grant: given a long-lived
refresh token plus the client credentials, it obtains a short-lived access
token. It does **not** implement the interactive consent flow (obtaining the
initial refresh token is a one-time, browser-based step the user performs with
their own tooling); it only refreshes.

Google and Microsoft token endpoints both speak the standard grant, so a single
implementation covers them. The HTTP POST is injectable so this is unit-tested
without a network.

Resolution order for each value: explicit argument, then provider-specific env
var, then a generic ``CALENDAR_*`` env var.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .exceptions import AuthenticationError, ConfigurationError

# Default OAuth2 token endpoints.
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105 - public URL
MICROSOFT_TOKEN_URL = (  # noqa: S105 - public URL template
    "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
)

# Per-provider env var names for the OAuth client/refresh material.
_OAUTH_ENV = {
    "google": {
        "client_id": "GOOGLE_CLIENT_ID",
        "client_secret": "GOOGLE_CLIENT_SECRET",
        "refresh_token": "GOOGLE_REFRESH_TOKEN",
        "token_url": "GOOGLE_TOKEN_URL",
        "tenant": None,
    },
    "microsoft": {
        "client_id": "MICROSOFT_CLIENT_ID",
        "client_secret": "MICROSOFT_CLIENT_SECRET",
        "refresh_token": "MICROSOFT_REFRESH_TOKEN",
        "token_url": "MICROSOFT_TOKEN_URL",
        "tenant": "MICROSOFT_TENANT",
    },
}

# Generic fallbacks shared across providers.
_GENERIC_ENV = {
    "client_id": "OAUTH_CLIENT_ID",
    "client_secret": "OAUTH_CLIENT_SECRET",
    "refresh_token": "OAUTH_REFRESH_TOKEN",
    "token_url": "OAUTH_TOKEN_URL",
}

#: Type of an injectable POST function: (url, data) -> response-with-.json()/.status_code
PostFn = Callable[[str, dict], Any]


@dataclass(frozen=True)
class OAuthRefreshConfig:
    """Material needed to perform an OAuth2 refresh-token grant."""

    client_id: str
    client_secret: Optional[str]
    refresh_token: str
    token_url: str
    scope: Optional[str] = None

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            "OAuthRefreshConfig(client_id={!r}, token_url={!r}, "
            "client_secret='***', refresh_token='***')".format(
                self.client_id, self.token_url
            )
        )


def _resolve(provider: str, key: str, explicit: Optional[str]) -> Optional[str]:
    if explicit:
        return explicit
    names = _OAUTH_ENV.get(provider, {})
    env_name = names.get(key)
    if env_name and os.getenv(env_name):
        return os.getenv(env_name)
    generic = _GENERIC_ENV.get(key)
    if generic and os.getenv(generic):
        return os.getenv(generic)
    return None


def oauth_config_from_env(
    provider: str,
    *,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    refresh_token: Optional[str] = None,
    token_url: Optional[str] = None,
    scope: Optional[str] = None,
) -> Optional[OAuthRefreshConfig]:
    """Build an :class:`OAuthRefreshConfig` from arguments/env, or ``None``.

    Returns ``None`` when no refresh token is available (the caller should then
    fall back to a directly-supplied access token). Raises
    :class:`ConfigurationError` when a refresh token is present but the client
    id (or, for non-Google, the token URL) cannot be resolved.
    """
    refresh = _resolve(provider, "refresh_token", refresh_token)
    if not refresh:
        return None

    cid = _resolve(provider, "client_id", client_id)
    secret = _resolve(provider, "client_secret", client_secret)
    url = _resolve(provider, "token_url", token_url)

    if not url:
        if provider == "google":
            url = GOOGLE_TOKEN_URL
        elif provider == "microsoft":
            tenant = os.getenv(_OAUTH_ENV["microsoft"]["tenant"]) or "common"
            url = MICROSOFT_TOKEN_URL.format(tenant=tenant)

    missing = []
    if not cid:
        missing.append("client id")
    if not url:
        missing.append("token URL")
    if missing:
        raise ConfigurationError(
            f"A refresh token was provided for {provider} but the OAuth "
            + " and ".join(missing)
            + " is missing. Set the corresponding client credentials."
        )

    return OAuthRefreshConfig(
        client_id=cid,
        client_secret=secret,
        refresh_token=refresh,
        token_url=url,
        scope=scope,
    )


def refresh_access_token(config: OAuthRefreshConfig, *, post: Optional[PostFn] = None) -> str:
    """Exchange a refresh token for an access token via the OAuth2 grant.

    Args:
        config: The refresh material.
        post: Optional injected ``post(url, data) -> response`` for testing. The
            response must expose ``status_code`` and ``json()``.

    Raises:
        AuthenticationError: if the token endpoint rejects the request.
    """
    data = {
        "grant_type": "refresh_token",
        "refresh_token": config.refresh_token,
        "client_id": config.client_id,
    }
    if config.client_secret:
        data["client_secret"] = config.client_secret
    if config.scope:
        data["scope"] = config.scope

    poster = post or _default_post
    resp = poster(config.token_url, data)

    code = getattr(resp, "status_code", 0)
    try:
        payload = resp.json()
    except ValueError:
        payload = {}
    if code != 200 or "access_token" not in payload:
        detail = payload.get("error_description") or payload.get("error") or f"HTTP {code}"
        raise AuthenticationError(f"OAuth token refresh failed: {detail}")
    return payload["access_token"]


def _default_post(url: str, data: dict):  # pragma: no cover - exercised via injection
    import requests

    return requests.post(url, data=data, timeout=30)


class TokenProvider:
    """Caches an access token and refreshes it on demand.

    If built with a static token and no refresh config, it simply returns the
    static token. With a refresh config, it fetches a token on first use and
    re-fetches once the cached one is near expiry.
    """

    def __init__(
        self,
        *,
        access_token: Optional[str] = None,
        refresh: Optional[OAuthRefreshConfig] = None,
        post: Optional[PostFn] = None,
        clock: Callable[[], float] = time.monotonic,
        leeway: int = 60,
    ):
        if not access_token and not refresh:
            raise ConfigurationError("TokenProvider needs an access token or refresh config.")
        self._token = access_token
        self._refresh = refresh
        self._post = post
        self._clock = clock
        self._leeway = leeway
        self._expires_at: Optional[float] = None

    def token(self) -> str:
        if self._refresh is None:
            return self._token  # static token
        if self._token and self._expires_at and self._clock() < self._expires_at - self._leeway:
            return self._token
        self._token = refresh_access_token(self._refresh, post=self._post)
        # We don't parse expires_in here (kept simple); refresh on next near-miss.
        self._expires_at = self._clock() + 3600
        return self._token

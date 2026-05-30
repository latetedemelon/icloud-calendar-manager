"""Backend selection and construction."""

from __future__ import annotations

from typing import Any, Optional

from ..client import EndpointCache
from ..config import AuthConfig
from ..oauth import TokenProvider, oauth_config_from_env
from ..providers import AUTH_BEARER, BACKEND_CALDAV, BACKEND_GRAPH
from .base import CalendarBackend
from .caldav_backend import CalDAVBackend
from .google_tasks import GoogleBackend, GoogleTasksBackend
from .graph_backend import GraphBackend, GraphTransport
from .transport import BearerTransport

__all__ = [
    "CalendarBackend",
    "CalDAVBackend",
    "GraphBackend",
    "GraphTransport",
    "GoogleBackend",
    "GoogleTasksBackend",
    "build_backend",
    "resolve_bearer_token",
]

_TASKS_BASE = "https://tasks.googleapis.com/tasks/v1"


def resolve_bearer_token(auth: AuthConfig, *, oauth: Any = None, post: Any = None) -> str:
    """Return the access token for a bearer provider.

    If OAuth refresh-token credentials are supplied (explicitly or via env),
    they are used to mint a fresh access token; otherwise the directly-supplied
    ``auth.secret`` is treated as the access token.
    """
    refresh = oauth if oauth is not None else oauth_config_from_env(auth.provider.key)
    if refresh is not None:
        return TokenProvider(refresh=refresh, post=post).token()
    return auth.secret


def build_backend(
    auth: AuthConfig,
    *,
    cache: Optional[EndpointCache] = None,
    session: Any = None,
    oauth: Any = None,
    post: Any = None,
) -> CalendarBackend:
    """Construct the backend appropriate for ``auth``'s provider.

    Args:
        auth: Resolved authentication/configuration.
        cache: Optional CalDAV endpoint cache (ignored by non-CalDAV backends).
        session: Optional HTTP transport, injected for testing the REST backends
            (Microsoft Graph and Google Tasks).
        oauth: Optional :class:`~icloud_calendar_manager.oauth.OAuthRefreshConfig`
            used to mint an access token for bearer providers.
        post: Optional injected OAuth token POST function, for testing refresh.
    """
    provider = auth.provider

    if provider.key == "google":
        return _build_google_backend(auth, cache=cache, session=session, oauth=oauth, post=post)

    if provider.backend == BACKEND_GRAPH:
        token = resolve_bearer_token(auth, oauth=oauth, post=post)
        transport = session or GraphTransport(
            token=token, base_url=auth.url, timeout=auth.timeout
        )
        return GraphBackend(transport=transport)

    if provider.backend == BACKEND_CALDAV:
        # Bearer CalDAV providers may also use OAuth refresh to mint the token.
        if provider.auth_scheme == AUTH_BEARER:
            token = resolve_bearer_token(auth, oauth=oauth, post=post)
            auth = _with_secret(auth, token)
        return CalDAVBackend(auth=auth, cache=cache)

    raise ValueError(f"Unknown backend {provider.backend!r} for provider {provider.key!r}.")


def _build_google_backend(auth, *, cache, session, oauth, post) -> GoogleBackend:
    """Google: CalDAV for events + Google Tasks for reminders (shared token)."""
    token = resolve_bearer_token(auth, oauth=oauth, post=post)
    caldav_backend = CalDAVBackend(auth=_with_secret(auth, token), cache=cache)
    tasks_transport = session or BearerTransport(
        token=token, base_url=_TASKS_BASE, timeout=auth.timeout
    )
    return GoogleBackend(caldav_backend, GoogleTasksBackend(tasks_transport))


def _with_secret(auth: AuthConfig, secret: str) -> AuthConfig:
    """Return a copy of ``auth`` with ``secret`` replaced (e.g. a minted token)."""
    if secret == auth.secret:
        return auth
    return AuthConfig(
        provider=auth.provider,
        url=auth.url,
        username=auth.username,
        secret=secret,
        timeout=auth.timeout,
    )

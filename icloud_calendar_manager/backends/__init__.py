"""Backend selection and construction."""

from __future__ import annotations

from typing import Any, Optional

from ..client import EndpointCache
from ..config import AuthConfig
from ..providers import BACKEND_CALDAV, BACKEND_GRAPH
from .base import CalendarBackend
from .caldav_backend import CalDAVBackend
from .graph_backend import GraphBackend, GraphTransport

__all__ = [
    "CalendarBackend",
    "CalDAVBackend",
    "GraphBackend",
    "GraphTransport",
    "build_backend",
]


def build_backend(
    auth: AuthConfig,
    *,
    cache: Optional[EndpointCache] = None,
    session: Any = None,
) -> CalendarBackend:
    """Construct the backend appropriate for ``auth``'s provider.

    Args:
        auth: Resolved authentication/configuration.
        cache: Optional CalDAV endpoint cache (ignored by non-CalDAV backends).
        session: Optional HTTP session/transport (used by the Graph backend;
            mainly an injection point for testing).
    """
    backend = auth.backend
    if backend == BACKEND_CALDAV:
        return CalDAVBackend(auth=auth, cache=cache)
    if backend == BACKEND_GRAPH:
        transport = session or GraphTransport(
            token=auth.secret, base_url=auth.url, timeout=auth.timeout
        )
        return GraphBackend(transport=transport)
    raise ValueError(f"Unknown backend {backend!r} for provider {auth.provider.key!r}.")

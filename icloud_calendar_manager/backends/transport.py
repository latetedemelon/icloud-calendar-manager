"""Shared HTTP plumbing for bearer-token REST backends (Graph, Google Tasks).

A :class:`BearerTransport` wraps ``requests`` to issue authenticated JSON
requests; :func:`json_or_raise` maps HTTP status codes onto the package's
exception hierarchy. Both are deliberately small and dependency-light so the
REST backends can be unit-tested with an injected fake transport.
"""

from __future__ import annotations

from typing import Any, Optional

from ..exceptions import AuthenticationError, ICloudCalendarError
from ..exceptions import ConnectionError as ICloudConnectionError


class BearerTransport:
    """Issue authenticated JSON HTTP requests against a REST API."""

    def __init__(self, token: str, base_url: str, timeout: int, session: Any = None):
        import requests  # imported lazily so the dependency stays optional

        self._token = token
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._session = session or requests.Session()

    def request(self, method, path, *, params=None, json=None, headers=None):
        url = path if path.startswith("http") else f"{self._base}{path}"
        all_headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if headers:
            all_headers.update(headers)
        return self._session.request(
            method,
            url,
            params=params,
            json=json,
            headers=all_headers,
            timeout=self._timeout,
        )


def _detail(resp: Any) -> str:
    """Best-effort extraction of a human-readable error from a response."""
    try:
        payload = resp.json()
    except Exception:
        return getattr(resp, "text", "") or "no detail"
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict) and error.get("message"):
            return error["message"]
        if isinstance(error, str):
            return payload.get("error_description") or error
    return str(payload)


def json_or_raise(
    resp: Any,
    *,
    service: str = "the calendar service",
    not_found: Optional[Exception] = None,
):
    """Return the decoded JSON body or raise a mapped exception.

    Args:
        resp: A ``requests``-style response (``status_code`` + ``json()``).
        service: Name used in error messages.
        not_found: Exception to raise on HTTP 404 (defaults to a generic error).
    """
    code = getattr(resp, "status_code", 0)
    if code in (401, 403):
        raise AuthenticationError(
            f"{service} rejected the access token. Ensure it is valid and has the "
            "required scopes."
        )
    if code == 404:
        raise not_found or ICloudCalendarError(f"{service}: resource not found.")
    if code == 429:
        raise ICloudConnectionError(f"{service} rate limit hit; retry later.")
    if not 200 <= code < 300:
        raise ICloudCalendarError(f"{service} request failed ({code}): {_detail(resp)}")
    if code == 204:
        return None
    try:
        return resp.json()
    except ValueError:
        return None

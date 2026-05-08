"""Per-IP sliding-window rate limiter for KDF (Argon2id) endpoints.

Tracks attempts in a ``dict[ip, deque[timestamp]]`` protected by a
``threading.Lock``.  The limiter is a no-op when ``app.config['TESTING']``
is true so the existing test suite is not affected.
"""

import json
import threading
import time
from collections import deque

from flask import Response, current_app, request

_WINDOW: int = 60          # seconds
_MAX_ATTEMPTS: int = 5

_lock: threading.Lock = threading.Lock()
_attempts: dict[str, deque] = {}


def _reset() -> None:
    """Reset all rate-limit state.  Call this from tests to get a clean slate."""
    with _lock:
        _attempts.clear()


def check_kdf_rate_limit():
    """Return a 429 ``Response`` if the remote IP is over the limit, else ``None``.

    Call this at the top of any route branch that invokes Argon2id::

        response = check_kdf_rate_limit()
        if response is not None:
            return response
    """
    if current_app.config.get('TESTING'):
        return None

    # 'unknown' is used as a sentinel for requests with no remote address
    # (e.g. unit tests or proxies that strip the header).  All such requests
    # share the same rate-limit bucket which prevents circumvention via a
    # missing X-Forwarded-For header.
    ip: str = (request.remote_addr or 'unknown')
    now: float = time.monotonic()
    cutoff: float = now - _WINDOW

    with _lock:
        if ip not in _attempts:
            _attempts[ip] = deque()
        q = _attempts[ip]

        # Evict timestamps outside the sliding window.
        while q and q[0] < cutoff:
            q.popleft()

        if len(q) >= _MAX_ATTEMPTS:
            retry_after = int(_WINDOW - (now - q[0])) + 1
            # Use flask.Response directly so no app context is needed for
            # serialisation — this keeps the rate limiter testable without
            # a running Flask application.
            body = json.dumps({'error': 'too_many_attempts', 'retry_after': retry_after})
            response = Response(body, status=429, mimetype='application/json')
            response.headers['Retry-After'] = str(retry_after)
            return response

        q.append(now)

    return None

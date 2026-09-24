"""Authentication boundary seam for the browser-facing API.

P4-02 does not implement authentication, and deliberately does not imitate one. The
architecture places ``/api/status`` on the authenticated surface and makes identity
server-owned, so the foundation fails closed instead of serving operational status to
an unauthenticated caller.

This module exists so that opening the authenticated surface in P4-04/P4-08 is a
dependency swap in one place rather than a rewrite of the routes. There are no
credentials to check, no session store, and no request shape that can satisfy it.
"""

from typing import NoReturn

from fastapi import HTTPException, status


def require_authenticated_identity() -> NoReturn:
    """Refuse every request until a real identity provider exists.

    P4-04 replaces this with a dependency that resolves the server-side web session
    and returns the authenticated identity. Until then every route that depends on it
    answers 401, so no authenticated route is reachable from the browser.
    """
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication is not available yet.",
    )

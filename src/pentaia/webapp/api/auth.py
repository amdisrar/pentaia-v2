"""Authentication surface routes.

P4-04 ships logout only. There is deliberately **no login route**: establishing an
identity requires an AD/LDAPS bind (P4-05) or a RADIUS access-request (P4-06), and
inventing a placeholder login would be a fake authentication system.

Logout destroys server-side session state, which is the authoritative act. Deleting the
cookie alone would leave a live session behind, and a valid session is required to call
this route, so an unknown or expired session cannot use it to probe for existence.

The session is destroyed by its safe label rather than by its identifier: the
resolution dependency deliberately never exposes the raw identifier to route code, and
the label identifies exactly one session.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status

from pentaia.webapp.api.dependencies import (
    require_authenticated_session,
    session_store,
)
from pentaia.webapp.sessions import WebSession, session_cookie_settings

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/auth",
    tags=["auth"],
    dependencies=[Depends(require_authenticated_session)],
)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
    session: Annotated[WebSession, Depends(require_authenticated_session)],
) -> Response:
    """Destroy the caller's session and clear its cookie.

    The cookie is cleared with the same attributes it will be set with, so browsers
    match and remove it. Clearing it is a courtesy to the browser; the server-side
    destruction is what ends the session.
    """
    invalidated = session_store(request).invalidate_label(session.label)

    logger.info(
        "Web session logout session_label=%s invalidated=%s user_id=%s",
        session.label,
        invalidated,
        session.identity.user_id,
    )

    # Clear the cookie with the same attributes it will be set with, so browsers match
    # and remove the right cookie.
    settings = session_cookie_settings()
    response.delete_cookie(
        key=settings["key"],
        path=settings["path"],
        httponly=settings["httponly"],
        secure=settings["secure"],
        samesite=settings["samesite"],
    )
    response.status_code = status.HTTP_204_NO_CONTENT

    return response

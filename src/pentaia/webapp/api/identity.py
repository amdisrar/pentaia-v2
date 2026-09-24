"""Authenticated identity projection.

``GET /api/me`` is the application's answer to "who am I", resolved from the
server-side session rather than from anything the browser supplied. It exists in P4-04
because identity resolution is only meaningfully tested through the HTTP surface it
protects, and because the architecture lists it as part of the browser API.

The projection is an explicit whitelist of identity fields. It carries no session
identifier, no cookie value, no credential and no provider secret.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from pentaia.webapp.api.dependencies import require_authenticated_identity
from pentaia.webapp.identity import AuthenticatedIdentity

router = APIRouter(
    prefix="/api",
    tags=["identity"],
    dependencies=[Depends(require_authenticated_identity)],
)


class IdentityResponse(BaseModel):
    """Safe projection of the authenticated identity.

    These fields are the whole contract. A session identifier, cookie value, token or
    provider credential must never be added here.
    """

    user_id: str
    username: str
    display_name: str
    auth_source: str
    authenticated_at: datetime


def build_identity_payload(identity: AuthenticatedIdentity) -> IdentityResponse:
    """Project an identity onto the safe response shape."""
    return IdentityResponse(
        user_id=identity.user_id,
        username=identity.username,
        display_name=identity.display_name,
        auth_source=identity.auth_source,
        authenticated_at=identity.authenticated_at,
    )


@router.get("/me", response_model=IdentityResponse)
async def me(
    identity: Annotated[AuthenticatedIdentity, Depends(require_authenticated_identity)],
) -> IdentityResponse:
    """Return the caller's own identity, resolved from the server-side session."""
    return build_identity_payload(identity)

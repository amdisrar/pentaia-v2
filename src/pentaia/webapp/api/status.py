"""Authenticated operational status foundation.

The architecture puts ``/api/status`` on the authenticated surface and defines it as
safe application/provider status. P4-02 therefore registers the route with the
authentication dependency already attached, which means it answers 401 and exposes
nothing until P4-04 supplies an identity.

The router carries the authentication dependency rather than the individual route.
That makes authenticated-by-default the behaviour for everything mounted under
``/api``, so a later route cannot become reachable by forgetting to add the
dependency. A route that must be reachable without an identity (login) belongs on its
own router, which is a deliberate, visible choice rather than an omission.

The safe payload shape is defined now so later issues fill it in instead of inventing
it, and so the "no secrets in status" rule has one place to live.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from pentaia.webapp.api.dependencies import require_authenticated_identity

router = APIRouter(
    prefix="/api",
    tags=["status"],
    dependencies=[Depends(require_authenticated_identity)],
)

APPLICATION_NAME = "pentaia"


class StatusResponse(BaseModel):
    """Safe application status for an authenticated operator.

    Every field here is safe to show an authenticated operator. The following must
    never be added: environment variables, credentials or API keys, SSH key material,
    session secrets, identity-provider secrets, Kali host details, and target
    information. Operational facts such as provider reachability belong here only
    once the corresponding component exists.
    """

    application: str = APPLICATION_NAME
    authentication_provider: str | None = None


def build_status_payload() -> StatusResponse:
    """Build the current safe status payload.

    P4-02 has no authentication provider and no accounting store, so the only honest
    values are the application name and an absent provider. Later issues extend this
    function; they must keep the result free of secrets.
    """
    return StatusResponse()


@router.get("/status", response_model=StatusResponse)
async def status_endpoint() -> StatusResponse:
    """Return safe application status to an authenticated caller.

    Unreachable until authentication exists: the router dependency refuses first, by
    design.
    """
    return build_status_payload()

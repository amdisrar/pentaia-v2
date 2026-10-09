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

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from pentaia.webapp.api.dependencies import (
    authentication_provider,
    require_authenticated_identity,
)
from pentaia.webapp.auth.base import AuthProvider

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

    ``authentication_provider`` is the canonical token of the active provider
    (``"ad"``), or ``None`` when the deployment selected none. ``authentication_ready``
    says whether this process can authenticate anyone at all, so liveness and the
    ability to authenticate are never conflated: a deployment with no provider answers
    ``/healthz`` and reports ``authentication_provider: null`` here.

    Readiness is a *construction* fact, not a reachability check. The identity source
    is contacted when a credential is verified (P4-08), not while the application
    starts, so ``authentication_ready`` does not promise the directory is up.
    """

    application: str = APPLICATION_NAME
    authentication_provider: str | None = None
    authentication_ready: bool = False


def build_status_payload(auth_provider: AuthProvider | None = None) -> StatusResponse:
    """Build the current safe status payload.

    Both authentication fields are derived from the one active provider object, so
    they cannot disagree: the provider that exists *is* the provider that is named.

    P4-02 had no provider to report. Later issues extend this function; they must keep
    the result free of secrets.
    """
    return StatusResponse(
        authentication_provider=None if auth_provider is None else auth_provider.name,
        authentication_ready=auth_provider is not None,
    )


@router.get("/status", response_model=StatusResponse)
async def status_endpoint(request: Request) -> StatusResponse:
    """Return safe application status to an authenticated caller.

    Unreachable until authentication exists: the router dependency refuses first, by
    design.
    """
    return build_status_payload(authentication_provider(request))

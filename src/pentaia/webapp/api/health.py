"""Unauthenticated liveness endpoint."""

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    """Liveness only.

    Deliberately one static field. The endpoint is unauthenticated, so it must not
    reveal environment variables, host names, credentials, API keys, Kali details,
    authentication configuration, internal stack information or target information.
    Anything that would help an unauthenticated caller map the deployment belongs in
    the authenticated status surface instead.
    """

    status: Literal["ok"] = "ok"


@router.get("/healthz", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Report that the application is alive, and nothing else."""
    return HealthResponse()

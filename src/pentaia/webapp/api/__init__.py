"""Browser-facing HTTP routes for the Phase 4 web application.

Only the routes P4-02 defines are registered here. The rest of the surface (login,
conversations, approval, accounting) is added by later issues.

Nothing registered here may accept a target, an action id, tool arguments, runtime
parameters, a proposal object, an approval object or a proposal signature: those are
resolved and validated server-side. No route may build a native command or reach the
Kali executor, directly or indirectly, because the web layer must not become a second
execution path to Kali. ``tests/test_webapp_boundaries.py`` enforces both rules.
"""

from fastapi import APIRouter

from pentaia.webapp.api.health import router as health_router
from pentaia.webapp.api.status import router as status_router

API_ROUTERS: tuple[APIRouter, ...] = (health_router, status_router)

__all__ = ["API_ROUTERS"]

"""Browser-facing HTTP routes for the Phase 4 web application.

Every router mounted here carries the session-resolution dependency, so the whole
``/api`` surface is authenticated by default and a new route cannot become reachable
by forgetting to add it. ``tests/test_webapp_auth.py`` asserts that property across
every route the schema advertises, which catches a future route that omits it.

Nothing registered here may accept a target, an action id, tool arguments, runtime
parameters, a proposal object, an approval object or a proposal signature: those are
resolved and validated server-side. No route may build a native command or reach the
Kali executor, directly or indirectly, because the web layer must not become a second
execution path to Kali. ``tests/test_webapp_boundaries.py`` enforces both rules.

``/api/auth/login`` is intentionally absent. Authentication providers arrive in P4-05
and P4-06, and P4-04 adds no placeholder that could be mistaken for a login.
"""

from fastapi import APIRouter

from pentaia.webapp.api.auth import router as auth_router
from pentaia.webapp.api.health import router as health_router
from pentaia.webapp.api.identity import router as identity_router
from pentaia.webapp.api.status import router as status_router

API_ROUTERS: tuple[APIRouter, ...] = (
    health_router,
    status_router,
    identity_router,
    auth_router,
)

__all__ = ["API_ROUTERS"]

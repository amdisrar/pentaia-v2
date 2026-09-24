"""Static GUI shell routes.

P4-03 serves the browser interface as plain HTML, CSS and JavaScript. There is no
server-side templating and no injected configuration, so the bytes the browser
receives are exactly the bytes in ``static/``: the shell cannot leak backend settings
even by accident, and it cannot render a value the server did not put in a file.

Routing rules:

- ``GET /`` serves the shell. It is excluded from the OpenAPI schema because it is a
  document, not part of the JSON API surface.
- ``/static`` is the only mounted directory. It is mounted with ``html=False`` so
  directory requests are 404 rather than a listing, and Starlette resolves every path
  beneath that one directory, so no repository file is reachable.
- There is deliberately no catch-all route. A catch-all would have to exclude ``/api``
  and ``/healthz`` by hand and could silently shadow them; the shell instead keeps its
  own state in the URL fragment, which the server never sees. Deep-link support can be
  added later as an explicit decision rather than as a side effect of a wildcard.
"""

from collections.abc import Iterator
from pathlib import Path

from fastapi import APIRouter, FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

STATIC_DIRECTORY = Path(__file__).resolve().parent / "static"
INDEX_FILE = STATIC_DIRECTORY / "index.html"
STATIC_URL_PREFIX = "/static"

router = APIRouter(tags=["gui"])


@router.get("/", include_in_schema=False)
async def index() -> FileResponse:
    """Serve the GUI shell document."""
    return FileResponse(INDEX_FILE, media_type="text/html")


def mount_gui(app: FastAPI) -> None:
    """Attach the GUI shell routes and static assets to the application."""
    app.include_router(router)

    # html=False disables directory listings and implicit index resolution.
    app.mount(
        STATIC_URL_PREFIX,
        StaticFiles(directory=STATIC_DIRECTORY, html=False),
        name="static",
    )


def static_files() -> Iterator[Path]:
    """Every file shipped with the shell, for tests and packaging checks."""
    return (
        path for path in sorted(STATIC_DIRECTORY.rglob("*")) if path.is_file()
    )

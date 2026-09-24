"""Phase 4 web application package.

The web layer may import the existing PentAiA core; the core must never import this
package. ``create_app`` is re-exported here so an ASGI server can be pointed at a
single documented name:

    uv run uvicorn --factory pentaia.webapp:create_app
"""

from pentaia.webapp.app import create_app
from pentaia.webapp.config import WebAppConfig, load_webapp_config

__all__ = ["WebAppConfig", "create_app", "load_webapp_config"]

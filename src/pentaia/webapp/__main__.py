"""Run the Phase 4 web application with uvicorn.

    uv run python -m pentaia.webapp

Configuration is read and validated, and the authentication provider is selected and
built, before the server binds. A bad setting or an unusable provider therefore fails
immediately with a message naming the setting at fault instead of starting a
misconfigured service; nothing is served and no other authentication mechanism is
substituted. The bind address comes from the validated configuration rather than from
uvicorn's command-line defaults.
"""

import logging
import sys

import uvicorn

from pentaia.logging_config import setup_logging
from pentaia.webapp.app import create_app
from pentaia.webapp.auth.base import ProviderError
from pentaia.webapp.config import load_webapp_config

logger = logging.getLogger(__name__)

#: Exit status for a configuration or provider-selection failure. Distinct from the
#: status uvicorn uses for its own errors so a supervisor can tell the two apart.
STARTUP_FAILED_STATUS = 2


def main() -> None:
    setup_logging()

    try:
        config = load_webapp_config()
        app = create_app(config)
    except (ValueError, ProviderError) as exc:
        # Written to stderr as well as the log: logging is file-only, and an operator
        # watching the terminal must see why the service did not come up. The messages
        # name the offending setting and never include credential material.
        sys.stderr.write(f"PentAiA web application refused to start: {exc}\n")

        raise SystemExit(STARTUP_FAILED_STATUS) from None

    logger.info(
        "Starting PentAiA web application host=%s port=%s", config.host, config.port
    )

    # ``proxy_headers=False`` is deliberate. uvicorn would otherwise rewrite
    # ``scope["client"]`` from ``X-Forwarded-For`` using its own trust list, which would
    # leave the application unable to tell a forwarded address from a real peer. The
    # trust boundary lives in ``pentaia.webapp.auth.client_ip`` instead, driven by
    # PENTAIA_TRUSTED_PROXIES, so there is exactly one place that decides what a client's
    # address is and it is covered by tests.
    #
    # Consequence to keep in mind: ``request.url.scheme`` is ``http`` behind the TLS
    # proxy. Nothing depends on it today (the session cookie is unconditionally Secure
    # and no route redirects); a later issue that needs the forwarded scheme must add it
    # beside that same trust check rather than re-enabling rewriting here.
    uvicorn.run(
        app,
        host=config.host,
        port=config.port,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()

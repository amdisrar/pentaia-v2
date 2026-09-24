"""Run the Phase 4 web application with uvicorn.

    uv run python -m pentaia.webapp

Configuration is read and validated before the server binds, so a bad setting fails
immediately with a message naming the variable instead of starting a misconfigured
service. The bind address comes from the validated configuration rather than from
uvicorn's command-line defaults.
"""

import logging

import uvicorn

from pentaia.logging_config import setup_logging
from pentaia.webapp.app import create_app
from pentaia.webapp.config import load_webapp_config

logger = logging.getLogger(__name__)


def main() -> None:
    setup_logging()

    config = load_webapp_config()

    logger.info(
        "Starting PentAiA web application host=%s port=%s", config.host, config.port
    )

    uvicorn.run(create_app(config), host=config.host, port=config.port)


if __name__ == "__main__":
    main()

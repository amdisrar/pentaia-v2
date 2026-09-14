"""Shared test isolation.

Two pieces of runtime state are process-local and environment-driven, and both can
leak between tests:

- the listener port reservation registry in ``pentaia.phase3_ports``, which is
  module state, and
- the ``PENTAIA_LPORT_MIN``/``PENTAIA_LPORT_MAX`` pool, which is read from the
  environment that ``load_dotenv`` populates from the developer's ``.env``.

Without this, one test's reservation stays live for the next (exhausting the pool),
and a developer's local pool configuration changes the behaviour of tests that
expect the single-port fallback. Tests must not depend on ambient configuration.
"""

import logging

import pytest

from pentaia.phase3_ports import reset_listener_port_reservations


@pytest.fixture(scope="session", autouse=True)
def redirect_application_log(tmp_path_factory: pytest.TempPathFactory):
    """Keep the test suite's audit events out of the real logs/pentaia.log.

    Modules call setup_logging() at import time, which installs a FileHandler on
    logs/pentaia.log. Test runs therefore injected phase3 audit and listener-port
    events into the developer's production log, which made that log misleading to
    read back and impossible to correlate with a real CLI run.
    """
    target = tmp_path_factory.mktemp("logs") / "pentaia-test.log"

    root = logging.getLogger()

    for handler in list(root.handlers):
        if isinstance(handler, logging.FileHandler):
            root.removeHandler(handler)
            handler.close()

    handler = logging.FileHandler(target)
    handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    )
    root.addHandler(handler)

    yield

    root.removeHandler(handler)
    handler.close()


@pytest.fixture(autouse=True)
def isolate_listener_port_state(monkeypatch: pytest.MonkeyPatch):
    """Give every test a clean reservation registry and no ambient port pool."""
    monkeypatch.delenv("PENTAIA_LPORT_MIN", raising=False)
    monkeypatch.delenv("PENTAIA_LPORT_MAX", raising=False)
    reset_listener_port_reservations()

    yield

    reset_listener_port_reservations()

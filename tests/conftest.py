"""Shared test isolation.

Three pieces of runtime state are process-local or environment-driven, and all can leak
between tests or reach outside the repository:

- the listener port reservation registry in ``pentaia.phase3_ports``, which is module
  state,
- the ``PENTAIA_LPORT_MIN``/``PENTAIA_LPORT_MAX`` pool, which is read from the environment
  that ``load_dotenv`` populates from the developer's ``.env``, and
- the application store and authentication-provider configuration, which can point the
  durable SQLite store at a real data directory a test run has no business opening, and
  make ``create_app()`` build the real AD provider from the developer's ``.env``.

Without this, one test's reservation stays live for the next (exhausting the pool), a
developer's local pool configuration changes the behaviour of tests that expect the
single-port fallback, and a ``.env`` that selects the durable store makes ``create_app()``
open — and potentially migrate — the developer's real database. Tests must not depend on
ambient configuration.
"""

import logging

import pytest

from pentaia.appstore.config import DATA_DIR_ENV, STORE_MODE_ENV, STORE_MODE_MEMORY
from pentaia.phase3_ports import reset_listener_port_reservations
from pentaia.webapp.config import AUTH_PROVIDER_ENV


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


@pytest.fixture(autouse=True)
def isolate_application_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep every test off the durable store a developer may have configured.

    ``create_app()`` with no arguments loads the environment, and ``load_webapp_config``
    loads ``.env`` on top of it. A developer whose ``.env`` selects
    ``PENTAIA_STORE_MODE=sqlite`` would otherwise have the suite open and migrate their
    real database — and any test that builds an app without an explicit configuration would
    fail wherever that directory is not writable.

    Both variables are *set* rather than deleted, which is the part worth understanding:
    ``monkeypatch.delenv`` would remove them only for ``load_dotenv`` to put them straight
    back from ``.env``. ``load_dotenv`` does not override a variable that is already
    present, so a value set here wins:

    * the mode is pinned to ``memory``,
    * the data directory is pinned to blank, which is the documented "unset" value, so a
      path from ``.env`` can never be selected, and
    * the authentication provider is pinned to blank, which is likewise the documented
      "no provider" value, so ``create_app()`` cannot build the real AD provider — and
      therefore cannot reach a directory controller — from a developer's ``.env``.

    Tests that want the durable store or a real provider pass an explicit
    ``WebAppConfig`` and inject their own provider; an explicit configuration is never read
    from the environment, so none of them is affected. Tests that set these variables
    themselves with ``monkeypatch.setenv`` still win, because their call happens after this
    fixture.
    """
    monkeypatch.setenv(STORE_MODE_ENV, STORE_MODE_MEMORY)
    monkeypatch.setenv(DATA_DIR_ENV, "")
    monkeypatch.setenv(AUTH_PROVIDER_ENV, "")

"""Configuration foundation for the Phase 4 web application.

Every test passes an explicit mapping rather than relying on the process
environment, so the suite does not depend on the developer's ``.env``.
"""

import pytest

from pentaia.webapp.config import (
    DEFAULT_DOCS_ENABLED,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DOCS_ENV,
    HOST_ENV,
    PORT_ENV,
    WebAppConfig,
    load_webapp_config,
    validate_docs_enabled,
    validate_web_host,
    validate_web_port,
)


def test_defaults_bind_to_loopback_with_documentation_disabled() -> None:
    """The secure default matters more than convenience: nothing public, no docs."""
    config = load_webapp_config({})

    assert config == WebAppConfig()
    assert config.host == DEFAULT_HOST == "127.0.0.1"
    assert config.port == DEFAULT_PORT == 8000
    assert config.docs_enabled is DEFAULT_DOCS_ENABLED is False


def test_explicit_configuration_is_read_and_normalized() -> None:
    config = load_webapp_config(
        {HOST_ENV: "  0.0.0.0  ", PORT_ENV: " 9001 ", DOCS_ENV: " TRUE "}
    )

    assert (config.host, config.port, config.docs_enabled) == ("0.0.0.0", 9001, True)


@pytest.mark.parametrize("value", ["0", "65536", "-1", "not-a-port", "", "   ", "80.5"])
def test_an_invalid_port_is_rejected_and_names_the_variable(value: str) -> None:
    with pytest.raises(ValueError, match=PORT_ENV):
        load_webapp_config({PORT_ENV: value})


@pytest.mark.parametrize(
    "value", ["", "   ", "http://localhost", "host/path", "two words", "host:8000"]
)
def test_an_invalid_host_is_rejected_and_names_the_variable(value: str) -> None:
    with pytest.raises(ValueError, match=HOST_ENV):
        load_webapp_config({HOST_ENV: value})


@pytest.mark.parametrize("value", ["maybe", "2", "", "  "])
def test_an_invalid_documentation_switch_is_rejected(value: str) -> None:
    with pytest.raises(ValueError, match=DOCS_ENV):
        load_webapp_config({DOCS_ENV: value})


def test_a_bool_is_never_accepted_as_a_port() -> None:
    """bool is an int subclass, so this needs an explicit check."""
    with pytest.raises(ValueError, match=PORT_ENV):
        validate_web_port(True)


def test_documentation_switch_accepts_only_documented_values() -> None:
    for value in ("1", "true", "TRUE", "yes", "on"):
        assert validate_docs_enabled(value) is True

    for value in ("0", "false", "No", "off"):
        assert validate_docs_enabled(value) is False


def test_validators_accept_their_typed_values_directly() -> None:
    assert validate_web_host("localhost") == "localhost"
    assert validate_web_port(8080) == 8080
    assert validate_docs_enabled(True) is True


def test_an_ipv6_literal_is_accepted_as_a_host() -> None:
    """A colon alone is not the problem; host:port is."""
    assert validate_web_host("::1") == "::1"
    assert validate_web_host("fd00::1") == "fd00::1"


def test_a_supplied_mapping_ignores_the_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tests must not inherit ambient configuration."""
    monkeypatch.setenv(PORT_ENV, "1234")

    assert load_webapp_config({}).port == DEFAULT_PORT


def test_the_process_environment_is_used_when_no_mapping_is_supplied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(PORT_ENV, "8123")

    assert load_webapp_config().port == 8123

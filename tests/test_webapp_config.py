"""Configuration foundation for the Phase 4 web application.

Every test passes an explicit mapping rather than relying on the process
environment, so the suite does not depend on the developer's ``.env``.
"""

import pytest

from pentaia.webapp.config import (
    DEFAULT_DOCS_ENABLED,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_SESSION_ABSOLUTE_LIFETIME_SECONDS,
    DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS,
    DEFAULT_TRUSTED_PROXIES,
    DOCS_ENV,
    HOST_ENV,
    LOGIN_MAX_ATTEMPTS_ENV,
    LOGIN_MAX_KEYS_ENV,
    LOGIN_WINDOW_SECONDS_ENV,
    PORT_ENV,
    PUBLIC_ORIGIN_ENV,
    SESSION_ABSOLUTE_LIFETIME_ENV,
    SESSION_IDLE_TIMEOUT_ENV,
    TRUSTED_PROXIES_ENV,
    WebAppConfig,
    load_webapp_config,
    normalize_origin,
    validate_docs_enabled,
    validate_login_max_attempts,
    validate_login_max_keys,
    validate_login_window_seconds,
    validate_public_origin,
    validate_session_absolute_lifetime,
    validate_session_idle_timeout,
    validate_trusted_proxies,
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


# --- P4-08 session, proxy and throttling settings --------------------------


def test_the_defaults_are_the_architecture_values() -> None:
    config = load_webapp_config({})

    assert config.session_idle_timeout == DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS == 30 * 60
    assert (
        config.session_absolute_lifetime
        == DEFAULT_SESSION_ABSOLUTE_LIFETIME_SECONDS
        == 12 * 60 * 60
    )
    assert config.trusted_proxies == DEFAULT_TRUSTED_PROXIES == ("127.0.0.1",)
    assert config.login_max_attempts == 5
    assert config.login_window_seconds == 15 * 60
    assert config.login_max_keys == 10_000


def test_the_session_settings_are_read_from_the_environment() -> None:
    config = load_webapp_config(
        {
            SESSION_IDLE_TIMEOUT_ENV: "900",
            SESSION_ABSOLUTE_LIFETIME_ENV: "3600",
            LOGIN_MAX_ATTEMPTS_ENV: "3",
            LOGIN_WINDOW_SECONDS_ENV: "120",
            LOGIN_MAX_KEYS_ENV: "500",
        }
    )

    assert config.session_idle_timeout == 900
    assert config.session_absolute_lifetime == 3600
    assert config.login_max_attempts == 3
    assert config.login_window_seconds == 120
    assert config.login_max_keys == 500


@pytest.mark.parametrize("value", ["59", "0", "-1", "86401", "soon", ""])
def test_an_invalid_idle_timeout_is_rejected(value: str) -> None:
    with pytest.raises(ValueError) as caught:
        load_webapp_config({SESSION_IDLE_TIMEOUT_ENV: value})

    assert SESSION_IDLE_TIMEOUT_ENV in str(caught.value)


@pytest.mark.parametrize("value", ["299", "0", "-1", "604801", "forever", ""])
def test_an_invalid_absolute_lifetime_is_rejected(value: str) -> None:
    with pytest.raises(ValueError) as caught:
        load_webapp_config({SESSION_ABSOLUTE_LIFETIME_ENV: value})

    assert SESSION_ABSOLUTE_LIFETIME_ENV in str(caught.value)


def test_the_documented_minimum_absolute_lifetime_is_accepted() -> None:
    """300 seconds is the floor, so a 120-second value is a configuration error."""
    config = load_webapp_config(
        {
            SESSION_IDLE_TIMEOUT_ENV: "60",
            SESSION_ABSOLUTE_LIFETIME_ENV: "300",
        }
    )

    assert config.session_absolute_lifetime == 300


def test_an_idle_timeout_beyond_the_absolute_lifetime_is_rejected() -> None:
    """Otherwise the idle timer could never fire and the policy would be a fiction."""
    with pytest.raises(ValueError) as caught:
        load_webapp_config(
            {
                SESSION_IDLE_TIMEOUT_ENV: "3600",
                SESSION_ABSOLUTE_LIFETIME_ENV: "600",
            }
        )

    message = str(caught.value)
    assert SESSION_IDLE_TIMEOUT_ENV in message
    assert SESSION_ABSOLUTE_LIFETIME_ENV in message


def test_the_idle_timeout_may_equal_the_absolute_lifetime() -> None:
    config = load_webapp_config(
        {
            SESSION_IDLE_TIMEOUT_ENV: "600",
            SESSION_ABSOLUTE_LIFETIME_ENV: "600",
        }
    )

    assert config.session_idle_timeout == config.session_absolute_lifetime == 600


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("127.0.0.1", ("127.0.0.1",)),
        (" 10.0.0.1 , 10.0.0.2 ", ("10.0.0.1", "10.0.0.2")),
        ("10.0.0.0/8", ("10.0.0.0/8",)),
        ("2001:db8::1", ("2001:db8::1",)),
        ("::1, 10.0.0.0/8", ("::1", "10.0.0.0/8")),
    ],
)
def test_trusted_proxies_accept_addresses_and_networks(value, expected) -> None:
    assert load_webapp_config({TRUSTED_PROXIES_ENV: value}).trusted_proxies == expected


def test_trusted_proxies_may_be_empty_meaning_no_peer_is_trusted() -> None:
    """The safe direction: forwarded headers are then ignored for everyone."""
    assert load_webapp_config({TRUSTED_PROXIES_ENV: ""}).trusted_proxies == ()
    assert load_webapp_config({TRUSTED_PROXIES_ENV: "   "}).trusted_proxies == ()


@pytest.mark.parametrize("value", ["*", "0.0.0.0/0", "::/0"])
def test_trusting_every_peer_is_refused(value: str) -> None:
    """A wildcard would make X-Forwarded-For authoritative for any caller."""
    with pytest.raises(ValueError) as caught:
        load_webapp_config({TRUSTED_PROXIES_ENV: value})

    assert TRUSTED_PROXIES_ENV in str(caught.value)


@pytest.mark.parametrize("value", ["proxy.example.test", "10.0.0.1/33", "not-an-ip"])
def test_unparseable_trusted_proxies_are_refused(value: str) -> None:
    with pytest.raises(ValueError) as caught:
        validate_trusted_proxies(value)

    assert TRUSTED_PROXIES_ENV in str(caught.value)


def test_blank_entries_in_the_trusted_proxy_list_are_tolerated() -> None:
    assert validate_trusted_proxies("10.0.0.1,") == ("10.0.0.1",)


def test_a_non_string_trusted_proxy_setting_is_refused() -> None:
    with pytest.raises(ValueError):
        validate_trusted_proxies(["127.0.0.1"])


@pytest.mark.parametrize("value", [0, 1001, -1, True, "many"])
def test_an_invalid_attempt_allowance_is_rejected(value: object) -> None:
    with pytest.raises(ValueError):
        validate_login_max_attempts(value)


@pytest.mark.parametrize("value", [29, 86401, 0, "soon"])
def test_an_invalid_throttling_window_is_rejected(value: object) -> None:
    with pytest.raises(ValueError):
        validate_login_window_seconds(value)


@pytest.mark.parametrize("value", [99, 1_000_001, 0, "lots"])
def test_an_invalid_throttling_key_bound_is_rejected(value: object) -> None:
    with pytest.raises(ValueError):
        validate_login_max_keys(value)


def test_the_session_validators_accept_typed_values() -> None:
    assert validate_session_idle_timeout(1800) == 1800
    assert validate_session_absolute_lifetime(43200) == 43200
    assert validate_login_window_seconds(900) == 900
    assert validate_login_max_attempts(5) == 5
    assert validate_login_max_keys(10_000) == 10_000


@pytest.mark.parametrize("validator", [validate_session_idle_timeout, validate_login_max_keys])
def test_a_bool_is_never_accepted_as_a_number(validator) -> None:
    with pytest.raises(ValueError):
        validator(True)


# --- the declared public origin (P4-08) ------------------------------------


def test_no_public_origin_is_declared_by_default() -> None:
    assert load_webapp_config({}).public_origin is None


@pytest.mark.parametrize("value", ["", "   "])
def test_a_blank_public_origin_means_undeclared(value: str) -> None:
    assert load_webapp_config({PUBLIC_ORIGIN_ENV: value}).public_origin is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://pentaia.example.test", "https://pentaia.example.test:443"),
        ("https://Pentaia.Example.test/", "https://pentaia.example.test:443"),
        ("  https://pentaia.example.test  ", "https://pentaia.example.test:443"),
        ("http://localhost:8000", "http://localhost:8000"),
        ("https://pentaia.example.test:8443", "https://pentaia.example.test:8443"),
        ("https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
        ("http://pentaia.example.test", "http://pentaia.example.test:80"),
    ],
)
def test_a_declared_public_origin_is_normalized(value: str, expected: str) -> None:
    """Scheme, host and an explicit port, so two spellings of one origin compare equal."""
    assert load_webapp_config({PUBLIC_ORIGIN_ENV: value}).public_origin == expected


@pytest.mark.parametrize(
    "value",
    [
        "pentaia.example.test",
        "ftp://pentaia.example.test",
        "https://pentaia.example.test/path",
        "https://pentaia.example.test?a=1",
        "https://pentaia.example.test#fragment",
        "https://user:secret@pentaia.example.test",
        "https://",
        "null",
        "https://pentaia.example.test:notaport",
    ],
)
def test_an_invalid_public_origin_is_rejected(value: str) -> None:
    with pytest.raises(ValueError) as caught:
        load_webapp_config({PUBLIC_ORIGIN_ENV: value})

    assert PUBLIC_ORIGIN_ENV in str(caught.value)


def test_a_non_string_public_origin_is_rejected() -> None:
    with pytest.raises(ValueError):
        validate_public_origin(["https://pentaia.example.test"])


def test_the_public_origin_accepts_its_typed_value() -> None:
    assert validate_public_origin(None) is None
    assert validate_public_origin("https://h:8443") == "https://h:8443"


@pytest.mark.parametrize(
    "value",
    [None, 42, "", "   ", "host", "null", "https://host/x", "https://host:port"],
)
def test_normalize_origin_returns_none_for_anything_that_is_not_an_origin(
    value: object,
) -> None:
    assert normalize_origin(value) is None


def test_a_directly_built_configuration_normalizes_the_public_origin() -> None:
    """A configuration built without the loader must still hold a canonical origin.

    Otherwise an un-normalized value would compare unequal to every browser Origin and
    silently disable the check for anyone constructing the configuration directly.
    """
    assert (
        WebAppConfig(public_origin="https://Pentaia.Example.test").public_origin
        == "https://pentaia.example.test:443"
    )
    assert WebAppConfig(public_origin=None).public_origin is None

    with pytest.raises(ValueError):
        WebAppConfig(public_origin="not-an-origin")

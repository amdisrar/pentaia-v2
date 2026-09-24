"""P4-05 Active Directory provider configuration.

Configuration must fail closed. These tests pin the rejections rather than the happy
path only, because a silently ignored security setting is the failure mode that matters.
"""

import ssl
from pathlib import Path

import pytest

from pentaia.webapp.auth.ad import (
    CA_FILE_ENV,
    CONNECT_TIMEOUT_ENV,
    DEFAULT_AD_PORT,
    DEFAULT_CONNECT_TIMEOUT_SECONDS,
    DEFAULT_RECEIVE_TIMEOUT_SECONDS,
    HOST_ENV,
    MAX_TIMEOUT_SECONDS,
    PORT_ENV,
    RECEIVE_TIMEOUT_ENV,
    UNSUPPORTED_INSECURE_SETTINGS,
    ADConfig,
    build_tls,
    load_ad_config,
)

HOST = "dc01.example.test"


def write_ca(tmp_path: Path) -> Path:
    bundle = tmp_path / "enterprise-ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----\n")

    return bundle


# --- defaults and valid configuration --------------------------------------


def test_minimal_configuration_uses_the_ldaps_defaults() -> None:
    config = load_ad_config({HOST_ENV: HOST})

    assert config.host == HOST
    assert config.port == DEFAULT_AD_PORT == 636
    assert config.ca_file is None
    assert config.connect_timeout == DEFAULT_CONNECT_TIMEOUT_SECONDS
    assert config.receive_timeout == DEFAULT_RECEIVE_TIMEOUT_SECONDS


def test_the_whole_configuration_can_be_supplied_explicitly(tmp_path: Path) -> None:
    ca = write_ca(tmp_path)

    config = load_ad_config(
        {
            HOST_ENV: "  dc02.example.test  ",
            PORT_ENV: "1636",
            CA_FILE_ENV: str(ca),
            CONNECT_TIMEOUT_ENV: "2.5",
            RECEIVE_TIMEOUT_ENV: "7",
        }
    )

    assert config.host == "dc02.example.test"
    assert config.port == 1636
    assert config.ca_file == ca
    assert config.connect_timeout == 2.5
    assert config.receive_timeout == 7.0


def test_the_configuration_is_frozen() -> None:
    import dataclasses

    config = ADConfig(host=HOST)

    with pytest.raises(dataclasses.FrozenInstanceError):
        config.port = 389  # type: ignore[misc]


def test_an_ipv6_literal_is_accepted_as_a_host() -> None:
    assert ADConfig(host="fd00::1").host == "fd00::1"


def test_the_configuration_carries_no_credential_field() -> None:
    """A direct bind needs no stored privilege, so there must be nowhere to put one."""
    import dataclasses

    fields = {field.name for field in dataclasses.fields(ADConfig)}

    assert fields == {"host", "port", "ca_file", "connect_timeout", "receive_timeout"}

    for forbidden in ("password", "secret", "bind", "base_dn", "username", "filter", "search"):
        assert not [name for name in fields if forbidden in name]


# --- fail-closed validation ------------------------------------------------


@pytest.mark.parametrize("value", ["", "   ", None, 5])
def test_a_missing_or_invalid_host_is_rejected(value: object) -> None:
    with pytest.raises(ValueError, match=HOST_ENV):
        load_ad_config({HOST_ENV: value})  # type: ignore[dict-item]


def test_no_host_at_all_is_rejected() -> None:
    with pytest.raises(ValueError, match=HOST_ENV):
        load_ad_config({})


@pytest.mark.parametrize(
    "value",
    [
        "ldap://dc01.example.test",
        "ldaps://dc01.example.test",
        "https://dc01.example.test",
    ],
)
def test_a_ldap_url_is_refused_rather_than_treated_as_a_host(value: str) -> None:
    """A URL here is usually an attempt to reach a plaintext endpoint."""
    with pytest.raises(ValueError, match="bare host"):
        load_ad_config({HOST_ENV: value})


@pytest.mark.parametrize("value", ["dc01.example.test/path", "dc 01", "host:636"])
def test_a_malformed_host_is_rejected(value: str) -> None:
    with pytest.raises(ValueError, match=HOST_ENV):
        load_ad_config({HOST_ENV: value})


@pytest.mark.parametrize("value", ["0", "65536", "-1", "not-a-port", "", "63.6"])
def test_an_invalid_port_is_rejected(value: str) -> None:
    with pytest.raises(ValueError, match=PORT_ENV):
        load_ad_config({HOST_ENV: HOST, PORT_ENV: value})


def test_a_bool_is_never_accepted_as_a_port() -> None:
    with pytest.raises(ValueError, match=PORT_ENV):
        ADConfig(host=HOST, port=True)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        (CONNECT_TIMEOUT_ENV, "0"),
        (CONNECT_TIMEOUT_ENV, "-1"),
        (CONNECT_TIMEOUT_ENV, "abc"),
        (CONNECT_TIMEOUT_ENV, ""),
        (CONNECT_TIMEOUT_ENV, str(MAX_TIMEOUT_SECONDS + 1)),
        (RECEIVE_TIMEOUT_ENV, "0"),
        (RECEIVE_TIMEOUT_ENV, "forever"),
    ],
)
def test_an_invalid_timeout_is_rejected(variable: str, value: str) -> None:
    """Unbounded or nonsensical timeouts must not reach the client."""
    with pytest.raises(ValueError, match=variable):
        load_ad_config({HOST_ENV: HOST, variable: value})


def test_a_timeout_at_the_upper_bound_is_accepted() -> None:
    config = load_ad_config({HOST_ENV: HOST, CONNECT_TIMEOUT_ENV: str(MAX_TIMEOUT_SECONDS)})

    assert config.connect_timeout == MAX_TIMEOUT_SECONDS


def test_a_boolean_timeout_is_rejected() -> None:
    with pytest.raises(ValueError, match=CONNECT_TIMEOUT_ENV):
        ADConfig(host=HOST, connect_timeout=True)  # type: ignore[arg-type]


# --- CA bundle -------------------------------------------------------------


def test_a_nonexistent_ca_file_is_rejected() -> None:
    with pytest.raises(ValueError, match=CA_FILE_ENV):
        load_ad_config({HOST_ENV: HOST, CA_FILE_ENV: "/does/not/exist/ca.pem"})


def test_a_ca_path_that_is_a_directory_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a regular file"):
        load_ad_config({HOST_ENV: HOST, CA_FILE_ENV: str(tmp_path)})


def test_a_non_path_ca_value_is_rejected() -> None:
    with pytest.raises(ValueError, match=CA_FILE_ENV):
        load_ad_config({HOST_ENV: HOST, CA_FILE_ENV: 5})  # type: ignore[dict-item]


def test_an_unreadable_ca_file_is_rejected(tmp_path: Path) -> None:
    ca = write_ca(tmp_path)
    ca.chmod(0o000)

    try:
        with pytest.raises(ValueError, match="not readable"):
            load_ad_config({HOST_ENV: HOST, CA_FILE_ENV: str(ca)})
    finally:
        ca.chmod(0o600)


def test_an_empty_ca_setting_is_treated_as_absent() -> None:
    assert load_ad_config({HOST_ENV: HOST, CA_FILE_ENV: ""}).ca_file is None
    assert load_ad_config({HOST_ENV: HOST, CA_FILE_ENV: "   "}).ca_file is None


# --- TLS enforcement -------------------------------------------------------


def test_certificate_validation_is_required(tmp_path: Path) -> None:
    """There is no mode in which verification is lowered."""
    without_ca = build_tls(ADConfig(host=HOST))
    with_ca = build_tls(ADConfig(host=HOST, ca_file=write_ca(tmp_path)))

    for tls in (without_ca, with_ca):
        assert tls.validate == ssl.CERT_REQUIRED


def test_a_configured_ca_bundle_is_passed_to_the_tls_layer(tmp_path: Path) -> None:
    ca = write_ca(tmp_path)

    tls = build_tls(ADConfig(host=HOST, ca_file=ca))

    assert tls.ca_certs_file == str(ca)


def test_no_ca_bundle_means_the_system_trust_store_is_used() -> None:
    assert build_tls(ADConfig(host=HOST)).ca_certs_file is None


@pytest.mark.parametrize("variable", UNSUPPORTED_INSECURE_SETTINGS)
def test_an_attempt_to_weaken_transport_security_is_refused(variable: str) -> None:
    """Refused, not ignored: an operator must not believe a downgrade took effect."""
    with pytest.raises(ValueError, match="mandatory"):
        load_ad_config({HOST_ENV: HOST, variable: "false"})


@pytest.mark.parametrize("variable", UNSUPPORTED_INSECURE_SETTINGS)
def test_weakening_is_refused_even_when_set_to_a_truthy_value(variable: str) -> None:
    with pytest.raises(ValueError, match="mandatory"):
        load_ad_config({HOST_ENV: HOST, variable: "true"})


def test_the_configuration_module_offers_no_way_to_disable_verification() -> None:
    """Source-level guard: the unsafe constants must not appear at all."""
    from pentaia.webapp.auth import ad

    source = Path(ad.__file__).read_text()

    for forbidden in ("CERT_NONE", "CERT_OPTIONAL", "check_hostname = False", "use_ssl=False"):
        assert forbidden not in source, forbidden


def test_the_process_environment_is_used_when_no_mapping_is_supplied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(HOST_ENV, HOST)
    monkeypatch.delenv(CA_FILE_ENV, raising=False)

    assert load_ad_config().host == HOST

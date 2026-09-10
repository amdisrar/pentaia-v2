import pytest

from pentaia.runtime_config import (
    DEFAULT_LISTENER_PORT,
    get_phase3_callback_address,
    get_phase3_listener_port,
    validate_callback_ipv4,
    validate_listener_port,
)


def test_validate_callback_ipv4_accepts_and_normalizes_ipv4() -> None:
    assert validate_callback_ipv4(" 172.16.0.13 ") == "172.16.0.13"


def test_validate_callback_ipv4_rejects_missing_value() -> None:
    with pytest.raises(ValueError, match="PENTAIA_LHOST is required"):
        validate_callback_ipv4(None)


def test_validate_callback_ipv4_rejects_invalid_value() -> None:
    with pytest.raises(ValueError, match="valid IPv4"):
        validate_callback_ipv4("invalid")


def test_validate_callback_ipv4_rejects_ipv6() -> None:
    with pytest.raises(ValueError, match="valid IPv4"):
        validate_callback_ipv4("2001:db8::1")


def test_get_phase3_callback_address_reads_runtime_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_LHOST", "172.16.0.13")
    assert get_phase3_callback_address() == "172.16.0.13"


def test_get_phase3_callback_address_fails_closed_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PENTAIA_LHOST", raising=False)
    with pytest.raises(ValueError, match="PENTAIA_LHOST is required"):
        get_phase3_callback_address()


# --- runtime-owned listener port -------------------------------------------
#
# The listener port is a material value for a reverse-session action: it is
# resolved by PentAiA, covered by the signed proposal, and revalidated before
# execution.


@pytest.mark.parametrize("value", [4444, "4444", " 4444 ", 1, 65535])
def test_validate_listener_port_accepts_and_normalizes(value) -> None:
    assert validate_listener_port(value) == int(str(value).strip())


@pytest.mark.parametrize(
    "value",
    [0, 65536, -1, "abc", "", "  ", None, True, False, 1.5, "4444; id"],
)
def test_validate_listener_port_rejects_bad_values(value) -> None:
    with pytest.raises(ValueError, match="PENTAIA_LPORT"):
        validate_listener_port(value)


def test_listener_port_defaults_when_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PENTAIA_LPORT", raising=False)
    assert get_phase3_listener_port() == DEFAULT_LISTENER_PORT


def test_listener_port_blank_configuration_uses_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_LPORT", "   ")
    assert get_phase3_listener_port() == DEFAULT_LISTENER_PORT


def test_listener_port_reads_runtime_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_LPORT", "5555")
    assert get_phase3_listener_port() == 5555


def test_listener_port_fails_closed_on_bad_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PENTAIA_LPORT", "not-a-port")
    with pytest.raises(ValueError, match="PENTAIA_LPORT"):
        get_phase3_listener_port()

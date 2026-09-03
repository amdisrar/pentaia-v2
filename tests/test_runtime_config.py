import pytest

from pentaia.runtime_config import (
    get_phase3_callback_address,
    validate_callback_ipv4,
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

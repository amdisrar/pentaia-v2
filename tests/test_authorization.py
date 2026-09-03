import pytest

from pentaia.authorization import authorize_phase3_target


def test_phase3_target_must_be_explicitly_allowlisted(monkeypatch):
    monkeypatch.delenv("PENTAIA_PHASE3_ALLOWLIST", raising=False)
    monkeypatch.delenv("PENTAIA_PHASE3_DENYLIST", raising=False)

    with pytest.raises(ValueError, match="not explicitly authorized"):
        authorize_phase3_target("172.16.0.64")


def test_phase3_allowlisted_target_is_authorized(monkeypatch):
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")
    monkeypatch.delenv("PENTAIA_PHASE3_DENYLIST", raising=False)

    assert authorize_phase3_target("172.16.0.64") == "172.16.0.64"


def test_default_protected_target_cannot_be_overridden(monkeypatch):
    monkeypatch.setenv(
        "PENTAIA_PHASE3_ALLOWLIST",
        "172.16.0.1,172.16.0.64",
    )
    monkeypatch.delenv("PENTAIA_PHASE3_DENYLIST", raising=False)

    with pytest.raises(ValueError, match="protected target"):
        authorize_phase3_target("172.16.0.1")


def test_configured_denylist_overrides_allowlist(monkeypatch):
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")
    monkeypatch.setenv("PENTAIA_PHASE3_DENYLIST", "172.16.0.64")

    with pytest.raises(ValueError, match="protected target"):
        authorize_phase3_target("172.16.0.64")


def test_invalid_allowlist_entry_fails_closed(monkeypatch):
    monkeypatch.setenv(
        "PENTAIA_PHASE3_ALLOWLIST",
        "172.16.0.64,not-an-ip",
    )
    monkeypatch.delenv("PENTAIA_PHASE3_DENYLIST", raising=False)

    with pytest.raises(ValueError, match="PENTAIA_PHASE3_ALLOWLIST"):
        authorize_phase3_target("172.16.0.64")


def test_invalid_target_is_rejected(monkeypatch):
    monkeypatch.setenv("PENTAIA_PHASE3_ALLOWLIST", "172.16.0.64")

    with pytest.raises(ValueError, match="Invalid IPv4 address"):
        authorize_phase3_target("172.16.0.64; whoami")

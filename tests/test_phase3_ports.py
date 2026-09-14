import pytest

from pentaia import phase3_ports
from pentaia.phase3_ports import (
    ListenerPortManager,
    resolve_port_pool,
)

ACTION = "validate_vsftpd_234_backdoor"


def _configure_env(
    monkeypatch: pytest.MonkeyPatch,
    *,
    lhost: str = "172.16.0.13",
    pool: tuple[str, str] | tuple[int, int] | None = None,
) -> None:
    monkeypatch.setenv("PENTAIA_LHOST", lhost)
    monkeypatch.setenv("PENTAIA_LPORT", "4444")
    monkeypatch.delenv("PENTAIA_LPORT_MIN", raising=False)
    monkeypatch.delenv("PENTAIA_LPORT_MAX", raising=False)

    if pool is not None:
        monkeypatch.setenv("PENTAIA_LPORT_MIN", str(pool[0]))
        monkeypatch.setenv("PENTAIA_LPORT_MAX", str(pool[1]))


# --- pool configuration ----------------------------------------------------


def test_no_pool_configured_means_single_port_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch)

    assert resolve_port_pool() is None


def test_pool_is_read_from_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_env(monkeypatch, pool=(5000, 5010))

    assert resolve_port_pool() == (5000, 5010)


@pytest.mark.parametrize(
    ("pool", "match"),
    [
        ((5000, None), "must be set together"),
        ((None, 5010), "must be set together"),
        ((5010, 5000), "must not be greater"),
        ((0, 10), "PENTAIA_LPORT"),
        ((5000, 70000), "PENTAIA_LPORT"),
        ((5000, 5000 + phase3_ports.MAX_POOL_SIZE), "at most"),
    ],
)
def test_invalid_pool_configuration_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    pool,
    match: str,
) -> None:
    _configure_env(monkeypatch)
    if pool[0] is not None:
        monkeypatch.setenv("PENTAIA_LPORT_MIN", str(pool[0]))
    if pool[1] is not None:
        monkeypatch.setenv("PENTAIA_LPORT_MAX", str(pool[1]))

    with pytest.raises(ValueError, match=match):
        resolve_port_pool()


# --- allocation ------------------------------------------------------------


def test_reservation_allocates_the_lowest_free_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch, pool=(5000, 5002))
    manager = ListenerPortManager()

    reservation = manager.reserve(action_id=ACTION, target="172.16.0.64", rport=21)

    assert reservation.lport == 5000
    assert reservation.status == "reserved"
    assert reservation.lhost == "172.16.0.13"
    assert reservation.is_live is True


def test_concurrent_targets_receive_distinct_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch, pool=(5000, 5002))
    manager = ListenerPortManager()

    first = manager.reserve(action_id=ACTION, target="172.16.0.64", rport=21)
    second = manager.reserve(action_id=ACTION, target="172.16.0.65", rport=21)

    assert first.lport == 5000
    assert second.lport == 5001


def test_reservation_is_idempotent_for_the_same_proposal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rebuilding one proposal must reuse its port, or the signature would move."""
    _configure_env(monkeypatch, pool=(5000, 5002))
    manager = ListenerPortManager()

    first = manager.reserve(action_id=ACTION, target="172.16.0.64", rport=21)
    second = manager.reserve(action_id=ACTION, target="172.16.0.64", rport=21)

    assert first.reservation_id == second.reservation_id
    assert first.lport == second.lport


def test_single_port_mode_still_works(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_env(monkeypatch, pool=None)
    manager = ListenerPortManager()

    reservation = manager.reserve(action_id=ACTION, target="172.16.0.64", rport=21)

    assert reservation.lport == 4444


def test_single_port_mode_refuses_a_second_concurrent_proposal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With one approved port, a second live reservation must fail safely."""
    _configure_env(monkeypatch, pool=None)
    manager = ListenerPortManager()

    manager.reserve(action_id=ACTION, target="172.16.0.64", rport=21)

    with pytest.raises(RuntimeError, match="No listener port is available"):
        manager.reserve(action_id=ACTION, target="172.16.0.65", rport=21)


def test_exhausted_pool_fails_safely(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_env(monkeypatch, pool=(5000, 5001))
    manager = ListenerPortManager()

    manager.reserve(action_id=ACTION, target="172.16.0.64", rport=21)
    manager.reserve(action_id=ACTION, target="172.16.0.65", rport=21)

    with pytest.raises(RuntimeError, match="5000-5001"):
        manager.reserve(action_id=ACTION, target="172.16.0.66", rport=21)


def test_a_released_port_becomes_available_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch, pool=(5000, 5000))
    manager = ListenerPortManager()

    first = manager.reserve(action_id=ACTION, target="172.16.0.64", rport=21)
    manager.release(action_id=ACTION, target="172.16.0.64", rport=21)
    second = manager.reserve(action_id=ACTION, target="172.16.0.65", rport=21)

    assert first.lport == second.lport == 5000


@pytest.mark.parametrize("rport", [0, 65536, True, "21", None])
def test_reservation_requires_a_valid_remote_port(
    monkeypatch: pytest.MonkeyPatch,
    rport,
) -> None:
    _configure_env(monkeypatch, pool=(5000, 5001))
    manager = ListenerPortManager()

    with pytest.raises(ValueError, match="remote port"):
        manager.reserve(action_id=ACTION, target="172.16.0.64", rport=rport)


def test_reservation_requires_a_configured_callback_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch, pool=(5000, 5001))
    monkeypatch.delenv("PENTAIA_LHOST", raising=False)
    manager = ListenerPortManager()

    with pytest.raises(ValueError, match="PENTAIA_LHOST"):
        manager.reserve(action_id=ACTION, target="172.16.0.64", rport=21)


# --- activation ------------------------------------------------------------


def test_activation_marks_the_reservation_in_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch, pool=(5000, 5001))
    manager = ListenerPortManager()
    manager.reserve(action_id=ACTION, target="172.16.0.64", rport=21)

    activated = manager.activate(
        action_id=ACTION,
        target="172.16.0.64",
        rport=21,
        proposal_signature="abc123",
    )

    assert activated.status == "active"
    assert activated.proposal_signature == "abc123"
    assert activated.is_live is True


def test_activation_without_a_reservation_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch, pool=(5000, 5001))
    manager = ListenerPortManager()

    with pytest.raises(ValueError, match="No live listener port reservation"):
        manager.activate(action_id=ACTION, target="172.16.0.64", rport=21)


# --- release and expiry ----------------------------------------------------


def test_release_frees_the_port_and_clears_the_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch, pool=(5000, 5000))
    manager = ListenerPortManager()
    manager.reserve(action_id=ACTION, target="172.16.0.64", rport=21)

    assert manager.release(action_id=ACTION, target="172.16.0.64", rport=21) is True
    assert manager.get(action_id=ACTION, target="172.16.0.64", rport=21) is None
    assert manager.reserved_ports() == set()


def test_release_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_env(monkeypatch, pool=(5000, 5000))
    manager = ListenerPortManager()
    manager.reserve(action_id=ACTION, target="172.16.0.64", rport=21)

    assert manager.release(action_id=ACTION, target="172.16.0.64", rport=21) is True
    assert manager.release(action_id=ACTION, target="172.16.0.64", rport=21) is False


def test_release_of_an_unknown_proposal_is_harmless(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch, pool=(5000, 5000))
    manager = ListenerPortManager()

    assert manager.release(action_id=ACTION, target="172.16.0.64", rport=21) is False


def test_expiry_frees_the_port(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_env(monkeypatch, pool=(5000, 5000))
    manager = ListenerPortManager(ttl_seconds=10.0)
    reservation = manager.reserve(action_id=ACTION, target="172.16.0.64", rport=21)

    assert manager.sweep_expired(now=reservation.expires_at + 1) == 1
    assert manager.get(action_id=ACTION, target="172.16.0.64", rport=21) is None
    assert manager.reserved_ports() == set()

    # The freed port can be handed to a different target.
    reused = manager.reserve(action_id=ACTION, target="172.16.0.65", rport=21)
    assert reused.lport == 5000


def test_live_reservations_are_not_swept(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_env(monkeypatch, pool=(5000, 5000))
    manager = ListenerPortManager(ttl_seconds=600.0)
    reservation = manager.reserve(action_id=ACTION, target="172.16.0.64", rport=21)

    assert manager.sweep_expired(now=reservation.created_at + 1) == 0
    assert manager.get(action_id=ACTION, target="172.16.0.64", rport=21) is not None


def test_an_active_reservation_also_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_env(monkeypatch, pool=(5000, 5000))
    manager = ListenerPortManager(ttl_seconds=10.0)
    reservation = manager.reserve(action_id=ACTION, target="172.16.0.64", rport=21)
    manager.activate(action_id=ACTION, target="172.16.0.64", rport=21)

    assert manager.sweep_expired(now=reservation.expires_at + 1) == 1


def test_reset_forgets_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_env(monkeypatch, pool=(5000, 5001))
    manager = ListenerPortManager()
    manager.reserve(action_id=ACTION, target="172.16.0.64", rport=21)

    manager.reset()

    assert manager.all_reservations() == []
    assert manager.reserved_ports() == set()


@pytest.mark.parametrize("ttl", [0, -1])
def test_ttl_must_be_positive(ttl) -> None:
    with pytest.raises(ValueError, match="TTL must be positive"):
        ListenerPortManager(ttl_seconds=ttl)


# --- module-level facade ---------------------------------------------------


def test_module_facade_shares_one_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_env(monkeypatch, pool=(5000, 5001))
    phase3_ports.reset_listener_port_reservations()

    try:
        first = phase3_ports.reserve_listener_port(
            action_id=ACTION, target="172.16.0.64", rport=21
        )
        again = phase3_ports.reserve_listener_port(
            action_id=ACTION, target="172.16.0.64", rport=21
        )
        other = phase3_ports.reserve_listener_port(
            action_id=ACTION, target="172.16.0.65", rport=21
        )

        assert first == again == 5000
        assert other == 5001

        assert phase3_ports.activate_listener_port(
            action_id=ACTION, target="172.16.0.64", rport=21
        ) == 5000
        assert phase3_ports.listener_reservation(
            action_id=ACTION, target="172.16.0.64", rport=21
        ).status == "active"

        assert phase3_ports.release_listener_port(
            action_id=ACTION, target="172.16.0.64", rport=21
        ) is True
        assert phase3_ports.listener_reservation(
            action_id=ACTION, target="172.16.0.64", rport=21
        ) is None
    finally:
        phase3_ports.reset_listener_port_reservations()

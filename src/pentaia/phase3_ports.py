"""Runtime-owned listener port reservation for Phase 3 reverse sessions.

A predefined validation action that calls back needs a local port on the Kali
host. That port is a runtime-owned resource: PentAiA allocates it from an approved
pool, binds the reservation to the pending proposal, and never silently
substitutes a different port after a human has approved one.

Reservations are keyed on the identity of the pending proposal *before* the port is
added -- ``(action_id, target, rport)`` -- because PentAiA rebuilds a proposal
several times for a single approval (gate, signature comparison, execution). A key
that included the port could not be computed before the port existed, and a port
that changed between rebuilds would make every approval look stale.

With no pool configured the manager falls back to the single ``PENTAIA_LPORT``
behaviour, so existing deployments keep working unchanged.

The manager is process-local. Cross-restart persistence is Phase 5 (#50).
"""

import logging
import os
import time
from dataclasses import asdict, dataclass
from typing import Any, Literal
from uuid import uuid4

from pentaia.runtime_config import (
    get_phase3_callback_address,
    get_phase3_listener_port,
    validate_listener_port,
)

logger = logging.getLogger(__name__)

PENTAIA_LPORT_MIN_ENV = "PENTAIA_LPORT_MIN"
PENTAIA_LPORT_MAX_ENV = "PENTAIA_LPORT_MAX"

DEFAULT_RESERVATION_TTL_SECONDS = 900.0
MAX_POOL_SIZE = 256

ReservationStatus = Literal["reserved", "active", "released", "expired"]

LIVE_STATUSES: frozenset[str] = frozenset({"reserved", "active"})


@dataclass(frozen=True)
class PortReservation:
    """One runtime-owned listener port bound to a pending proposal."""

    reservation_id: str
    action_id: str
    target: str
    rport: int
    lhost: str
    lport: int
    status: ReservationStatus
    created_at: float
    expires_at: float
    released_at: float | None = None
    proposal_signature: str | None = None

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.action_id, self.target, self.rport)

    @property
    def is_live(self) -> bool:
        return self.status in LIVE_STATUSES

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _is_port_number(value: object) -> bool:
    """True only for a genuine integer port, never a bool."""
    return isinstance(value, int) and not isinstance(value, bool)


def resolve_port_pool() -> tuple[int, int] | None:
    """Return the configured ``(start, end)`` listener pool, or None for single-port mode."""
    raw_min = os.getenv(PENTAIA_LPORT_MIN_ENV, "").strip()
    raw_max = os.getenv(PENTAIA_LPORT_MAX_ENV, "").strip()

    if not raw_min and not raw_max:
        return None

    if not raw_min or not raw_max:
        raise ValueError(
            f"{PENTAIA_LPORT_MIN_ENV} and {PENTAIA_LPORT_MAX_ENV} must be set together."
        )

    start = validate_listener_port(raw_min)
    end = validate_listener_port(raw_max)

    if start > end:
        raise ValueError(
            f"{PENTAIA_LPORT_MIN_ENV} must not be greater than {PENTAIA_LPORT_MAX_ENV}."
        )

    if end - start + 1 > MAX_POOL_SIZE:
        raise ValueError(
            f"The listener port pool may contain at most {MAX_POOL_SIZE} ports."
        )

    return (start, end)


def _fallback_pool() -> tuple[int, int]:
    """Single-port mode: the one legacy ``PENTAIA_LPORT`` value."""
    port = get_phase3_listener_port()

    return (port, port)


class ListenerPortManager:
    """Process-local registry of runtime-owned listener port reservations."""

    def __init__(self, *, ttl_seconds: float = DEFAULT_RESERVATION_TTL_SECONDS) -> None:
        if ttl_seconds <= 0:
            raise ValueError("Reservation TTL must be positive.")

        self._ttl_seconds = float(ttl_seconds)
        self._reservations: dict[str, PortReservation] = {}
        self._by_key: dict[tuple[str, str, int], str] = {}

    # -- inspection ---------------------------------------------------------

    def get(self, *, action_id: str, target: str, rport: int) -> PortReservation | None:
        """Return the live reservation for a proposal identity, if there is one."""
        self.sweep_expired()

        reservation_id = self._by_key.get((action_id, target, rport))
        if reservation_id is None:
            return None

        reservation = self._reservations[reservation_id]

        return reservation if reservation.is_live else None

    def reserved_ports(self) -> set[int]:
        """Every port currently held by a live reservation."""
        self.sweep_expired()

        return {
            reservation.lport
            for reservation in self._reservations.values()
            if reservation.is_live
        }

    def all_reservations(self) -> list[PortReservation]:
        self.sweep_expired()

        return list(self._reservations.values())

    # -- lifecycle ----------------------------------------------------------

    def reserve(self, *, action_id: str, target: str, rport: int) -> PortReservation:
        """Allocate a port, reusing the existing reservation for this proposal.

        Idempotent by design: rebuilding the same proposal must yield the same
        port, otherwise the proposal signature would change between approval and
        execution and every approval would look stale.
        """
        rport = _require_rport(rport)

        existing = self.get(action_id=action_id, target=target, rport=rport)
        if existing is not None:
            return existing

        lhost = get_phase3_callback_address()
        pool = resolve_port_pool()
        pool = pool if pool is not None else _fallback_pool()

        lport = self._allocate(pool)

        now = time.monotonic()
        reservation = PortReservation(
            reservation_id=uuid4().hex,
            action_id=action_id,
            target=target,
            rport=rport,
            lhost=lhost,
            lport=lport,
            status="reserved",
            created_at=now,
            expires_at=now + self._ttl_seconds,
        )

        self._reservations[reservation.reservation_id] = reservation
        self._by_key[reservation.key] = reservation.reservation_id

        logger.info(
            "Phase 3 listener port reserved action_id=%s target=%s lport=%s reservation_id=%s",
            action_id,
            target,
            lport,
            reservation.reservation_id,
        )

        return reservation

    def activate(
        self,
        *,
        action_id: str,
        target: str,
        rport: int,
        proposal_signature: str | None = None,
    ) -> PortReservation:
        """Mark the reservation as in use by an executing proposal."""
        rport = _require_rport(rport)

        reservation = self.get(action_id=action_id, target=target, rport=rport)
        if reservation is None:
            raise ValueError(
                "No live listener port reservation exists for this proposal."
            )

        activated = PortReservation(
            **{
                **reservation.to_dict(),
                "status": "active",
                "proposal_signature": proposal_signature
                or reservation.proposal_signature,
            }
        )

        self._reservations[activated.reservation_id] = activated
        self._by_key[activated.key] = activated.reservation_id

        logger.info(
            "Phase 3 listener port active action_id=%s target=%s lport=%s",
            action_id,
            target,
            activated.lport,
        )

        return activated

    def release(self, *, action_id: str, target: str, rport: int) -> bool:
        """Release a reservation so its port can be reused. Idempotent."""
        rport = _require_rport(rport)

        reservation_id = self._by_key.get((action_id, target, rport))
        if reservation_id is None:
            return False

        reservation = self._reservations[reservation_id]

        if not reservation.is_live:
            return False

        released = PortReservation(
            **{
                **reservation.to_dict(),
                "status": "released",
                "released_at": time.monotonic(),
            }
        )

        self._reservations[released.reservation_id] = released
        self._by_key.pop(released.key, None)

        logger.info(
            "Phase 3 listener port released action_id=%s target=%s lport=%s",
            action_id,
            target,
            released.lport,
        )

        return True

    def sweep_expired(self, *, now: float | None = None) -> int:
        """Expire stale reservations and free their ports."""
        moment = time.monotonic() if now is None else now
        expired = 0

        for reservation_id, reservation in list(self._reservations.items()):
            if not reservation.is_live or reservation.expires_at > moment:
                continue

            expired_reservation = PortReservation(
                **{
                    **reservation.to_dict(),
                    "status": "expired",
                    "released_at": moment,
                }
            )

            self._reservations[reservation_id] = expired_reservation
            self._by_key.pop(expired_reservation.key, None)
            expired += 1

            logger.info(
                "Phase 3 listener port expired action_id=%s target=%s lport=%s",
                reservation.action_id,
                reservation.target,
                reservation.lport,
            )

        return expired

    def reset(self) -> None:
        """Forget every reservation. Intended for tests and process startup."""
        self._reservations.clear()
        self._by_key.clear()

    # -- internals ----------------------------------------------------------

    def _allocate(self, pool: tuple[int, int]) -> int:
        start, end = pool
        held = self.reserved_ports()

        for port in range(start, end + 1):
            if port not in held:
                return port

        raise RuntimeError(
            f"No listener port is available in the approved pool {start}-{end}."
        )


def _require_rport(value: object) -> int:
    if not _is_port_number(value) or not 1 <= value <= 65535:
        raise ValueError("A listener reservation requires a valid remote port.")

    return value


_manager = ListenerPortManager()


def reserve_listener_port(*, action_id: str, target: str, rport: int) -> int:
    """Reserve (or reuse) the runtime-owned local port for one proposal."""
    return _manager.reserve(action_id=action_id, target=target, rport=rport).lport


def activate_listener_port(
    *,
    action_id: str,
    target: str,
    rport: int,
    proposal_signature: str | None = None,
) -> int:
    """Mark the reserved port as in use by an executing proposal."""
    return _manager.activate(
        action_id=action_id,
        target=target,
        rport=rport,
        proposal_signature=proposal_signature,
    ).lport


def release_listener_port(*, action_id: str, target: str, rport: int) -> bool:
    """Release the reserved port for one proposal."""
    return _manager.release(action_id=action_id, target=target, rport=rport)


def listener_reservation(
    *, action_id: str, target: str, rport: int
) -> PortReservation | None:
    """Return the live reservation for one proposal identity, if any."""
    return _manager.get(action_id=action_id, target=target, rport=rport)


def sweep_listener_port_reservations() -> int:
    """Expire stale reservations. Returns how many were expired."""
    return _manager.sweep_expired()


def reset_listener_port_reservations() -> None:
    """Forget every reservation. Intended for tests and process startup."""
    _manager.reset()

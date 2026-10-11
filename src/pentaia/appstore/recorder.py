"""The interface security-critical callers use to account for what they did.

The distinction this module exists for is **required** versus **optional** accounting.

* ``required=True`` is for an action that must not happen unaccounted: a state-changing
  approval or execution. The call raises :class:`AccountingUnavailable` so the caller
  refuses to proceed. Nothing is executed first and discovered to be unaccounted
  afterwards (architecture §20.7).
* ``required=False`` is for everything else. A failure is logged, the recorder becomes
  observably **degraded**, and the request continues: a read path should not fail because
  the audit store is momentarily busy.

The degraded state is deliberately coarse — a single word, no message, no path, no
exception text — because it is surfaced to an authenticated operator through the status
endpoint, and an error string from a storage layer is exactly the kind of thing that
leaks a filesystem layout. It is also sticky: once an event was not recorded the trail has
a gap, and reporting "active" again would misrepresent that until the process restarts.

``NullAccountingRecorder`` is what a deployment without a durable store gets. It refuses
required events, which is the mechanism that makes the memory mode safe: an operation that
demands accountability cannot run when there is nowhere durable to record it.
"""

import enum
import logging
from typing import Protocol

from pentaia.appstore.accounting import AccountingEvent
from pentaia.appstore.errors import AccountingUnavailable, StoreError
from pentaia.appstore.repository import AccountingRepository

logger = logging.getLogger(__name__)


class AccountingState(enum.Enum):
    """Coarse, safe-to-display accounting health."""

    #: Events are being recorded.
    ACTIVE = "active"
    #: The store is configured but an event was not recorded; the trail has a gap.
    DEGRADED = "degraded"
    #: No durable store is configured; only required events are refused.
    DISABLED = "disabled"


class AccountingRecorder(Protocol):
    """Records accounted events, or refuses when it cannot."""

    def record(self, event: AccountingEvent, *, required: bool = False) -> None:
        """Record one event.

        Raises :class:`AccountingUnavailable` when ``required`` is true and the event
        could not be committed. Callers performing a security-significant change must let
        that propagate as a refusal.
        """
        ...

    @property
    def state(self) -> AccountingState:
        """The current, safe-to-display accounting health."""
        ...


class NullAccountingRecorder:
    """Records nothing, and refuses anything that must be recorded."""

    def __init__(self, *, reason: str = "no durable accounting store is configured") -> None:
        self._reason = reason

    @property
    def state(self) -> AccountingState:
        return AccountingState.DISABLED

    def record(self, event: AccountingEvent, *, required: bool = False) -> None:
        if required:
            raise AccountingUnavailable(self._reason)

        logger.debug(
            "Accounting event not recorded because no store is configured "
            "event_type=%s",
            event.event_type.value,
        )


class RepositoryAccountingRecorder:
    """Records through a repository, translating storage failures by requirement."""

    def __init__(self, repository: AccountingRepository) -> None:
        self._repository = repository
        self._degraded = False

    @property
    def state(self) -> AccountingState:
        return AccountingState.DEGRADED if self._degraded else AccountingState.ACTIVE

    def record(self, event: AccountingEvent, *, required: bool = False) -> None:
        try:
            self._repository.append(event)
        except StoreError as exc:
            # The event type and the requirement are safe to log; the exception text is
            # not, because it can name a path or a database error.
            logger.warning(
                "Accounting event was not recorded event_type=%s required=%s error=%s",
                event.event_type.value,
                required,
                type(exc).__name__,
            )

            if required:
                raise AccountingUnavailable(
                    "the required accounting event could not be committed"
                ) from exc

            self._degraded = True

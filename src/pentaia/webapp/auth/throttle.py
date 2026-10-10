"""Login throttling by username and client address.

The architecture requires throttling "by normalized username and client IP". Three
counters enforce that, all inside one fixed window measured from the first failure of
each key:

* the ``(username, address)`` pair — five failures, the fine-grained control;
* the address alone — four times the pair allowance, which stops one host spraying many
  usernames;
* the username alone — the same, which stops many hosts converging on one account.

Admission and counting are **one atomic operation**, and it is all-or-nothing across all
three counters. A request that is allowed through has already consumed its slot in every
counter, in the same lock acquisition that decided it was allowed; a request that is
refused consumes nothing at all and evicts nothing. There is therefore no window between
deciding and counting, and a burst of concurrent requests for one key cannot slip past the
threshold together: the allowance bounds attempts in flight, not just failures observed so
far. A successful login releases the
pair's slots so a mistyped password does not linger; the aggregate counters keep their
window.

Identities are digests. A raw username is never a key, never stored and never logged:
:func:`throttling_username_key` hashes the normalised name, so the usernames an attacker
probes cannot be read out of this process's state.

State is bounded and eviction cannot be turned into a bypass. When a map is full, only
entries that are **not currently blocking** are dropped, closest to expiry first. A key
that is in its lockout is therefore never evicted, and if every entry is blocking the
request is refused rather than admitted untracked. Growing the map to flush out one's
own block does not work.

Everything takes an injected clock so expiry is tested without sleeping, and the
implementation sits behind :class:`LoginThrottle` so P4-09 can move it to durable
storage without touching the login API.
"""

import hashlib
import math
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from pentaia.webapp.identity import MAX_USERNAME_LENGTH, normalize_username

#: How many times the pair allowance is granted to the aggregate counters. With the
#: approved default of five attempts, one address may fail twenty times and one username
#: may fail twenty times in a window.
AGGREGATE_ATTEMPT_MULTIPLIER = 4

#: Digest length is the full SHA-256 hex string; nothing here is reversible.
_KEY_LENGTH = 64


@dataclass(frozen=True)
class ThrottleDecision:
    """Whether a login attempt may proceed, and when to try again if not."""

    allowed: bool
    retry_after_seconds: int | None = None


def throttling_username_key(value: object) -> str:
    """Derive a stable, non-reversible throttle key for a supplied username.

    Normalisation matches the application identity rules, so ``User@Example.test`` and
    ``user@example.test`` share one key. A value that cannot be normalised is still
    counted — an attacker must not escape throttling by sending a malformed username —
    but it is bounded and hashed first, so it cannot inflate the key space with megabyte
    input. Non-string values collapse to one key.
    """
    if not isinstance(value, str):
        return hashlib.sha256(b"pentaia:non-string-username").hexdigest()

    try:
        material = normalize_username(value)
    except ValueError:
        material = value.strip().lower()[:MAX_USERNAME_LENGTH]

    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()


@dataclass
class _Window:
    """One fixed window: how many failures it holds and when it stops applying."""

    count: int
    expires_at: datetime


class LoginThrottle(Protocol):
    """Admission control for login attempts.

    The seam P4-09 replaces with durable storage. There is deliberately no separate
    "record" step: a caller that has been admitted has already been counted, so a failure
    to record cannot arise and two concurrent callers cannot both be admitted past the
    limit.
    """

    def admit(
        self, *, username_key: str, client_ip: str, now: datetime | None = None
    ) -> ThrottleDecision:
        """Decide whether this pair may attempt a login, and count it if so.

        Refuses when any of the three counters has reached its allowance, and also when
        the state is full of live lockouts and no new key can be admitted; the caller
        must treat both as throttled rather than letting an uncounted attempt through.
        """
        ...

    def record_success(self, *, username_key: str, client_ip: str) -> None:
        """Release the pair's slots after a successful authentication."""
        ...


class InMemoryLoginThrottle:
    """Process-local throttling state.

    Adequate for the single-process Phase 4 application. State does not survive a
    restart, which is the same known limitation the session store carries; P4-09 owns
    moving both behind their interfaces onto durable storage.
    """

    def __init__(
        self,
        *,
        max_attempts: int,
        window_seconds: int,
        max_keys: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._max_attempts = self._positive(max_attempts, field="max_attempts")
        self._window = timedelta(seconds=self._positive(window_seconds, field="window_seconds"))
        self._max_keys = self._positive(max_keys, field="max_keys")
        self._ip_allowance = self._max_attempts * AGGREGATE_ATTEMPT_MULTIPLIER
        self._username_allowance = self._max_attempts * AGGREGATE_ATTEMPT_MULTIPLIER
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._pairs: dict[tuple[str, str], _Window] = {}
        self._by_ip: dict[str, _Window] = {}
        self._by_username: dict[str, _Window] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _positive(value: object, *, field: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"{field} must be a positive integer.")

        return value

    def admit(
        self, *, username_key: str, client_ip: str, now: datetime | None = None
    ) -> ThrottleDecision:
        """Decide and count in one critical section.

        Holding the lock across both is the whole point: a caller cannot be told "yes"
        while another caller is still deciding. Every admitted attempt has already been
        counted, so N concurrent attempts against one pair admit exactly the allowance.
        """
        moment = self._moment(now)

        with self._lock:
            self._purge(moment)

            candidates = (
                (self._pairs.get((username_key, client_ip)), self._max_attempts),
                (self._by_ip.get(client_ip), self._ip_allowance),
                (self._by_username.get(username_key), self._username_allowance),
            )

            retry_after = 0.0

            for window, allowance in candidates:
                if window is None or window.count < allowance:
                    continue

                retry_after = max(
                    retry_after, (window.expires_at - moment).total_seconds()
                )

            if retry_after > 0:
                # At least a second, so a Retry-After never reads as "now".
                return ThrottleDecision(
                    allowed=False,
                    retry_after_seconds=max(1, math.ceil(retry_after)),
                )

            # Every counter is planned before any of them is touched. Either all three
            # are incremented or none is: a refused admission must not consume part of
            # the allowance, and no entry is evicted unless the admission happens.
            targets = (
                (self._pairs, (username_key, client_ip), self._max_attempts),
                (self._by_ip, client_ip, self._ip_allowance),
                (self._by_username, username_key, self._username_allowance),
            )

            plans: list[tuple[dict, list]] = []

            for mapping, key, allowance in targets:
                victims = self._eviction_plan(mapping, key=key, allowance=allowance)

                if victims is None:
                    # Everything tracked in that map is blocking, so no room can be made.
                    # Room appears as those windows expire, which makes the full window an
                    # honest upper bound on how long to wait.
                    return ThrottleDecision(
                        allowed=False,
                        retry_after_seconds=max(
                            1, math.ceil(self._window.total_seconds())
                        ),
                    )

                plans.append((mapping, victims))

            for mapping, victims in plans:
                for victim in victims:
                    mapping.pop(victim, None)

            for mapping, key, _allowance in targets:
                self._bump(mapping, key, moment=moment)

        return ThrottleDecision(allowed=True)

    def record_success(self, *, username_key: str, client_ip: str) -> None:
        """Release the pair's slots. Aggregate windows expire on their own."""
        with self._lock:
            self._pairs.pop((username_key, client_ip), None)

    # -- inspection (tests and diagnostics only) ----------------------------

    @property
    def pair_count(self) -> int:
        with self._lock:
            return len(self._pairs)

    @property
    def address_count(self) -> int:
        with self._lock:
            return len(self._by_ip)

    @property
    def username_count(self) -> int:
        with self._lock:
            return len(self._by_username)

    def counts(
        self, *, username_key: str, client_ip: str
    ) -> tuple[int, int, int]:
        """Attempt counts for one key as ``(pair, address, username)``.

        Inspection only, for tests and diagnostics. It exists so a test can prove that a
        refused admission consumed nothing, rather than inferring it from the sizes of
        internal maps.
        """
        with self._lock:
            pair = self._pairs.get((username_key, client_ip))
            address = self._by_ip.get(client_ip)
            username = self._by_username.get(username_key)

        return (
            pair.count if pair is not None else 0,
            address.count if address is not None else 0,
            username.count if username is not None else 0,
        )

    # -- internals ----------------------------------------------------------

    def _moment(self, now: datetime | None) -> datetime:
        moment = now if now is not None else self._clock()

        if not isinstance(moment, datetime):
            raise TypeError("now must be a datetime.")

        if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
            raise ValueError("now must be timezone-aware.")

        return moment.astimezone(UTC)

    def _purge(self, moment: datetime) -> None:
        for mapping in (self._pairs, self._by_ip, self._by_username):
            for key in [
                key for key, window in mapping.items() if moment >= window.expires_at
            ]:
                mapping.pop(key, None)

    def _eviction_plan(
        self,
        mapping: dict,
        *,
        key: object,
        allowance: int,
    ) -> list | None:
        """Keys to drop so ``key`` fits, or ``None`` when that is impossible.

        Planning is separate from evicting so a later refusal cannot leave an earlier map
        already emptied. A blocking entry is never a candidate: that is what stops a flood
        of new keys from flushing a live lockout out of a bounded map.
        """
        if key in mapping or len(mapping) < self._max_keys:
            return []

        evictable = [
            candidate
            for candidate, window in mapping.items()
            if window.count < allowance
        ]

        if not evictable:
            return None

        needed = len(mapping) - self._max_keys + 1

        return sorted(
            evictable, key=lambda candidate: mapping[candidate].expires_at
        )[:needed]

    def _bump(self, mapping: dict, key: object, *, moment: datetime) -> None:
        """Count one admitted attempt. Room is guaranteed by the plan."""
        window = mapping.get(key)

        if window is None:
            window = _Window(count=0, expires_at=moment + self._window)
            mapping[key] = window

        # The window keeps the expiry set by its first admission, so a lockout ends at a
        # predictable moment instead of being extendable by further attempts.
        window.count += 1

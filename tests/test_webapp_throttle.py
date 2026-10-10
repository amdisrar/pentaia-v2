"""P4-08 login throttling.

Behaviour is asserted with an injected clock: windows expire because time is advanced,
not because a test sleeps. The eviction tests pin the property that matters — a live
lockout cannot be flushed out of the bounded state by an attacker generating new keys.
"""

import re
import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from pentaia.webapp.auth.base import AuthOutcome, AuthResult
from pentaia.webapp.auth.login import LoginOutcome, LoginService
from pentaia.webapp.auth.throttle import (
    AGGREGATE_ATTEMPT_MULTIPLIER,
    InMemoryLoginThrottle,
    ThrottleDecision,
    throttling_username_key,
)
from pentaia.webapp.sessions import InMemorySessionStore


class SlowProvider:
    """A provider that counts calls and holds each one open long enough to race.

    The delay is what makes the old design reproduce reliably: every worker is inside
    ``authenticate`` while the others are still deciding whether to enter it.
    """

    name = "ad"

    def __init__(self, delay: float = 0.05) -> None:
        self.calls = 0
        self._delay = delay
        self._lock = threading.Lock()

    def authenticate(self, username: object, password: object) -> AuthResult:
        with self._lock:
            self.calls += 1

        time.sleep(self._delay)

        return AuthResult(AuthOutcome.REJECTED)

START = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")

IP = "203.0.113.9"
OTHER_IP = "198.51.100.7"


@pytest.fixture()
def throttle() -> InMemoryLoginThrottle:
    return InMemoryLoginThrottle(
        max_attempts=5,
        window_seconds=900,
        max_keys=10_000,
        clock=lambda: START,
    )


def admit(throttle: InMemoryLoginThrottle, username_key: str, ip: str, at=None):
    """One attempt: admission and counting are the same call."""
    return throttle.admit(username_key=username_key, client_ip=ip, now=at)


def attempt(throttle: InMemoryLoginThrottle, username_key: str, ip: str, times: int = 1, at=None):
    """Attempt ``times`` times, asserting each was admitted."""
    for _ in range(times):
        assert admit(throttle, username_key, ip, at).allowed is True


def check(throttle: InMemoryLoginThrottle, username_key: str, ip: str, at=None):
    """Peek at the decision without consuming a slot, for readability in assertions."""
    return throttle.admit(username_key=username_key, client_ip=ip, now=at)


# --- the username key is a digest, never a username ------------------------


def test_a_username_key_is_a_stable_digest() -> None:
    key = throttling_username_key("Admin@Example.test")

    assert HEX_DIGEST.match(key)
    assert key == throttling_username_key("Admin@Example.test")
    assert "admin" not in key
    assert "pentaia" not in key


def test_normalisation_matches_the_identity_rules() -> None:
    """One account must not get two buckets by changing case or padding."""
    assert throttling_username_key("  User@Example.test  ") == throttling_username_key(
        "user@example.test"
    )
    assert throttling_username_key("user@example.test") != throttling_username_key(
        "other@example.test"
    )


@pytest.mark.parametrize(
    "value",
    ["", "   ", "user name", "user:name", "x" * 5000, 42, None, True, b"bytes"],
)
def test_a_malformed_username_is_still_counted_but_bounded(value: object) -> None:
    """An attacker must not escape throttling by sending junk, nor inflate the keyspace."""
    key = throttling_username_key(value)

    assert HEX_DIGEST.match(key)


def test_non_string_values_collapse_to_one_key() -> None:
    assert throttling_username_key(None) == throttling_username_key(42)


# --- the pair allowance ----------------------------------------------------


def test_a_fresh_pair_is_allowed(throttle: InMemoryLoginThrottle) -> None:
    decision = check(throttle, "u", IP)

    assert decision == ThrottleDecision(allowed=True)
    assert decision.retry_after_seconds is None


def test_the_pair_is_blocked_after_the_allowance(throttle: InMemoryLoginThrottle) -> None:
    attempt(throttle, "u", IP, times=5)

    decision = check(throttle, "u", IP, at=START)

    assert decision.allowed is False
    assert decision.retry_after_seconds == 900


def test_a_blocked_pair_does_not_block_a_different_username(
    throttle: InMemoryLoginThrottle,
) -> None:
    attempt(throttle, "u", IP, times=5)

    assert check(throttle, "other", IP).allowed is True


def test_a_blocked_pair_does_not_block_the_same_username_elsewhere(
    throttle: InMemoryLoginThrottle,
) -> None:
    attempt(throttle, "u", IP, times=5)

    assert check(throttle, "u", OTHER_IP).allowed is True


def test_the_pair_is_allowed_again_after_the_window(throttle: InMemoryLoginThrottle) -> None:
    attempt(throttle, "u", IP, times=5)

    assert check(throttle, "u", IP, at=START + timedelta(seconds=900)).allowed is True


def test_the_lockout_window_is_fixed_from_the_first_admission(
    throttle: InMemoryLoginThrottle,
) -> None:
    """A fixed window ends predictably, and attempts made during it count for nothing.

    An attacker cannot extend anyone's lockout by hammering, and cannot shorten it
    either: the deadline was set by the first admitted attempt and no later request
    changes it.
    """
    attempt(throttle, "u", IP, times=5)

    assert admit(throttle, "u", IP).retry_after_seconds == 900

    later = START + timedelta(seconds=600)
    assert admit(throttle, "u", IP, at=later).retry_after_seconds == 300


def test_retry_after_is_at_least_one_second(throttle: InMemoryLoginThrottle) -> None:
    attempt(throttle, "u", IP, times=5)

    decision = check(throttle, "u", IP, at=START + timedelta(seconds=899.5))

    assert decision.retry_after_seconds is not None
    assert decision.retry_after_seconds >= 1


# --- aggregate allowances --------------------------------------------------


def test_one_address_spraying_usernames_is_blocked_by_the_address_counter(
    throttle: InMemoryLoginThrottle,
) -> None:
    allowance = 5 * AGGREGATE_ATTEMPT_MULTIPLIER

    for index in range(allowance // 5):
        attempt(throttle, f"user{index}", IP, times=5)

    assert check(throttle, "brand-new", IP).allowed is False
    # A different address is unaffected.
    assert check(throttle, "brand-new", OTHER_IP).allowed is True


def test_many_addresses_targeting_one_username_are_blocked_by_the_username_counter(
    throttle: InMemoryLoginThrottle,
) -> None:
    allowance = 5 * AGGREGATE_ATTEMPT_MULTIPLIER

    for index in range(allowance):
        attempt(throttle, "target", f"198.51.100.{index}")

    assert check(throttle, "target", "203.0.113.200").allowed is False
    assert check(throttle, "someone-else", "203.0.113.200").allowed is True


def test_a_successful_login_clears_the_pair_not_the_aggregates(
    throttle: InMemoryLoginThrottle,
) -> None:
    """Success releases the pair so a typo does not linger; the address cap still binds."""
    address_allowance = 5 * AGGREGATE_ATTEMPT_MULTIPLIER  # 5 attempts, multiplier 4

    attempt(throttle, "u", IP, times=4)
    throttle.record_success(username_key="u", client_ip=IP)

    # The pair is clear again: the same pair is admitted, which its own counter allows.
    assert admit(throttle, "u", IP).allowed is True

    # The address counter still remembers all five, so spraying other usernames from the
    # same address stays bounded by what is left of the address allowance.
    for index in range(address_allowance - 5):
        assert admit(throttle, f"spray{index}", IP).allowed is True

    assert admit(throttle, "spray-final", IP).allowed is False


# --- bounded state and eviction --------------------------------------------


def test_failure_accounting_stays_bounded() -> None:
    throttle = InMemoryLoginThrottle(
        max_attempts=5, window_seconds=900, max_keys=3, clock=lambda: START
    )

    for index in range(50):
        attempt(throttle, f"user{index}", f"198.51.100.{index}")

    assert throttle.pair_count <= 3
    assert throttle.address_count <= 3
    assert throttle.username_count <= 3


def test_eviction_never_removes_a_blocking_entry() -> None:
    """Filling the map must not flush out a live lockout."""
    throttle = InMemoryLoginThrottle(
        max_attempts=2, window_seconds=900, max_keys=2, clock=lambda: START
    )

    attempt(throttle, "blocked", "203.0.113.1", times=2)
    assert check(throttle, "blocked", "203.0.113.1").allowed is False

    # Generate many new keys; none of them may displace the blocked pair.
    for index in range(10):
        attempt(throttle, f"noise{index}", f"203.0.113.{index + 10}")

    assert check(throttle, "blocked", "203.0.113.1").allowed is False


def test_cannot_make_room_when_every_entry_is_blocking() -> None:
    """With every tracked key blocking, a new attempt is refused rather than untracked."""
    throttle = InMemoryLoginThrottle(
        max_attempts=1, window_seconds=900, max_keys=1, clock=lambda: START
    )

    attempt(throttle, "first", "203.0.113.1", times=1)

    decision = admit(throttle, "second", "203.0.113.2")

    assert decision.allowed is False
    assert decision.retry_after_seconds == 900

    # The blocking entry is still there and the new key was never admitted.
    assert admit(throttle, "first", "203.0.113.1").allowed is False
    assert throttle.pair_count == 1


def test_an_expired_entry_frees_room(throttle: InMemoryLoginThrottle) -> None:
    attempt(throttle, "u", IP, times=5)

    later = START + timedelta(seconds=901)

    assert check(throttle, "u", IP, at=later).allowed is True
    assert check(throttle, "brand-new", IP, at=later).allowed is True


# --- state hygiene ---------------------------------------------------------


def test_no_username_is_stored_in_the_state(throttle: InMemoryLoginThrottle) -> None:
    attempt(throttle, throttling_username_key("admin@example.test"), IP, times=3)

    state = repr(throttle.__dict__)

    assert "admin" not in state
    assert "example.test" not in state


def test_no_username_is_logged(
    throttle: InMemoryLoginThrottle, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    with caplog.at_level(logging.DEBUG):
        attempt(throttle, throttling_username_key("admin@example.test"), IP, times=3)
        check(throttle, throttling_username_key("admin@example.test"), IP)

    assert not caplog.records


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_attempts": 0},
        {"max_attempts": True},
        {"window_seconds": 0},
        {"window_seconds": -1},
        {"max_keys": 0},
    ],
)
def test_the_throttle_configuration_is_validated(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        InMemoryLoginThrottle(
            **{"max_attempts": 5, "window_seconds": 900, "max_keys": 10, **kwargs}
        )


def test_admission_is_the_only_counting_step(throttle: InMemoryLoginThrottle) -> None:
    """There is no separate "record" call, so nothing can be admitted uncounted."""
    for _ in range(5):
        assert admit(throttle, "u", IP).allowed is True

    assert throttle.pair_count == 1
    assert admit(throttle, "u", IP).allowed is False


# --- concurrency: admission and counting are one step ----------------------
#
# These are the regression tests for the race the review found: with a separate check
# and record step, N concurrent requests can all pass the check before any of them is
# counted, so the allowance bounds failures observed rather than attempts in flight.
# The assertions are exact, not probabilistic: the lock makes the admitted count
# deterministic however the threads interleave.


def _run_together(workers):
    """Start every worker at the same moment and collect its result."""
    barrier = threading.Barrier(len(workers))
    results = [None] * len(workers)

    def run(index, worker):
        barrier.wait(timeout=10)
        results[index] = worker(index)

    threads = [
        threading.Thread(target=run, args=(index, worker))
        for index, worker in enumerate(workers)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive(), "a worker deadlocked"

    return results


def test_concurrent_admissions_cannot_exceed_the_pair_allowance() -> None:
    """Forty simultaneous attempts against one pair admit exactly the allowance."""
    throttle = InMemoryLoginThrottle(
        max_attempts=5, window_seconds=900, max_keys=10_000, clock=lambda: START
    )

    decisions = _run_together(
        [lambda index: admit(throttle, "u", IP) for _ in range(40)]
    )

    assert sum(decision.allowed for decision in decisions) == 5
    assert throttle.pair_count == 1


def test_concurrent_attempts_across_usernames_respect_the_address_allowance() -> None:
    """A simultaneous spray from one address cannot slip past the address cap."""
    throttle = InMemoryLoginThrottle(
        max_attempts=5, window_seconds=900, max_keys=10_000, clock=lambda: START
    )
    allowance = 5 * AGGREGATE_ATTEMPT_MULTIPLIER

    decisions = _run_together(
        [lambda index: admit(throttle, f"user{index}", IP) for index in range(40)]
    )

    assert sum(decision.allowed for decision in decisions) == allowance


def test_concurrent_attempts_across_addresses_respect_the_username_allowance() -> None:
    throttle = InMemoryLoginThrottle(
        max_attempts=5, window_seconds=900, max_keys=10_000, clock=lambda: START
    )
    allowance = 5 * AGGREGATE_ATTEMPT_MULTIPLIER

    decisions = _run_together(
        [
            lambda index: admit(throttle, "target", f"198.51.100.{index}")
            for index in range(40)
        ]
    )

    assert sum(decision.allowed for decision in decisions) == allowance


def test_concurrent_attempts_reach_the_provider_only_within_the_allowance() -> None:
    """The end-to-end version: the service admits the allowance, not the burst.

    Each worker blocks briefly inside the provider, which is exactly the window a
    check-then-record design leaves open. With admission counted up front the burst
    cannot outrun the allowance.
    """
    provider = SlowProvider()
    service = LoginService(
        provider=provider,
        throttle=InMemoryLoginThrottle(
            max_attempts=3, window_seconds=900, max_keys=10_000, clock=lambda: START
        ),
        session_store=InMemorySessionStore(),
        clock=lambda: START,
    )

    results = _run_together(
        [
            lambda index: service.authenticate(
                username="victim@example.test",
                password="wrong",
                client_ip=IP,
            )
            for _ in range(12)
        ]
    )

    assert provider.calls == 3, "more attempts reached the provider than the allowance"
    assert sum(result.outcome is LoginOutcome.THROTTLED for result in results) == 9


# --- a refused admission consumes nothing ---------------------------------


def test_a_refused_admission_does_not_consume_partial_quota() -> None:
    """All-or-nothing: the counters move together or not at all.

    The state is built so the pair and username maps could make room but the address map
    cannot, which is the case that used to leave the pair counter incremented by an
    admission that was then refused.
    """
    throttle = InMemoryLoginThrottle(
        max_attempts=2, window_seconds=900, max_keys=1, clock=lambda: START
    )

    # Drive one address to its aggregate allowance so its entry is blocking, using a
    # distinct username each time so no username counter becomes blocking.
    for index in range(2 * AGGREGATE_ATTEMPT_MULTIPLIER):
        assert admit(throttle, f"spray{index}", "203.0.113.1").allowed is True

    # The bounded maps keep the most recent key; its address counter is at its allowance,
    # which is what makes that entry blocking and room impossible.
    assert throttle.counts(username_key="spray7", client_ip="203.0.113.1") == (1, 8, 1)

    decision = admit(throttle, "fresh", "198.51.100.9")

    assert decision.allowed is False
    assert throttle.counts(username_key="fresh", client_ip="198.51.100.9") == (0, 0, 0)


def test_a_refused_admission_evicts_nothing() -> None:
    """A plan that fails for one map must not have emptied another."""
    throttle = InMemoryLoginThrottle(
        max_attempts=2, window_seconds=900, max_keys=2, clock=lambda: START
    )

    # Two blocking address entries fill the address map.
    for address in ("203.0.113.1", "203.0.113.2"):
        for index in range(2 * AGGREGATE_ATTEMPT_MULTIPLIER):
            assert admit(throttle, f"{address}-{index}", address).allowed is True

    before = throttle.address_count

    assert admit(throttle, "fresh", "198.51.100.9").allowed is False
    assert throttle.address_count == before, "nothing may be evicted by a refusal"


def test_an_admitted_attempt_consumes_all_three_counters() -> None:
    throttle = InMemoryLoginThrottle(
        max_attempts=5, window_seconds=900, max_keys=100, clock=lambda: START
    )

    assert admit(throttle, "u", IP).allowed is True

    assert throttle.counts(username_key="u", client_ip=IP) == (1, 1, 1)


def test_a_successful_login_releases_only_the_pair() -> None:
    throttle = InMemoryLoginThrottle(
        max_attempts=5, window_seconds=900, max_keys=100, clock=lambda: START
    )

    attempt(throttle, "u", IP, times=2)
    throttle.record_success(username_key="u", client_ip=IP)

    assert throttle.counts(username_key="u", client_ip=IP) == (0, 2, 2)

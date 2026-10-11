"""Durable sessions and durable login throttling.

These exercise the contracts #58 established against the SQLite implementations: the same
expiry semantics, the same revocation, the same admission rules — plus the two properties
that only a durable store can have (survival across a restart) and the one that only a
transaction can have (a session mutation and its accounting record committing together).
"""

import pathlib
import threading
from datetime import UTC, datetime, timedelta

import pytest

from pentaia.appstore.config import StoreConfig
from pentaia.appstore.connection import SqliteAppStore
from pentaia.appstore.errors import AccountingUnavailable
from pentaia.appstore.recorder import RepositoryAccountingRecorder
from pentaia.appstore.repository import SqliteAccountingRepository
from pentaia.webapp.auth.throttle import AGGREGATE_ATTEMPT_MULTIPLIER
from pentaia.webapp.identity import AuthenticatedIdentity
from pentaia.webapp.persistence import SqliteLoginThrottle, SqliteSessionStore

START = datetime(2026, 10, 10, 22, 11, 41, tzinfo=UTC)
IP = "203.0.113.7"


class Clock:
    def __init__(self, start: datetime = START) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def identity(username: str = "user@example.test") -> AuthenticatedIdentity:
    return AuthenticatedIdentity.from_provider(
        auth_source="ad", username=username, display_name="Example User"
    )


@pytest.fixture()
def clock() -> Clock:
    return Clock()


@pytest.fixture()
def store(tmp_path: pathlib.Path):
    opened = SqliteAppStore.open(StoreConfig(mode="sqlite", data_dir=tmp_path))
    opened.migrate()

    yield opened

    opened.close()


@pytest.fixture()
def repository(store: SqliteAppStore) -> SqliteAccountingRepository:
    return SqliteAccountingRepository(store)


@pytest.fixture()
def sessions(
    store: SqliteAppStore, repository: SqliteAccountingRepository, clock: Clock
) -> SqliteSessionStore:
    return SqliteSessionStore(
        store,
        idle_timeout_seconds=60,
        absolute_lifetime_seconds=600,
        recorder=RepositoryAccountingRecorder(repository),
        clock=clock,
    )


@pytest.fixture()
def throttle(store: SqliteAppStore, clock: Clock) -> SqliteLoginThrottle:
    return SqliteLoginThrottle(
        store, max_attempts=2, window_seconds=900, max_keys=100, clock=clock
    )


def reopen(tmp_path: pathlib.Path) -> SqliteAppStore:
    """A fresh handle over the same database, as a restart would produce."""
    opened = SqliteAppStore.open(StoreConfig(mode="sqlite", data_dir=tmp_path))
    opened.migrate()

    return opened


def event_types(repository: SqliteAccountingRepository) -> list[str]:
    return [str(record.as_mapping()["event_type"]) for record in repository.iter_records()]


# --- durable sessions -------------------------------------------------------


def test_a_created_session_resolves_with_its_identity(
    sessions: SqliteSessionStore,
) -> None:
    issued = sessions.create(identity())

    resolved = sessions.resolve(issued.session_id)

    assert resolved is not None
    assert resolved.identity.user_id == "ad:user@example.test"
    assert resolved.label == issued.session.label
    assert resolved.csrf_token == issued.csrf_token
    assert sessions.active_count == 1


def test_the_raw_identifier_is_never_written(
    store: SqliteAppStore, sessions: SqliteSessionStore, tmp_path: pathlib.Path
) -> None:
    """A copy of the database must not be enough to impersonate anyone."""
    issued = sessions.create(identity())

    assert sessions.holds_raw_identifier(issued.session_id) is False
    assert issued.session_id not in repr(store.paths)

    store.close()

    for path in tmp_path.iterdir():
        if path.is_file():
            assert issued.session_id.encode() not in path.read_bytes(), path.name


def test_a_session_survives_a_restart(
    sessions: SqliteSessionStore, clock: Clock, tmp_path: pathlib.Path
) -> None:
    """Durability is the point of P4-09: the record outlives the process."""
    issued = sessions.create(identity())

    store = reopen(tmp_path)
    revived = SqliteSessionStore(
        store,
        idle_timeout_seconds=60,
        absolute_lifetime_seconds=600,
        recorder=RepositoryAccountingRecorder(SqliteAccountingRepository(store)),
        clock=clock,
    )

    try:
        resolved = revived.resolve(issued.session_id)

        assert resolved is not None
        assert resolved.identity.user_id == "ad:user@example.test"
        # The refresh-recovery contract from P4-08 still works after a restart.
        assert resolved.csrf_token == issued.csrf_token
    finally:
        store.close()


def test_an_idle_session_is_destroyed_and_accounted(
    sessions: SqliteSessionStore,
    repository: SqliteAccountingRepository,
    clock: Clock,
) -> None:
    issued = sessions.create(identity())

    clock.advance(61)

    assert sessions.resolve(issued.session_id) is None
    assert sessions.active_count == 0
    assert event_types(repository) == ["web_session_created", "web_session_expired"]


def test_activity_refreshes_the_idle_timer_but_not_the_absolute_lifetime(
    sessions: SqliteSessionStore, clock: Clock
) -> None:
    issued = sessions.create(identity())

    for _ in range(9):
        clock.advance(59)
        assert sessions.resolve(issued.session_id) is not None

    # 531 seconds of continuous activity: past 600 would already have ended it.
    clock.advance(80)

    assert sessions.resolve(issued.session_id) is None


def test_logout_revokes_and_accounts(
    sessions: SqliteSessionStore, repository: SqliteAccountingRepository
) -> None:
    issued = sessions.create(identity())

    assert sessions.invalidate_label(issued.session.label) is True
    assert sessions.active_count == 0
    assert event_types(repository) == ["web_session_created", "web_session_revoked"]


def test_revocation_by_identifier_and_by_user(
    sessions: SqliteSessionStore,
) -> None:
    first = sessions.create(identity("one@example.test"))
    second = sessions.create(identity("two@example.test"))
    third = sessions.create(identity("two@example.test"))

    assert sessions.invalidate(first.session_id) is True
    assert sessions.invalidate("not-a-session") is False
    assert sessions.invalidate_user("ad:two@example.test") == 2
    assert sessions.active_count == 0
    assert sessions.invalidate_label(second.session.label) is False
    assert third.session_id != second.session_id


def test_purge_expired_removes_only_expired_sessions(
    sessions: SqliteSessionStore, clock: Clock
) -> None:
    expired = sessions.create(identity("old@example.test"))
    clock.advance(400)
    live = sessions.create(identity("new@example.test"))

    assert sessions.purge_expired() == 1
    assert sessions.resolve(expired.session_id) is None
    assert sessions.resolve(live.session_id) is not None


def test_an_unknown_identifier_fails_closed(sessions: SqliteSessionStore) -> None:
    for value in ("", "unknown", "a" * 100):
        assert sessions.resolve(value) is None

    assert sessions.resolve("") is None


def test_the_identity_is_rebuilt_faithfully_across_a_restart(
    sessions: SqliteSessionStore, clock: Clock, tmp_path: pathlib.Path
) -> None:
    issued = sessions.create(identity())
    store = reopen(tmp_path)
    revived = SqliteSessionStore(
        store,
        idle_timeout_seconds=60,
        absolute_lifetime_seconds=600,
        recorder=RepositoryAccountingRecorder(SqliteAccountingRepository(store)),
        clock=clock,
    )

    try:
        resolved = revived.resolve(issued.session_id)

        assert resolved is not None
        assert resolved.identity == issued.session.identity
        assert resolved.created_at == issued.session.created_at
        assert resolved.absolute_expires_at == issued.session.absolute_expires_at
    finally:
        store.close()


def test_a_session_mutation_and_its_event_commit_together(
    store: SqliteAppStore, sessions: SqliteSessionStore
) -> None:
    """The transactional guarantee: no unaccounted session can exist.

    The accounting table is removed, so the lifecycle event cannot be written. The session
    insert shares that transaction and must therefore disappear with it.
    """
    with store.transaction() as connection:
        connection.execute("DROP TABLE accounting_events")

    with pytest.raises(AccountingUnavailable):
        sessions.create(identity())

    with store.reading() as connection:
        assert connection.execute(
            "SELECT COUNT(*) AS total FROM web_sessions"
        ).fetchone()["total"] == 0


# --- durable login throttling -----------------------------------------------


def test_admission_is_durable_and_bounded(throttle: SqliteLoginThrottle) -> None:
    assert throttle.admit(username_key="k", client_ip=IP).allowed is True
    assert throttle.admit(username_key="k", client_ip=IP).allowed is True

    refused = throttle.admit(username_key="k", client_ip=IP)

    assert refused.allowed is False
    assert refused.retry_after_seconds is not None
    assert refused.retry_after_seconds > 0


def test_the_window_expires(throttle: SqliteLoginThrottle, clock: Clock) -> None:
    throttle.admit(username_key="k", client_ip=IP)
    throttle.admit(username_key="k", client_ip=IP)

    assert throttle.admit(username_key="k", client_ip=IP).allowed is False

    clock.advance(901)

    assert throttle.admit(username_key="k", client_ip=IP).allowed is True


def test_counters_survive_a_restart(tmp_path: pathlib.Path, clock: Clock) -> None:
    """A restart must not be a way to clear a lockout."""
    store = reopen(tmp_path)
    first = SqliteLoginThrottle(
        store, max_attempts=2, window_seconds=900, max_keys=100, clock=clock
    )

    for _ in range(2):
        first.admit(username_key="k", client_ip=IP)

    store.close()

    store = reopen(tmp_path)
    second = SqliteLoginThrottle(
        store, max_attempts=2, window_seconds=900, max_keys=100, clock=clock
    )

    try:
        assert second.admit(username_key="k", client_ip=IP).allowed is False
        assert second.counts(username_key="k", client_ip=IP) == (2, 2, 2)
    finally:
        store.close()


def test_a_refused_admission_consumes_nothing(
    store: SqliteAppStore, clock: Clock
) -> None:
    """All three counters move together or not at all."""
    throttle = SqliteLoginThrottle(
        store, max_attempts=2, window_seconds=900, max_keys=1, clock=clock
    )

    # One address reaches its aggregate allowance, so its row blocks.
    for index in range(2 * 4):
        assert throttle.admit(username_key=f"spray{index}", client_ip="203.0.113.1").allowed

    before = throttle.counts(username_key="fresh", client_ip="198.51.100.9")

    # The address scope is full of blocking rows, so nothing can be admitted.
    decision = throttle.admit(username_key="fresh", client_ip="198.51.100.9")

    assert decision.allowed is False
    assert before == (0, 0, 0)
    assert throttle.counts(username_key="fresh", client_ip="198.51.100.9") == (0, 0, 0)


def test_a_successful_login_releases_only_the_pair(
    throttle: SqliteLoginThrottle,
) -> None:
    throttle.admit(username_key="k", client_ip=IP)

    throttle.record_success(username_key="k", client_ip=IP)

    assert throttle.counts(username_key="k", client_ip=IP) == (0, 1, 1)


def test_a_blocking_entry_is_never_evicted(store: SqliteAppStore, clock: Clock) -> None:
    throttle = SqliteLoginThrottle(
        store, max_attempts=1, window_seconds=900, max_keys=2, clock=clock
    )

    assert throttle.admit(username_key="blocked", client_ip="203.0.113.1").allowed is True
    assert throttle.admit(username_key="blocked", client_ip="203.0.113.1").allowed is False

    for index in range(6):
        throttle.admit(username_key=f"noise{index}", client_ip=f"198.51.100.{index}")

    assert throttle.admit(username_key="blocked", client_ip="203.0.113.1").allowed is False


def test_expired_rows_are_pruned(throttle: SqliteLoginThrottle, clock: Clock) -> None:
    throttle.admit(username_key="k", client_ip=IP)
    assert throttle.pair_count == 1

    clock.advance(901)
    throttle.admit(username_key="other", client_ip="198.51.100.9")

    assert throttle.pair_count == 1, "the expired pair row was removed"


def test_concurrent_admissions_admit_exactly_the_allowance(
    store: SqliteAppStore, clock: Clock
) -> None:
    """The transaction is what makes the allowance hold under concurrency."""
    throttle = SqliteLoginThrottle(
        store, max_attempts=3, window_seconds=900, max_keys=100, clock=clock
    )
    barrier = threading.Barrier(12)
    results: list[bool] = []
    results_lock = threading.Lock()

    def attempt() -> None:
        barrier.wait(timeout=10)
        decision = throttle.admit(username_key="victim", client_ip=IP)

        with results_lock:
            results.append(decision.allowed)

    threads = [threading.Thread(target=attempt) for _ in range(12)]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join(timeout=15)

    assert len(results) == 12
    assert sum(results) == 3


def test_a_durable_store_with_no_accounting_refuses_to_create_sessions(
    store: SqliteAppStore, clock: Clock
) -> None:
    """A contradiction, asserted rather than left to chance.

    A durable session store exists so sessions can be accounted; pairing it with a
    recorder that refuses required events would silently produce unaccounted sessions, so
    the creation is refused instead.
    """
    from pentaia.appstore.recorder import NullAccountingRecorder

    contradictory = SqliteSessionStore(
        store,
        idle_timeout_seconds=60,
        absolute_lifetime_seconds=600,
        recorder=NullAccountingRecorder(),
        clock=clock,
    )

    with pytest.raises(AccountingUnavailable):
        contradictory.create(identity())

    assert contradictory.active_count == 0


# --- a refused admission mutates nothing ------------------------------------


def test_a_refused_address_admission_evicts_nothing(
    store: SqliteAppStore, clock: Clock
) -> None:
    """The pair scope could make room, the address scope cannot: nothing may change.

    The pair plan is computed first, and it *would* evict its one non-blocking entry. The
    address scope then refuses because its only entry is blocking. A plan-then-apply
    admission leaves both untouched.
    """
    throttle = SqliteLoginThrottle(
        store, max_attempts=2, window_seconds=900, max_keys=1, clock=clock
    )

    for index in range(2 * AGGREGATE_ATTEMPT_MULTIPLIER):
        assert throttle.admit(
            username_key=f"spray{index}", client_ip="203.0.113.1"
        ).allowed

    decision = throttle.admit(username_key="fresh", client_ip="198.51.100.9")

    assert decision.allowed is False
    assert throttle.counts(username_key="fresh", client_ip="198.51.100.9") == (0, 0, 0)
    # The evictable pair entry, the blocking address entry and the username entry all
    # survive with their counts intact.
    assert throttle.pair_count == 1
    assert throttle.counts(username_key="spray7", client_ip="203.0.113.1") == (1, 8, 1)


def test_a_refused_username_admission_evicts_nothing(
    store: SqliteAppStore, clock: Clock
) -> None:
    """The same guarantee when the *username* scope is the one that refuses."""
    throttle = SqliteLoginThrottle(
        store, max_attempts=2, window_seconds=900, max_keys=1, clock=clock
    )

    for index in range(2 * AGGREGATE_ATTEMPT_MULTIPLIER):
        assert throttle.admit(
            username_key="blocker", client_ip=f"198.51.100.{index}"
        ).allowed

    decision = throttle.admit(username_key="fresh", client_ip="203.0.113.9")

    assert decision.allowed is False
    assert throttle.counts(username_key="fresh", client_ip="203.0.113.9") == (0, 0, 0)
    assert throttle.username_count == 1
    assert throttle.counts(username_key="blocker", client_ip="198.51.100.7")[2] == 8


def test_concurrent_attempts_across_usernames_respect_the_address_allowance(
    store: SqliteAppStore, clock: Clock
) -> None:
    """Aggregate limits hold under concurrency, not only the pair limit."""
    throttle = SqliteLoginThrottle(
        store, max_attempts=2, window_seconds=900, max_keys=100, clock=clock
    )
    allowance = 2 * AGGREGATE_ATTEMPT_MULTIPLIER
    barrier = threading.Barrier(16)
    results: list[bool] = []
    results_lock = threading.Lock()

    def attempt(index: int) -> None:
        barrier.wait(timeout=10)
        decision = throttle.admit(username_key=f"user{index}", client_ip=IP)

        with results_lock:
            results.append(decision.allowed)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(16)]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join(timeout=15)

    assert len(results) == 16
    assert sum(results) == allowance

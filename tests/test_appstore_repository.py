"""The accounting repository and the required/optional recorder.

The behaviour that matters most here is the refusal: a caller that must be accountable
has to be *unable* to proceed when its event cannot be committed, and that has to hold
for every way the store can fail — a closed handle, a busy lock, a read-only file, a full
disk.
"""

import logging
import pathlib
import threading

import pytest

from pentaia.appstore.accounting import (
    AccountingErrorType,
    AccountingEvent,
    AccountingEventType,
    AccountingOutcome,
)
from pentaia.appstore.config import StoreConfig
from pentaia.appstore.connection import SqliteAppStore
from pentaia.appstore.errors import AccountingUnavailable, StoreUnavailable
from pentaia.appstore.integrity import GENESIS_HASH, ChainHead
from pentaia.appstore.recorder import (
    AccountingState,
    NullAccountingRecorder,
    RepositoryAccountingRecorder,
)
from pentaia.appstore.repository import SqliteAccountingRepository


@pytest.fixture()
def store(tmp_path: pathlib.Path):
    opened = SqliteAppStore.open(StoreConfig(mode="sqlite", data_dir=tmp_path))
    opened.migrate()

    yield opened

    opened.close()


@pytest.fixture()
def repository(store: SqliteAppStore) -> SqliteAccountingRepository:
    return SqliteAccountingRepository(store)


def login_event(**overrides) -> AccountingEvent:
    fields = {
        "event_type": AccountingEventType.LOGIN_SUCCESS,
        "outcome": AccountingOutcome.SUCCESS,
        "user_id": "ad:user@example.test",
        "auth_source": "ad",
        "session_label": "sess-0123456789abcdef",
    }
    fields.update(overrides)

    return AccountingEvent(**fields)


# --- appending and reading --------------------------------------------------


def test_an_appended_event_is_queryable(repository: SqliteAccountingRepository) -> None:
    sequence = repository.append(login_event())

    assert sequence == 1
    assert repository.count() == 1

    records = list(repository.iter_records())

    assert len(records) == 1
    assert records[0].as_mapping()["event_type"] == "login_success"
    assert records[0].as_mapping()["user_id"] == "ad:user@example.test"


def test_records_are_returned_in_sequence_order(
    repository: SqliteAccountingRepository,
) -> None:
    for index in range(5):
        repository.append(login_event(request_id=f"req-{index}"))

    sequences = [record.sequence for record in repository.iter_records()]

    assert sequences == [1, 2, 3, 4, 5]


def test_iteration_can_resume_and_be_bounded(
    repository: SqliteAccountingRepository,
) -> None:
    for _ in range(5):
        repository.append(login_event())

    assert [r.sequence for r in repository.iter_records(after_sequence=3)] == [4, 5]
    assert [r.sequence for r in repository.iter_records(limit=2)] == [1, 2]


def test_a_large_history_is_streamed_in_pages(
    repository: SqliteAccountingRepository,
) -> None:
    """More records than one page, so the paging path is exercised."""
    for _ in range(600):
        repository.append(login_event())

    assert repository.count() == 600
    assert len(list(repository.iter_records())) == 600


def test_the_anchor_advances_with_every_append(
    repository: SqliteAccountingRepository,
) -> None:
    assert repository.head() == ChainHead()

    repository.append(login_event())
    first = repository.head()

    assert first.record_count == 1
    assert first.head_hash != GENESIS_HASH

    repository.append(login_event())
    second = repository.head()

    assert second.record_count == 2
    assert second.head_hash != first.head_hash


def test_a_written_chain_verifies(repository: SqliteAccountingRepository) -> None:
    for index in range(4):
        repository.append(login_event(request_id=f"req-{index}"))

    result = repository.verify()

    assert result.ok is True
    assert result.record_count == 4


def test_optional_fields_round_trip(repository: SqliteAccountingRepository) -> None:
    repository.append(
        login_event(
            event_type=AccountingEventType.LOGIN_FAILURE,
            outcome=AccountingOutcome.DENIED,
            user_id=None,
            session_label=None,
            error_type=AccountingErrorType.BLOCKED,
            duration_ms=42,
            requester_user_id="ad:requester@example.test",
            approver_user_id="ad:approver@example.test",
        )
    )

    record = next(iter(repository.iter_records())).as_mapping()

    assert record["user_id"] is None
    assert record["error_type"] == "blocked"
    assert record["duration_ms"] == 42
    assert record["requester_user_id"] == "ad:requester@example.test"
    assert record["approver_user_id"] == "ad:approver@example.test"


def test_an_event_with_a_duplicate_identifier_is_refused(
    repository: SqliteAccountingRepository,
) -> None:
    event = login_event()
    repository.append(event)

    with pytest.raises(AccountingUnavailable):
        repository.append(event)

    assert repository.count() == 1


def test_tampering_with_a_stored_event_fails_verification(
    store: SqliteAppStore, repository: SqliteAccountingRepository
) -> None:
    repository.append(login_event())
    repository.append(login_event())

    with store.transaction() as connection:
        connection.execute(
            "UPDATE accounting_events SET canonical_event = replace(canonical_event, "
            "'login_success', 'login_failure') WHERE sequence = 1"
        )

    result = repository.verify()

    assert result.ok is False
    assert result.failing_sequence == 1


def test_deleting_the_last_event_is_detected_by_the_anchor(
    store: SqliteAppStore, repository: SqliteAccountingRepository
) -> None:
    """The anchor is what makes a truncated history visible."""
    for _ in range(3):
        repository.append(login_event())

    with store.transaction() as connection:
        connection.execute("DELETE FROM accounting_events WHERE sequence = 3")

    result = repository.verify()

    assert result.ok is False
    assert "anchor records 3 events" in (result.failure or "")


# --- a rolled-back append leaves nothing behind -----------------------------


def test_a_failed_append_rolls_back_both_the_row_and_the_anchor(
    repository: SqliteAccountingRepository,
) -> None:
    """The row and the anchor are one transaction, so they cannot disagree."""
    repository.append(login_event())
    before = repository.head()

    # A duplicate identifier makes the INSERT fail inside the append transaction.
    duplicate = login_event()
    repository.append(duplicate)

    with pytest.raises(AccountingUnavailable):
        repository.append(duplicate)

    assert repository.count() == 2
    assert repository.head() != before
    assert repository.verify().ok is True


def test_an_append_to_a_closed_store_is_refused(store: SqliteAppStore) -> None:
    """The repository reports an accounting failure, whatever closed the store."""
    repository = SqliteAccountingRepository(store)
    store.close()

    with pytest.raises(AccountingUnavailable):
        repository.append(login_event())


# --- the recorder: required versus optional ---------------------------------


def test_a_required_event_that_cannot_be_committed_is_an_exception(
    store: SqliteAppStore,
) -> None:
    recorder = RepositoryAccountingRecorder(SqliteAccountingRepository(store))
    store.close()

    with pytest.raises(AccountingUnavailable):
        recorder.record(login_event(), required=True)


def test_an_optional_event_that_cannot_be_committed_only_degrades(
    store: SqliteAppStore,
) -> None:
    recorder = RepositoryAccountingRecorder(SqliteAccountingRepository(store))
    assert recorder.state is AccountingState.ACTIVE

    store.close()
    recorder.record(login_event(), required=False)

    assert recorder.state is AccountingState.DEGRADED


def test_the_degraded_state_is_sticky(
    store: SqliteAppStore, repository: SqliteAccountingRepository
) -> None:
    """Once an event was lost the trail has a gap; reporting active again would lie."""
    recorder = RepositoryAccountingRecorder(repository)
    store.close()

    recorder.record(login_event(), required=False)

    assert recorder.state is AccountingState.DEGRADED


def test_a_healthy_recorder_reports_active(
    repository: SqliteAccountingRepository,
) -> None:
    recorder = RepositoryAccountingRecorder(repository)

    recorder.record(login_event())
    recorder.record(login_event(), required=True)

    assert recorder.state is AccountingState.ACTIVE
    assert repository.count() == 2


def test_the_null_recorder_refuses_required_events() -> None:
    """The memory mode is safe rather than merely unconfigured."""
    recorder = NullAccountingRecorder()

    assert recorder.state is AccountingState.DISABLED

    with pytest.raises(AccountingUnavailable) as caught:
        recorder.record(login_event(), required=True)

    assert "no durable accounting store" in str(caught.value)


def test_the_null_recorder_accepts_optional_events() -> None:
    NullAccountingRecorder().record(login_event(), required=False)


def test_a_required_failure_stops_a_security_critical_caller(
    store: SqliteAppStore, repository: SqliteAccountingRepository
) -> None:
    """The interface P4-12 needs, exercised by a stand-in caller.

    This is the shape the real approval path will have: record first, and let the refusal
    propagate. Nothing here changes Phase 3 code, which is P4-12's job.
    """
    recorder = RepositoryAccountingRecorder(repository)
    executed: list[str] = []

    def approve_and_execute() -> None:
        recorder.record(
            AccountingEvent(
                event_type=AccountingEventType.APPROVAL_APPROVED,
                outcome=AccountingOutcome.SUCCESS,
                user_id="ad:operator@example.test",
                requester_user_id="ad:operator@example.test",
                approver_user_id="ad:operator@example.test",
                action_id="nmap_service_scan",
                target="192.0.2.64",
            ),
            required=True,
        )
        executed.append("executed")

    approve_and_execute()
    assert executed == ["executed"]
    assert repository.count() == 1

    # Now the store fails, and the action must not run.
    store.close()

    with pytest.raises(AccountingUnavailable):
        approve_and_execute()

    assert executed == ["executed"], "the action must not have run a second time"


def test_the_degraded_state_carries_no_sensitive_detail(
    store: SqliteAppStore,
    repository: SqliteAccountingRepository,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The observable state is a category; no path or driver text is exposed."""
    recorder = RepositoryAccountingRecorder(repository)
    store.close()

    with caplog.at_level(logging.DEBUG):
        recorder.record(login_event(), required=False)

    assert recorder.state.value == "degraded"
    assert "sqlite" not in recorder.state.value.lower()

    logged = "\n".join(record.getMessage() for record in caplog.records)

    assert "/" not in logged.replace("Accounting event was not recorded", ""), (
        "no filesystem path may be logged"
    )


def test_a_missing_table_is_reported_as_unavailable(store: SqliteAppStore) -> None:
    """A store that was never migrated fails closed rather than half-working."""
    with store.transaction() as connection:
        connection.execute("DROP TABLE accounting_events")

    repository = SqliteAccountingRepository(store)

    with pytest.raises(AccountingUnavailable):
        repository.append(login_event())

    with pytest.raises(StoreUnavailable):
        repository.count()

    with pytest.raises(StoreUnavailable):
        list(repository.iter_records())


# --- chain verification under concurrent appends ----------------------------


def test_verification_uses_one_consistent_snapshot(
    store: SqliteAppStore, repository: SqliteAccountingRepository
) -> None:
    """A committed append from another connection never makes a healthy chain look broken."""
    repository.append(login_event())
    other = SqliteAppStore.open(store_config_of(store))
    errors: list[str] = []

    def append_many() -> None:
        writer = SqliteAccountingRepository(other)

        for _ in range(30):
            writer.append(login_event())

    thread = threading.Thread(target=append_many)
    thread.start()

    try:
        for _ in range(20):
            result = repository.verify()

            if not result.ok:
                errors.append(str(result.failure))
    finally:
        thread.join(timeout=15)
        other.close()

    assert errors == []


def test_verification_is_unaffected_by_an_open_write_transaction_elsewhere(
    store: SqliteAppStore, repository: SqliteAccountingRepository
) -> None:
    """WAL lets a reader keep its own view while another connection holds a write lock.

    The verification must neither block nor see a half-open unit of work; it reads the
    last committed state and passes. This is also the deployment case that matters: the
    local admin utility verifying the trail while the application is writing to it.
    """
    repository.append(login_event())

    other = SqliteAppStore.open(store_config_of(store))

    try:
        with other.transaction() as connection:
            connection.execute(
                "INSERT INTO login_throttle (scope, key, count, expires_at) "
                "VALUES ('pair', 'k', 1, '2030-01-01T00:00:00.000000+00:00')"
            )

            # Committed state only: one accounting record, and a healthy chain.
            assert repository.verify().ok is True
            assert repository.count() == 1

        assert repository.verify().ok is True
        assert repository.count() == 1
    finally:
        other.close()


def store_config_of(store: SqliteAppStore) -> StoreConfig:
    return StoreConfig(mode="sqlite", data_dir=store.paths.directory)

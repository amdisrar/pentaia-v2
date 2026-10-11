"""The accounting repository: append, read, and verify.

Business logic depends on the :class:`AccountingRepository` protocol, never on SQLite.
The implementation here is the only place that knows the table shape, which is what keeps
a later database migration a repository change rather than an application change.

Appending is one transaction that writes the event row **and** the chain anchor together.
They can therefore never disagree: either both describe the new head, or neither moved.
"""

import logging
import sqlite3
from collections.abc import Iterator
from typing import Protocol

from pentaia.appstore.accounting import AccountingEvent
from pentaia.appstore.connection import SqliteAppStore
from pentaia.appstore.errors import AccountingUnavailable, StoreUnavailable
from pentaia.appstore.integrity import (
    GENESIS_HASH,
    AccountingRecord,
    ChainHead,
    ChainVerification,
    canonical_bytes,
    chain_hash,
    verify_chain,
)
from pentaia.appstore.timestamps import to_stamp

logger = logging.getLogger(__name__)

#: Column names that carry a canonical event field, and the field each one holds. The two
#: names that differ are mapped explicitly rather than assumed.
_COLUMN_FOR_FIELD: dict[str, str] = {
    "timestamp": "recorded_at",
    "event_id": "event_id",
    "event_type": "event_type",
    "outcome": "outcome",
    "user_id": "user_id",
    "auth_source": "auth_source",
    "session_label": "session_label",
    "conversation_id": "conversation_id",
    "langgraph_thread_id": "langgraph_thread_id",
    "request_id": "request_id",
    "duration_ms": "duration_ms",
    "action_id": "action_id",
    "target": "target",
    "proposal_signature": "proposal_signature",
    "requester_user_id": "requester_user_id",
    "approver_user_id": "approver_user_id",
    "error_type": "error_type",
}

_INSERT_COLUMNS = (
    "event_id",
    "recorded_at",
    "event_type",
    "outcome",
    "user_id",
    "auth_source",
    "session_label",
    "conversation_id",
    "langgraph_thread_id",
    "request_id",
    "duration_ms",
    "action_id",
    "target",
    "proposal_signature",
    "requester_user_id",
    "approver_user_id",
    "error_type",
    "canonical_event",
    "previous_record_hash",
    "record_hash",
)


class AccountingRepository(Protocol):
    """Append-only storage for accounted events."""

    def append(self, event: AccountingEvent) -> int:
        """Persist one event and return its sequence number."""
        ...

    def count(self) -> int:
        """Number of recorded events."""
        ...

    def head(self) -> ChainHead:
        """The stored end of the chain."""
        ...

    def iter_records(
        self, *, after_sequence: int = 0, limit: int | None = None
    ) -> Iterator[AccountingRecord]:
        """Stream records in sequence order."""
        ...

    def verify(self) -> ChainVerification:
        """Verify the whole chain against its anchor."""
        ...


def _fetch(
    connection: sqlite3.Connection, *, after_sequence: int, limit: int
) -> list[tuple[int, AccountingRecord]]:
    """Read one page of records in sequence order."""
    rows = connection.execute(
        "SELECT * FROM accounting_events WHERE sequence > ? ORDER BY sequence ASC LIMIT ?",
        (after_sequence, limit),
    ).fetchall()

    return [
        (
            int(row["sequence"]),
            AccountingRecord(
                sequence=int(row["sequence"]),
                canonical_event=str(row["canonical_event"]),
                previous_record_hash=str(row["previous_record_hash"]),
                record_hash=str(row["record_hash"]),
                columns={
                    field: row[column] for field, column in _COLUMN_FOR_FIELD.items()
                },
            ),
        )
        for row in rows
    ]


def _iter_records(
    connection: sqlite3.Connection, *, after_sequence: int, limit: int | None
) -> Iterator[AccountingRecord]:
    """Stream every record over one caller-owned connection, in pages.

    Used by verification, which passes a snapshot so the whole walk sees one consistent
    view of the table.
    """
    cursor = after_sequence
    remaining = limit
    page = 500

    while True:
        fetch = page if remaining is None else min(page, remaining)

        if fetch <= 0:
            return

        rows = _fetch(connection, after_sequence=cursor, limit=fetch)

        if not rows:
            return

        for sequence, record in rows:
            cursor = sequence

            yield record

        if remaining is not None:
            remaining -= len(rows)

        if len(rows) < fetch:
            return


def _head_from(connection: sqlite3.Connection) -> ChainHead:
    row = connection.execute(
        "SELECT head_hash, record_count FROM accounting_chain_state WHERE id = 1"
    ).fetchone()

    if row is None:
        return ChainHead()

    return ChainHead(
        head_hash=str(row["head_hash"]),
        record_count=int(row["record_count"]),
    )


class SqliteAccountingRepository:
    """SQLite-backed accounting storage over one :class:`SqliteAppStore`."""

    def __init__(self, store: SqliteAppStore) -> None:
        self._store = store

    def append(self, event: AccountingEvent) -> int:
        """Write one event and advance the anchor, in one transaction."""
        record = event.to_record()
        canonical = canonical_bytes(record)
        recorded_at = to_stamp(event.timestamp)

        try:
            with self._store.transaction() as connection:
                row = connection.execute(
                    "SELECT head_hash, record_count FROM accounting_chain_state "
                    "WHERE id = 1"
                ).fetchone()

                previous = GENESIS_HASH if row is None else str(row["head_hash"])
                count = 0 if row is None else int(row["record_count"])
                digest = chain_hash(previous, canonical)

                placeholders = ", ".join("?" for _ in _INSERT_COLUMNS)
                connection.execute(
                    f"INSERT INTO accounting_events ({', '.join(_INSERT_COLUMNS)}) "
                    f"VALUES ({placeholders})",
                    (
                        record["event_id"],
                        recorded_at,
                        record["event_type"],
                        record["outcome"],
                        record["user_id"],
                        record["auth_source"],
                        record["session_label"],
                        record["conversation_id"],
                        record["langgraph_thread_id"],
                        record["request_id"],
                        record["duration_ms"],
                        record["action_id"],
                        record["target"],
                        record["proposal_signature"],
                        record["requester_user_id"],
                        record["approver_user_id"],
                        record["error_type"],
                        canonical.decode("utf-8"),
                        previous,
                        digest,
                    ),
                )

                sequence = int(
                    connection.execute("SELECT last_insert_rowid()").fetchone()[0]
                )

                # The anchor is written in the same transaction as the row it describes,
                # so a crash between the two is impossible.
                connection.execute(
                    """
                    INSERT INTO accounting_chain_state
                        (id, head_hash, record_count, updated_at)
                    VALUES (1, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        head_hash = excluded.head_hash,
                        record_count = excluded.record_count,
                        updated_at = excluded.updated_at
                    """,
                    (digest, count + 1, recorded_at),
                )
        except (sqlite3.Error, StoreUnavailable) as exc:
            # The store already normalises statement failures; either way the caller is
            # told the event is not committed, which is what a required event needs.
            raise AccountingUnavailable(
                "the accounting event could not be committed."
            ) from exc

        return sequence

    def count(self) -> int:
        with self._store.reading() as connection:
            try:
                return int(
                    connection.execute(
                        "SELECT COUNT(*) AS total FROM accounting_events"
                    ).fetchone()["total"]
                )
            except sqlite3.Error as exc:
                raise StoreUnavailable(
                    "the accounting store could not be read."
                ) from exc

    def head(self) -> ChainHead:
        with self._store.reading() as connection:
            return _head_from(connection)

    def iter_records(
        self, *, after_sequence: int = 0, limit: int | None = None
    ) -> Iterator[AccountingRecord]:
        """Stream records in sequence order.

        The rows are read in pages so a long history does not have to be held in memory at
        once, and the lock is released between pages.
        """
        page_size = 500
        remaining = limit
        cursor = after_sequence

        while True:
            fetch = page_size if remaining is None else min(page_size, remaining)

            if fetch <= 0:
                return

            with self._store.reading() as connection:
                rows = _fetch(connection, after_sequence=cursor, limit=fetch)

            if not rows:
                return

            for sequence, record in rows:
                cursor = sequence

                yield record

            if remaining is not None:
                remaining -= len(rows)

            if len(rows) < fetch:
                return

    def verify(self) -> ChainVerification:
        """Verify the stored chain against the stored anchor.

        The records and the anchor are read inside one snapshot. Read separately, a
        concurrent append between the two reads would make a healthy chain look truncated
        or its head look wrong — a false alarm in the one routine whose output is meant to
        be trusted.
        """
        with self._store.snapshot() as connection:
            records = _iter_records(connection, after_sequence=0, limit=None)
            verification = verify_chain(records, head=_head_from(connection))

        return verification

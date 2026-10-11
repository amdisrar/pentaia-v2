"""Canonical serialization and the SHA-256 hash chain.

    record_hash = SHA256(previous_record_hash || canonical_event)

The chain is verified against the **stored canonical bytes**, never against a
re-serialization of the query columns. That is what makes verification independent of
the code that reads it: a field added to the event model in a later version would change
the serialization of new records only, and every record already written keeps the hash it
was given. Recomputing from columns would invalidate the entire history the first time
the model changed.

What the chain establishes, and what it does not — this is stated here so no reader has to
infer it:

===============================================  ==================================
Tampering                                        Detected?
===============================================  ==================================
Editing any field inside a stored event          Yes: the record hash no longer matches
Deleting or reordering a record in the middle    Yes: the chain link and the contiguous
                                                 sequence both break
Inserting a forged record                        Yes: it cannot produce a hash the
                                                 following record links to
Deleting the tail of the history                 Yes, by comparing against the stored
                                                 anchor (count and head hash)
Rewriting the history *and* its local anchor     **No.** Anyone who can write the
                                                 database file can recompute a
                                                 consistent chain
Replacing the whole database with a forgery      **No**, without an external anchor
===============================================  ==================================

So this is integrity verification and tamper *evidence* against partial or casual
modification. It is not tamper-proof storage, and it is not a substitute for an external
anchor or a remote append-only destination, which Phase 4 does not have. The verify
primitive returns the head hash and the record count so an operator can record them
somewhere outside the database; that record is what makes a full rewrite detectable.
"""

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

#: The link value of the first record in a chain: 64 zeroes, so there is no special case
#: in the hashing code and the genesis value is visible in the stored row.
GENESIS_HASH = "0" * 64


def canonical_bytes(record: Mapping[str, object]) -> bytes:
    """Serialize one record deterministically.

    Sorted keys, no insignificant whitespace, UTF-8, non-ASCII preserved. Two records with
    the same fields therefore always produce the same bytes, on any machine and in any
    process, which is the property the chain depends on.
    """
    return json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def chain_hash(previous_record_hash: str, canonical_event: bytes) -> str:
    """Hash one link: the previous record's hash followed by the canonical event."""
    return hashlib.sha256(
        previous_record_hash.encode("ascii") + canonical_event
    ).hexdigest()


@dataclass(frozen=True)
class AccountingRecord:
    """One stored record as read back, with the columns kept separate.

    ``canonical_event`` is the authoritative serialization that was hashed.
    ``columns`` are the queryable column values, used only for the cross-check that a
    column was not edited while the blob was left alone.
    """

    sequence: int
    canonical_event: str
    previous_record_hash: str
    record_hash: str
    columns: Mapping[str, object] = field(default_factory=dict)

    def as_mapping(self) -> Mapping[str, object]:
        """The parsed event, or an empty mapping when the blob is unusable."""
        try:
            parsed = json.loads(self.canonical_event)
        except (TypeError, ValueError):
            return {}

        return parsed if isinstance(parsed, dict) else {}


@dataclass(frozen=True)
class ChainHead:
    """The expected end of the chain, as recorded by the anchor row."""

    head_hash: str = GENESIS_HASH
    record_count: int = 0


@dataclass(frozen=True)
class ChainVerification:
    """The outcome of verifying a chain.

    ``failure`` is a short fixed description and ``failing_sequence`` the row it applies
    to. Neither carries event content: a verification report is safe to print.
    """

    ok: bool
    checked: int
    head_hash: str
    record_count: int
    failure: str | None = None
    failing_sequence: int | None = None

    def describe(self) -> str:
        """A one-line summary suitable for the operator or the admin utility."""
        if self.ok:
            return (
                f"accounting chain verified: {self.record_count} records, "
                f"head {self.head_hash}"
            )

        return (
            f"accounting chain FAILED at sequence {self.failing_sequence}: {self.failure} "
            f"({self.checked} records checked)"
        )


def _fail(
    checked: int,
    head_hash: str,
    failure: str,
    sequence: int | None,
) -> ChainVerification:
    return ChainVerification(
        ok=False,
        checked=checked,
        head_hash=head_hash,
        record_count=checked,
        failure=failure,
        failing_sequence=sequence,
    )


def verify_chain(
    records: Iterable[AccountingRecord],
    *,
    head: ChainHead | None = None,
) -> ChainVerification:
    """Walk a chain and report the first inconsistency.

    Checks, in order, per record: the expected sequence number, that the blob parses,
    that every field the blob and the columns share agree, that the link to the previous
    hash is intact, and that the record hash recomputes **from the stored bytes**. After
    the walk the final head and count are compared with ``head`` when one is supplied.

    The hash is taken over ``canonical_event`` exactly as stored, never over a
    re-serialization of the parsed JSON. Re-serializing would silently normalise a
    byte-level edit: adding whitespace, reordering the keys, or changing a number's
    spelling would all produce the same bytes again and verify as intact. Parsing happens
    separately, only for the semantic and column checks.
    """
    expected_previous = GENESIS_HASH
    expected_sequence = 1
    checked = 0

    for record in records:
        if record.sequence != expected_sequence:
            # A gap means a record was removed, or one was inserted out of order.
            return _fail(
                checked,
                expected_previous,
                f"expected sequence {expected_sequence} but found {record.sequence}; a "
                "record is missing or out of order",
                record.sequence,
            )

        parsed = record.as_mapping()

        if not parsed:
            return _fail(
                checked,
                expected_previous,
                "the stored canonical event is not a JSON object",
                record.sequence,
            )

        # Every field the blob and the columns share must agree. Fields the blob does not
        # contain are skipped: a column added by a later schema version is not part of an
        # older record's hash, and pretending otherwise would break old history.
        for key, column_value in record.columns.items():
            if key not in parsed:
                continue

            if parsed[key] != column_value:
                return _fail(
                    checked,
                    expected_previous,
                    f"column {key!r} does not match the hashed event",
                    record.sequence,
                )

        if record.previous_record_hash != expected_previous:
            return _fail(
                checked,
                expected_previous,
                "the link to the previous record does not match",
                record.sequence,
            )

        recomputed = chain_hash(
            record.previous_record_hash,
            record.canonical_event.encode("utf-8"),
        )

        if recomputed != record.record_hash:
            return _fail(
                checked,
                expected_previous,
                "the record hash does not match its content",
                record.sequence,
            )

        expected_previous = record.record_hash
        expected_sequence += 1
        checked += 1

    if head is not None:
        if checked != head.record_count:
            return _fail(
                checked,
                expected_previous,
                f"the stored anchor records {head.record_count} events but the chain "
                f"holds {checked}; records were added or removed",
                None,
            )

        if expected_previous != head.head_hash:
            return _fail(
                checked,
                expected_previous,
                "the head hash does not match the stored anchor",
                None,
            )

    return ChainVerification(
        ok=True,
        checked=checked,
        head_hash=expected_previous,
        record_count=checked,
    )

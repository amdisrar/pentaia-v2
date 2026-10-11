"""Hash-chain serialization, verification, and the limits of what it can detect.

The tests are written in two halves on purpose. The first asserts that modification,
deletion, reordering, insertion and tail truncation are detected. The second asserts what
is *not* detected — a consistent rewrite of the history together with its local anchor —
because a security control whose limits are only described in prose is a control nobody
has checked.
"""

import hashlib
import json
from collections.abc import Mapping

import pytest

from pentaia.appstore.integrity import (
    GENESIS_HASH,
    AccountingRecord,
    ChainHead,
    canonical_bytes,
    chain_hash,
    verify_chain,
)

EVENT_COLUMNS = ("event_id", "event_type", "outcome", "user_id")


def sample(index: int, **overrides: object) -> dict[str, object]:
    record = {
        "event_id": f"{index:032x}",
        "timestamp": "2026-10-10T22:11:41.123456+00:00",
        "event_type": "login_success",
        "outcome": "success",
        "user_id": "ad:user@example.test",
        "auth_source": "ad",
        "session_label": "sess-0123456789abcdef",
        "conversation_id": None,
        "langgraph_thread_id": None,
        "request_id": None,
        "duration_ms": None,
        "action_id": None,
        "target": None,
        "proposal_signature": None,
        "requester_user_id": None,
        "approver_user_id": None,
        "error_type": None,
    }
    record.update(overrides)

    return record


def build_chain(events: list[Mapping[str, object]]):
    """Build a valid chain, optionally tampering as instructed by the event list."""
    records: list[AccountingRecord] = []
    previous = GENESIS_HASH

    for index, event in enumerate(events, start=1):
        canonical = canonical_bytes(event)
        digest = chain_hash(previous, canonical)

        records.append(
            AccountingRecord(
                sequence=index,
                canonical_event=canonical.decode("utf-8"),
                previous_record_hash=previous,
                record_hash=digest,
                columns={key: event[key] for key in EVENT_COLUMNS if key in event},
            )
        )
        previous = digest

    return records


def head_of(records: list[AccountingRecord]) -> ChainHead:
    if not records:
        return ChainHead()

    return ChainHead(head_hash=records[-1].record_hash, record_count=len(records))


# --- canonical serialization ------------------------------------------------


def test_canonical_bytes_ignore_key_order() -> None:
    forward = {"b": 1, "a": 2}
    backward = {"a": 2, "b": 1}

    assert canonical_bytes(forward) == canonical_bytes(backward)
    assert canonical_bytes(forward) == b'{"a":2,"b":1}'


def test_canonical_bytes_keep_non_ascii_readable() -> None:
    assert b"caf\xc3\xa9" in canonical_bytes({"note": "caf\u00e9"})


def test_the_hash_uses_the_documented_formula() -> None:
    record = sample(1)
    canonical = canonical_bytes(record)
    expected = hashlib.sha256(GENESIS_HASH.encode("ascii") + canonical).hexdigest()

    assert chain_hash(GENESIS_HASH, canonical) == expected
    assert len(expected) == 64


# --- a clean chain ----------------------------------------------------------


def test_a_clean_chain_verifies() -> None:
    records = build_chain([sample(1), sample(2), sample(3)])

    result = verify_chain(records, head=head_of(records))

    assert result.ok is True
    assert result.checked == 3
    assert result.record_count == 3
    assert result.head_hash == records[-1].record_hash
    assert result.failure is None


def test_an_empty_chain_verifies_at_genesis() -> None:
    result = verify_chain([], head=ChainHead())

    assert result.ok is True
    assert result.checked == 0
    assert result.head_hash == GENESIS_HASH


def test_verification_without_an_anchor_still_checks_the_links() -> None:
    records = build_chain([sample(1), sample(2)])

    assert verify_chain(records).ok is True


# --- what is detected -------------------------------------------------------


def test_editing_a_stored_field_is_detected() -> None:
    records = build_chain([sample(1), sample(2), sample(3)])
    tampered = json.loads(records[1].canonical_event)
    tampered["outcome"] = "denied"
    records[1] = AccountingRecord(
        sequence=2,
        canonical_event=json.dumps(tampered),
        previous_record_hash=records[1].previous_record_hash,
        record_hash=records[1].record_hash,
        # The column is edited too, so the cross-check passes and the hash is what
        # catches the change.
        columns={**records[1].columns, "outcome": "denied"},
    )

    result = verify_chain(records, head=head_of(records))

    assert result.ok is False
    assert result.failing_sequence == 2
    assert "hash does not match" in (result.failure or "")


def test_editing_a_column_without_the_blob_is_detected() -> None:
    """The columns are not hashed, so they are cross-checked against the blob instead."""
    records = build_chain([sample(1), sample(2)])
    records[0] = AccountingRecord(
        sequence=1,
        canonical_event=records[0].canonical_event,
        previous_record_hash=records[0].previous_record_hash,
        record_hash=records[0].record_hash,
        columns={**records[0].columns, "outcome": "denied"},
    )

    result = verify_chain(records)

    assert result.ok is False
    assert result.failing_sequence == 1
    assert "column 'outcome'" in (result.failure or "")


def test_a_column_the_blob_does_not_contain_is_not_a_failure() -> None:
    """A column added by a later schema version is absent from older hashed events."""
    records = build_chain([sample(1)])
    records[0] = AccountingRecord(
        sequence=1,
        canonical_event=records[0].canonical_event,
        previous_record_hash=records[0].previous_record_hash,
        record_hash=records[0].record_hash,
        columns={**records[0].columns, "future_field": "added later"},
    )

    assert verify_chain(records).ok is True


def test_a_broken_link_is_detected() -> None:
    records = build_chain([sample(1), sample(2)])
    records[1] = AccountingRecord(
        sequence=2,
        canonical_event=records[1].canonical_event,
        previous_record_hash=GENESIS_HASH,
        record_hash=records[1].record_hash,
        columns=records[1].columns,
    )

    result = verify_chain(records)

    assert result.ok is False
    assert "link to the previous record" in (result.failure or "")


def test_a_wrong_record_hash_is_detected() -> None:
    records = build_chain([sample(1), sample(2)])
    records[1] = AccountingRecord(
        sequence=2,
        canonical_event=records[1].canonical_event,
        previous_record_hash=records[1].previous_record_hash,
        record_hash="f" * 64,
        columns=records[1].columns,
    )

    result = verify_chain(records)

    assert result.ok is False
    assert result.failing_sequence == 2


def test_deleting_a_middle_record_is_detected() -> None:
    records = build_chain([sample(1), sample(2), sample(3)])
    del records[1]  # sequences become 1, 3

    result = verify_chain(records)

    assert result.ok is False
    assert result.failing_sequence == 3
    assert "missing or out of order" in (result.failure or "")


def test_reordering_records_is_detected() -> None:
    records = build_chain([sample(1), sample(2), sample(3)])
    records[1], records[2] = records[2], records[1]

    result = verify_chain(records)

    assert result.ok is False
    assert result.failing_sequence == 3


def test_inserting_a_forged_record_is_detected() -> None:
    """A forgery cannot produce a hash that the genuine record after it links to."""
    records = build_chain([sample(1), sample(2)])
    forged_event = sample(99, outcome="denied")
    forged = AccountingRecord(
        sequence=2,
        canonical_event=canonical_bytes(forged_event).decode(),
        previous_record_hash=records[0].record_hash,
        record_hash=chain_hash(records[0].record_hash, canonical_bytes(forged_event)),
        columns={"event_id": forged_event["event_id"], "outcome": "denied"},
    )
    genuine_second = AccountingRecord(
        sequence=3,
        canonical_event=records[1].canonical_event,
        previous_record_hash=records[1].previous_record_hash,
        record_hash=records[1].record_hash,
        columns=records[1].columns,
    )
    records = [records[0], forged, genuine_second]

    result = verify_chain(records)

    assert result.ok is False
    assert result.failing_sequence == 3
    assert "link to the previous record" in (result.failure or "")


def test_truncating_the_tail_is_detected_by_the_anchor() -> None:
    records = build_chain([sample(1), sample(2), sample(3)])
    head = head_of(records)
    truncated = records[:2]

    result = verify_chain(truncated, head=head)

    assert result.ok is False
    assert result.record_count == 2
    assert "anchor records 3 events but the chain holds 2" in (result.failure or "")


def test_a_rewritten_anchor_head_is_detected() -> None:
    records = build_chain([sample(1), sample(2)])

    result = verify_chain(
        records, head=ChainHead(head_hash="a" * 64, record_count=2)
    )

    assert result.ok is False
    assert "head hash does not match" in (result.failure or "")


@pytest.mark.parametrize(
    "blob",
    ["not json at all", "[]", '"a string"', "null", "123"],
)
def test_an_unusable_canonical_blob_is_detected(blob: str) -> None:
    record = AccountingRecord(
        sequence=1,
        canonical_event=blob,
        previous_record_hash=GENESIS_HASH,
        record_hash="a" * 64,
        columns={},
    )

    result = verify_chain([record])

    assert result.ok is False
    assert "not a JSON object" in (result.failure or "")


def test_verification_reports_are_safe_to_print() -> None:
    """A report names the sequence and the kind of failure, never the event content."""
    records = build_chain([sample(1, user_id="ad:secret-looking@example.test")])
    tampered = json.loads(records[0].canonical_event)
    tampered["user_id"] = "ad:attacker@example.test"
    records[0] = AccountingRecord(
        sequence=1,
        canonical_event=json.dumps(tampered),
        previous_record_hash=GENESIS_HASH,
        record_hash=records[0].record_hash,
        columns=records[0].columns,
    )

    described = verify_chain(records).describe()

    assert "FAILED at sequence 1" in described
    assert "attacker" not in described
    assert "secret-looking" not in described


def test_the_success_report_names_the_head_and_count() -> None:
    records = build_chain([sample(1), sample(2)])

    described = verify_chain(records, head=head_of(records)).describe()

    assert "verified: 2 records" in described
    assert records[-1].record_hash in described


# --- the documented limits --------------------------------------------------


def test_a_consistent_rewrite_of_the_whole_chain_is_not_detected() -> None:
    """The stated limitation, pinned rather than assumed.

    An attacker who can write the database file can recompute every hash and the anchor
    that accompanies it. Detecting this needs the head hash to have been recorded
    somewhere the attacker does not control, which is why the verify primitive prints it.
    """
    genuine = build_chain([sample(1), sample(2)])

    rewritten = build_chain([sample(1, outcome="denied"), sample(2, outcome="denied")])

    assert verify_chain(rewritten, head=head_of(rewritten)).ok is True
    assert verify_chain(rewritten, head=head_of(genuine)).ok is False, (
        "an externally recorded anchor is what makes the rewrite visible"
    )


# --- the chain hashes the stored bytes, not a re-serialization --------------


def test_a_whitespace_only_edit_of_the_stored_json_is_detected() -> None:
    """The change is semantically invisible, so only a byte-level check catches it."""
    records = build_chain([sample(1)])
    original_text = records[0].canonical_event
    edited_text = original_text.replace('"outcome":"success"', '"outcome": "success"')

    assert edited_text != original_text
    assert json.loads(edited_text) == json.loads(original_text)

    tampered = AccountingRecord(
        sequence=1,
        canonical_event=edited_text,
        previous_record_hash=records[0].previous_record_hash,
        record_hash=records[0].record_hash,
        columns=records[0].columns,
    )

    result = verify_chain([tampered])

    assert result.ok is False
    assert "hash does not match" in (result.failure or "")


def test_a_field_order_only_edit_of_the_stored_json_is_detected() -> None:
    """Same keys, same values, different order: the stored bytes are what is hashed."""
    records = build_chain([sample(1)])
    parsed = json.loads(records[0].canonical_event)
    reordered = "{" + ",".join(
        f"{json.dumps(key)}:{json.dumps(value)}"
        for key, value in reversed(list(parsed.items()))
    ) + "}"

    assert reordered != records[0].canonical_event
    assert json.loads(reordered) == parsed

    tampered = AccountingRecord(
        sequence=1,
        canonical_event=reordered,
        previous_record_hash=records[0].previous_record_hash,
        record_hash=records[0].record_hash,
        columns=records[0].columns,
    )

    result = verify_chain([tampered])

    assert result.ok is False
    assert "hash does not match" in (result.failure or "")


def test_a_record_written_by_the_application_verifies_byte_for_byte() -> None:
    """The byte-level rule must not reject what the application itself writes."""
    records = build_chain([sample(1), sample(2)])

    assert all(
        record.canonical_event == canonical_bytes(json.loads(record.canonical_event)).decode()
        for record in records
    )
    assert verify_chain(records, head=head_of(records)).ok is True

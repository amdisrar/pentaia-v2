"""One timestamp representation for everything the store persists.

Every stored instant is a UTC ISO-8601 string with **microsecond** precision and an
explicit offset, for example ``2026-10-10T22:11:41.123456+00:00``. One representation
means:

* comparisons are plain string comparisons, which is why SQLite can order and index
  deadlines directly;
* precision is fixed, so a deadline round-trips through the database unchanged and an
  expiry boundary cannot move by a rounding step;
* the zone is explicit rather than implied, so a naive value is a bug that raises here
  instead of silently being interpreted as local time.

Ordering of *events* does not rely on this at all: ``accounting_events.sequence`` is the
authoritative order, because two events can legitimately share a microsecond. Timestamps
are for deadlines and for human reading.
"""

from datetime import UTC, datetime

#: Fixed precision. Changing this would change the stored form of every new value, so it
#: is named rather than inlined.
STAMP_PRECISION = "microseconds"


def _as_utc(value: object, *, field: str) -> datetime:
    """Accept a timezone-aware datetime and normalise it to UTC.

    A wrong type is a programming error (``TypeError``); a naive value is unusable input
    (``ValueError``), matching the convention in ``pentaia/webapp/sessions.py``.
    """
    if not isinstance(value, datetime):
        raise TypeError(f"{field} must be a datetime.")

    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field} must be timezone-aware.")

    return value.astimezone(UTC)


def to_stamp(value: object, *, field: str = "timestamp") -> str:
    """Render one instant in the stored representation."""
    return _as_utc(value, field=field).isoformat(timespec=STAMP_PRECISION)


def from_stamp(value: object, *, field: str = "timestamp") -> datetime:
    """Parse one stored instant, always returning an aware UTC datetime."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a stored timestamp string.")

    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(f"{field} is not a valid stored timestamp.") from None

    return _as_utc(parsed, field=field)

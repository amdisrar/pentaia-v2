"""Typed accounting events and their whitelist serialization.

Redaction here is **structural, not filtering**. The emitter accepts an
:class:`AccountingEvent` and :meth:`AccountingEvent.to_record` writes out an explicit,
closed set of fields. Nothing else can get in:

* there is no free-form payload, no ``**kwargs``, no arbitrary mapping and no
  ``dataclasses.asdict`` — a field added to the dataclass does not silently start being
  persisted, because each field is named individually below;
* `error_type` is a closed enum, not an exception string, so an arbitrary exception
  message cannot become an audit record;
* every text field has a **grammar** as well as a length bound and a control-character
  rejection, so a value that is not shaped like the field it claims to be is refused: a
  user identifier must look like ``provider:username``, a session label like
  ``sess-<16 hex>``, a proposal signature like 64 hex characters, and so on;
* there is deliberately no ``safe_detail`` field. The architecture lists one, but any
  free-form string field is a channel a credential can be pushed through, and no amount
  of value inspection can tell a password from a legitimate note. Correlation that a
  later issue actually needs is added as a typed field, under review.

There is one honest limit, and the tests pin it rather than pretend otherwise: a value
that *is* grammatically valid for its field is stored — a password that happens to look
like a hostname is indistinguishable from a hostname. The model therefore refuses
anything it can recognise as the wrong shape, and **emitter discipline is the remaining
control**: ``test_webapp_accounting_events`` asserts that the events the application
actually emits never carry a credential.

A test walks ``dataclasses.fields(AccountingEvent)`` against :data:`PERSISTED_FIELDS`, so
adding a field fails the suite until it is either persisted deliberately or excluded
deliberately.
"""

import enum
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from pentaia.appstore.timestamps import to_stamp

#: Longest text value any single field may hold. Deliberately small: this is a record of
#: what happened, not a place to store documents.
MAX_TEXT_LENGTH = 256

#: Longest accepted duration (seven days). A larger value indicates a bug rather than a
#: long operation.
MAX_DURATION_MS = 7 * 24 * 60 * 60 * 1000

#: Field names a record may contain. Pinned so a serialized record cannot grow a key by
#: accident; ``test_appstore_accounting`` asserts it equals the dataclass field set.
PERSISTED_FIELDS = frozenset(
    {
        "event_id",
        "timestamp",
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
    }
)

#: Fields that exist on the object but are never serialized. Empty on purpose: if a future
#: field is genuinely transient it is listed here, with a reason, rather than silently
#: left out of ``to_record``.
NOT_PERSISTED_FIELDS: frozenset[str] = frozenset()


class AccountingEventCategory(enum.Enum):
    """Top-level grouping, mirroring the architecture's four accounting areas."""

    AUTHENTICATION = "authentication"
    CONVERSATION = "conversation"
    SECURITY_WORKFLOW = "security_workflow"
    ADMINISTRATION = "administration"


class AccountingEventType(enum.Enum):
    """Every event type Phase 4 defines.

    The set is complete now so the schema and the query surface do not churn later. Only
    the authentication and session members are emitted by P4-09; conversation events
    arrive with P4-11, security-workflow events with P4-12 and later, and administration
    events with P4-14/P4-15.
    """

    # Authentication and sessions (emitted by P4-09).
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    WEB_SESSION_CREATED = "web_session_created"
    WEB_SESSION_EXPIRED = "web_session_expired"
    WEB_SESSION_REVOKED = "web_session_revoked"

    # Conversations (P4-11).
    CONVERSATION_CREATED = "conversation_created"
    CONVERSATION_OPENED = "conversation_opened"
    PROMPT_SUBMITTED = "prompt_submitted"
    CONVERSATION_CLOSED = "conversation_closed"

    # Security workflow (P4-12 and later).
    TOOL_REQUESTED = "tool_requested"
    TOOL_COMPLETED = "tool_completed"
    PROPOSAL_CREATED = "proposal_created"
    APPROVAL_APPROVED = "approval_approved"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_STALE = "approval_stale"
    VALIDATION_STARTED = "validation_started"
    VALIDATION_COMPLETED = "validation_completed"
    SESSION_HELD = "session_held"
    SESSION_HANDOFF = "session_handoff"
    SESSION_CLOSED = "session_closed"

    # Administration (P4-14/P4-15).
    AUTH_PROVIDER_STATUS_CHECK = "auth_provider_status_check"
    BREAK_GLASS_USED = "break_glass_used"
    RECOVERY_ACTION = "recovery_action"
    OPERATIONAL_SETTING_CHANGED = "operational_setting_changed"

    @property
    def category(self) -> AccountingEventCategory:
        """The accounting area this event belongs to."""
        return _EVENT_CATEGORIES[self]


_EVENT_CATEGORIES: dict[AccountingEventType, AccountingEventCategory] = {
    **dict.fromkeys(
        (
            AccountingEventType.LOGIN_SUCCESS,
            AccountingEventType.LOGIN_FAILURE,
            AccountingEventType.LOGOUT,
            AccountingEventType.WEB_SESSION_CREATED,
            AccountingEventType.WEB_SESSION_EXPIRED,
            AccountingEventType.WEB_SESSION_REVOKED,
        ),
        AccountingEventCategory.AUTHENTICATION,
    ),
    **dict.fromkeys(
        (
            AccountingEventType.CONVERSATION_CREATED,
            AccountingEventType.CONVERSATION_OPENED,
            AccountingEventType.PROMPT_SUBMITTED,
            AccountingEventType.CONVERSATION_CLOSED,
        ),
        AccountingEventCategory.CONVERSATION,
    ),
    **dict.fromkeys(
        (
            AccountingEventType.TOOL_REQUESTED,
            AccountingEventType.TOOL_COMPLETED,
            AccountingEventType.PROPOSAL_CREATED,
            AccountingEventType.APPROVAL_APPROVED,
            AccountingEventType.APPROVAL_REJECTED,
            AccountingEventType.APPROVAL_STALE,
            AccountingEventType.VALIDATION_STARTED,
            AccountingEventType.VALIDATION_COMPLETED,
            AccountingEventType.SESSION_HELD,
            AccountingEventType.SESSION_HANDOFF,
            AccountingEventType.SESSION_CLOSED,
        ),
        AccountingEventCategory.SECURITY_WORKFLOW,
    ),
    **dict.fromkeys(
        (
            AccountingEventType.AUTH_PROVIDER_STATUS_CHECK,
            AccountingEventType.BREAK_GLASS_USED,
            AccountingEventType.RECOVERY_ACTION,
            AccountingEventType.OPERATIONAL_SETTING_CHANGED,
        ),
        AccountingEventCategory.ADMINISTRATION,
    ),
}


class AccountingOutcome(enum.Enum):
    """How the recorded operation ended."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    ERROR = "error"
    CANCELLED = "cancelled"
    NOT_APPLICABLE = "not_applicable"


class AccountingErrorType(enum.Enum):
    """Closed set of error categories.

    A category, never a message: an exception's text can contain a hostname, a
    distinguished name, a submitted value or a path, and none of those belong in an audit
    record. The categories mirror the ones Phase 3 already classifies failures into, plus
    the store's own refusal.
    """
    BLOCKED = "blocked"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    CONFLICT = "conflict"
    EXECUTION = "execution"
    MALFORMED = "malformed"
    REFUSED = "refused"
    INTERNAL = "internal"


#: The provider tokens Phase 4 defines. A closed set rather than a pattern: the
#: architecture fixes exactly these, and a membership check is what stops an arbitrary
#: string being recorded as where an identity came from. ``pentaia/webapp/config.py``
#: owns the same list for configuration; a webapp-level test asserts the two agree, so
#: adding a provider cannot leave the accounting model behind.
ALLOWED_AUTH_SOURCES = ("ad", "radius")

#: Grammar for the opaque correlation tokens the application generates.
_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

#: Grammar for a Phase 3 target: an address, a CIDR block or a host name.
_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9.:\[\]/_-]{1,64}$")

#: Per-field grammars. These mirror the shapes the application already produces rather
#: than importing them, because the store must not depend on the web layer: canonical
#: user ids come from ``pentaia/webapp/identity.py``, session labels from
#: ``pentaia/webapp/sessions.py`` and proposal signatures from
#: ``pentaia/approval.py``. A value that does not match its field's grammar is refused
#: instead of stored, which is what stops a cookie value being recorded as a user id.
_FIELD_PATTERNS: dict[str, re.Pattern[str]] = {
    # "<auth_source>:<normalized-username>"
    "user_id": re.compile(r"^[a-z][a-z0-9_-]{0,31}:[^\s:]{1,256}$"),
    "requester_user_id": re.compile(r"^[a-z][a-z0-9_-]{0,31}:[^\s:]{1,256}$"),
    "approver_user_id": re.compile(r"^[a-z][a-z0-9_-]{0,31}:[^\s:]{1,256}$"),
    "auth_source": re.compile(r"^[a-z][a-z0-9_-]{0,31}$"),
    "session_label": re.compile(r"^sess-[0-9a-f]{16}$"),
    "conversation_id": _TOKEN_PATTERN,
    "langgraph_thread_id": _TOKEN_PATTERN,
    "request_id": _TOKEN_PATTERN,
    "action_id": _TOKEN_PATTERN,
    "target": _TARGET_PATTERN,
    "proposal_signature": re.compile(r"^[0-9a-f]{64}$"),
}


#: Fields whose value must be one of a fixed set rather than merely well shaped.
_ALLOWED_VALUES: dict[str, frozenset[str]] = {
    "auth_source": frozenset(ALLOWED_AUTH_SOURCES),
}


def _require(condition: bool, message: str) -> None:
    """Refuse one invalid field.

    A single exception type for every rejection: a caller of this model is either
    application code assembling an event (where a wrong type is a bug) or a validator
    (where a wrong value is bad input), and both are reported as ``ValueError``, matching
    the convention the rest of the codebase uses for validated values.
    """
    if not condition:
        raise ValueError(message)


def _clean_text(value: object, *, field_name: str) -> str | None:
    """Validate one optional text field against its length, characters and grammar."""
    if value is None:
        return None

    _require(isinstance(value, str), f"{field_name} must be a string when provided.")

    if not isinstance(value, str):  # pragma: no cover - guarded above
        return None

    candidate = value.strip()

    if not candidate:
        return None

    if len(candidate) > MAX_TEXT_LENGTH:
        raise ValueError(f"{field_name} must be at most {MAX_TEXT_LENGTH} characters.")

    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in candidate):
        raise ValueError(f"{field_name} must not contain control characters.")

    allowed = _ALLOWED_VALUES.get(field_name)

    if allowed is not None and candidate not in allowed:
        raise ValueError(f"{field_name} must be one of: {', '.join(sorted(allowed))}.")

    pattern = _FIELD_PATTERNS.get(field_name)

    if pattern is not None and pattern.match(candidate) is None:
        raise ValueError(f"{field_name} is not a valid value for that field.")

    return candidate


@dataclass(frozen=True)
class AccountingEvent:
    """One accounted event.

    Constructed typed rather than from a dictionary, so a caller cannot introduce a field
    the schema does not define. The identity fields are optional because not every event
    has an actor: a login failure for an unknown username has no ``user_id``.
    """

    event_type: AccountingEventType
    outcome: AccountingOutcome
    user_id: str | None = None
    auth_source: str | None = None
    session_label: str | None = None
    conversation_id: str | None = None
    langgraph_thread_id: str | None = None
    request_id: str | None = None
    duration_ms: int | None = None
    action_id: str | None = None
    target: str | None = None
    proposal_signature: str | None = None
    #: Kept separate from ``user_id`` even in the single-operator Phase 4 model, so a
    #: future two-person approval rule needs no schema change (architecture §14.4).
    requester_user_id: str | None = None
    approver_user_id: str | None = None
    error_type: AccountingErrorType | None = None
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        _require(
            isinstance(self.event_type, AccountingEventType),
            "event_type must be an AccountingEventType.",
        )
        _require(
            isinstance(self.outcome, AccountingOutcome),
            "outcome must be an AccountingOutcome.",
        )

        if self.error_type is not None and not isinstance(
            self.error_type, AccountingErrorType
        ):
            raise ValueError("error_type must be an AccountingErrorType.")

        _require(
            isinstance(self.event_id, str) and len(self.event_id) == 32,
            "event_id must be a 32-character identifier.",
        )

        for name in (
            "user_id",
            "auth_source",
            "session_label",
            "conversation_id",
            "langgraph_thread_id",
            "request_id",
            "action_id",
            "target",
            "proposal_signature",
            "requester_user_id",
            "approver_user_id",
        ):
            object.__setattr__(
                self, name, _clean_text(getattr(self, name), field_name=name)
            )

        if self.duration_ms is not None:
            _require(
                isinstance(self.duration_ms, int)
                and not isinstance(self.duration_ms, bool),
                "duration_ms must be a whole number of milliseconds.",
            )
            _require(
                0 <= self.duration_ms <= MAX_DURATION_MS,
                f"duration_ms must be between 0 and {MAX_DURATION_MS}.",
            )

        # Normalise once, here, so every reader and the stored form agree.
        _require(
            isinstance(self.timestamp, datetime),
            "timestamp must be a datetime.",
        )
        _require(
            self.timestamp.tzinfo is not None
            and self.timestamp.utcoffset() is not None,
            "timestamp must be timezone-aware.",
        )

        object.__setattr__(self, "timestamp", self.timestamp.astimezone(UTC))

    @property
    def category(self) -> AccountingEventCategory:
        return self.event_type.category

    def to_record(self) -> dict[str, object]:
        """The exact fields that may be persisted, one line per field.

        Absent values are written as ``None`` rather than omitted, so the serialized shape
        is identical for every event of a given version. That is what keeps the hash of a
        record reproducible.
        """
        return {
            "event_id": self.event_id,
            "timestamp": to_stamp(self.timestamp),
            "event_type": self.event_type.value,
            "outcome": self.outcome.value,
            "user_id": self.user_id,
            "auth_source": self.auth_source,
            "session_label": self.session_label,
            "conversation_id": self.conversation_id,
            "langgraph_thread_id": self.langgraph_thread_id,
            "request_id": self.request_id,
            "duration_ms": self.duration_ms,
            "action_id": self.action_id,
            "target": self.target,
            "proposal_signature": self.proposal_signature,
            "requester_user_id": self.requester_user_id,
            "approver_user_id": self.approver_user_id,
            "error_type": None if self.error_type is None else self.error_type.value,
        }

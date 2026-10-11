"""The login flow: throttling, the provider call, and session issuance.

This is the application's authentication decision, expressed without any HTTP type, so
the route above it stays a thin adapter and so P4-09 can attach typed accounting events
where the outcome is produced without changing the HTTP contract.

Order matters and is deliberate:

1. **Throttle first.** A locked-out pair never reaches the directory, so a blocked
   attempt cannot be used to hammer AD or to measure its response time.
2. **Then the provider.** The selected provider is the only thing consulted; there is no
   fallback, and a provider that fails is never replaced by another mechanism. Admission
   happens in a single atomic step, so concurrent attempts share one allowance rather
   than each seeing an empty history.
3. **Session only on success.** No failure path creates, touches or invalidates a
   session, so a wrong password never disturbs a session the caller already holds.
4. **Rotation on success.** Whatever session the presented cookie pointed to is
   destroyed before a new identifier and a new CSRF token are issued, which is what
   makes session fixation impossible even for a client that already holds a session.

Nothing here logs a password, a session identifier or a CSRF token, and the raw username
never leaves this function except as the digest used for throttling — the identity that
reaches the session record is the provider's normalised one.
"""

import enum
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from pentaia.appstore.accounting import (
    AccountingErrorType,
    AccountingEvent,
    AccountingEventType,
    AccountingOutcome,
)
from pentaia.appstore.errors import StoreError
from pentaia.appstore.recorder import AccountingRecorder
from pentaia.webapp.auth.base import AuthOutcome, AuthProvider
from pentaia.webapp.auth.throttle import LoginThrottle, throttling_username_key
from pentaia.webapp.identity import AuthenticatedIdentity
from pentaia.webapp.sessions import IssuedSession, SessionStore

logger = logging.getLogger(__name__)


class LoginOutcome(enum.Enum):
    """Why a login attempt ended the way it did.

    The route collapses these into three client-visible answers; the distinction is kept
    here because it is what accounting (P4-09) and the operator's log need.
    """

    #: The credentials were proven and a session was issued.
    SUCCESS = "success"
    #: The credentials were refused. Indistinguishable from an unknown username.
    REJECTED = "rejected"
    #: The provider could not be reached, or did not answer in time.
    UNAVAILABLE = "unavailable"
    #: The application's own provider configuration is wrong or unsafe.
    MISCONFIGURED = "misconfigured"
    #: The attempt was refused before any provider call because of the failure rate.
    THROTTLED = "throttled"
    #: No authentication provider is configured for this deployment.
    PROVIDER_NOT_CONFIGURED = "provider_not_configured"


#: Provider outcomes that map onto a login outcome. Anything not listed fails closed.
_FAILURE_OUTCOMES = {
    AuthOutcome.REJECTED: LoginOutcome.REJECTED,
    AuthOutcome.UNAVAILABLE: LoginOutcome.UNAVAILABLE,
    AuthOutcome.MISCONFIGURED: LoginOutcome.MISCONFIGURED,
}

#: Longest password that can be a credential this application verifies. A larger value
#: is refused locally so an oversized submission cannot be used to make the application
#: or the directory do work.
MAX_PASSWORD_LENGTH = 1024

#: How each outcome is recorded. The accounting outcome is coarser than the login outcome
#: on purpose: an outage and a refusal are worth distinguishing in the log and here, but
#: an audit reader needs "denied" versus "error", not the provider's own vocabulary.
#:
#: The mapping is **total**: every member of :class:`LoginOutcome` appears here, and
#: ``test_every_login_outcome_has_a_recorded_mapping`` fails if one is added without a
#: deliberate decision. That test is not decoration — a missing entry does not raise, it
#: silently falls through to the "error/internal" default, which is how a successful login
#: would be recorded as an error.
#:
#: The error type separates the three ways an attempt can end badly: a refusal
#: (``denied``), an identity source that could not be reached (``unavailable``), and a
#: fault in this deployment's own configuration or setup (``internal``).
_RECORDED_OUTCOMES: dict[LoginOutcome, tuple[AccountingOutcome, AccountingErrorType | None]] = {
    LoginOutcome.SUCCESS: (AccountingOutcome.SUCCESS, None),
    LoginOutcome.REJECTED: (AccountingOutcome.DENIED, None),
    LoginOutcome.THROTTLED: (AccountingOutcome.DENIED, AccountingErrorType.BLOCKED),
    LoginOutcome.UNAVAILABLE: (AccountingOutcome.ERROR, AccountingErrorType.UNAVAILABLE),
    LoginOutcome.MISCONFIGURED: (AccountingOutcome.ERROR, AccountingErrorType.INTERNAL),
    # No provider is configured for this deployment: a setup fault of ours, not an outage
    # at the far end, so it is recorded as internal rather than unavailable.
    LoginOutcome.PROVIDER_NOT_CONFIGURED: (
        AccountingOutcome.ERROR,
        AccountingErrorType.INTERNAL,
    ),
}


@dataclass(frozen=True)
class LoginResult:
    """One login attempt's outcome and, on success, the session it issued."""

    outcome: LoginOutcome
    issued: IssuedSession | None = None
    retry_after_seconds: int | None = None

    def __post_init__(self) -> None:
        if self.outcome is LoginOutcome.SUCCESS:
            if self.issued is None:
                raise ValueError("a successful login must carry the session it issued.")
        elif self.issued is not None:
            raise ValueError("only a successful login may carry a session.")

        if self.outcome is LoginOutcome.THROTTLED:
            if self.retry_after_seconds is None or self.retry_after_seconds <= 0:
                raise ValueError("a throttled login must carry a positive retry delay.")
        elif self.retry_after_seconds is not None:
            raise ValueError("only a throttled login may carry a retry delay.")


class LoginService:
    """The application's authentication decision.

    Holds no per-request state, so one instance is shared by the application.
    """

    def __init__(
        self,
        *,
        provider: AuthProvider | None,
        throttle: LoginThrottle,
        session_store: SessionStore,
        recorder: AccountingRecorder | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._provider = provider
        self._throttle = throttle
        self._session_store = session_store
        self._recorder = recorder
        # One clock for the whole application, so an injected clock also drives session
        # creation and throttling windows.
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))

    def authenticate(
        self,
        *,
        username: object,
        password: object,
        client_ip: str,
        presented_session_id: str | None = None,
        now: datetime | None = None,
    ) -> LoginResult:
        """Attempt one login and return its outcome.

        ``presented_session_id`` is the identifier from the caller's cookie, if any. It
        is used only to destroy that session on success.
        """
        moment = now if now is not None else self._clock()
        username_key = throttling_username_key(username)

        # Admission and counting are one atomic step, so a burst of concurrent requests
        # for the same pair cannot all be admitted before any of them is counted.
        try:
            decision = self._throttle.admit(
                username_key=username_key, client_ip=client_ip, now=moment
            )
        except StoreError as exc:
            # Fail closed. If admission cannot be decided, the attempt is refused rather
            # than allowed through unchecked: a storage failure must never become a way
            # around throttling. Only the exception type is logged.
            logger.error(
                "Login refused reason=throttle_store_unavailable exception=%s client_ip=%s",
                type(exc).__name__,
                client_ip,
            )

            return self._finish(LoginResult(LoginOutcome.UNAVAILABLE), moment=moment)

        if not decision.allowed:
            logger.warning("Login throttled reason=attempt_limit client_ip=%s", client_ip)

            return self._finish(
                LoginResult(
                    LoginOutcome.THROTTLED,
                    retry_after_seconds=decision.retry_after_seconds,
                ),
                moment=moment,
            )

        if self._provider is None:
            logger.warning("Login refused reason=no_provider client_ip=%s", client_ip)

            return self._finish(
                LoginResult(LoginOutcome.PROVIDER_NOT_CONFIGURED), moment=moment
            )

        # A password this large cannot be a credential this application verifies, so it
        # is refused without touching the directory. It is still counted as a failure, so
        # an oversized submission cannot be used to escape throttling.
        if isinstance(password, str) and len(password) > MAX_PASSWORD_LENGTH:
            logger.warning("Login failed reason=rejected client_ip=%s", client_ip)

            return self._finish(LoginResult(LoginOutcome.REJECTED), moment=moment)

        try:
            result = self._provider.authenticate(username, password)
        except Exception as exc:  # noqa: BLE001 - a provider bug must still fail closed
            # Only the exception type is logged: a library message could carry directory
            # detail or the value that was submitted. The provider logs its own reasons.
            logger.error(
                "Login failed reason=provider_raised exception=%s client_ip=%s",
                type(exc).__name__,
                client_ip,
            )

            return self._finish(LoginResult(LoginOutcome.UNAVAILABLE), moment=moment)

        if not result.authenticated or result.identity is None:
            outcome = _FAILURE_OUTCOMES.get(result.outcome, LoginOutcome.UNAVAILABLE)

            logger.warning("Login failed reason=%s client_ip=%s", outcome.value, client_ip)

            return self._finish(LoginResult(outcome), moment=moment)

        try:
            self._throttle.record_success(username_key=username_key, client_ip=client_ip)
        except StoreError as exc:
            # The credential was proven, so a failure to clear the counter must not refuse
            # the login. The pair keeps its count until the window expires, which is the
            # conservative direction, and the failure is logged.
            logger.warning(
                "Login throttle counters were not cleared exception=%s client_ip=%s",
                type(exc).__name__,
                client_ip,
            )

        try:
            # Fixation protection: the session the caller already held, if any, is
            # destroyed before a new identifier is issued. Login never adopts a
            # client-supplied value.
            if presented_session_id:
                self._session_store.invalidate(presented_session_id)

            issued = self._session_store.create(result.identity, now=moment)
        except StoreError as exc:
            # The credential was proven, so this is recorded as an error rather than a
            # refusal: the operator needs to see that someone authenticated and did not
            # get a session. Only the exception type is logged.
            logger.error(
                "Login failed reason=session_store_unavailable exception=%s client_ip=%s",
                type(exc).__name__,
                client_ip,
            )

            return self._finish(
                LoginResult(LoginOutcome.UNAVAILABLE),
                moment=moment,
                identity=result.identity,
            )

        logger.info(
            "Login succeeded session_label=%s user_id=%s auth_source=%s",
            issued.session.label,
            result.identity.user_id,
            result.identity.auth_source,
        )

        return self._finish(
            LoginResult(LoginOutcome.SUCCESS, issued=issued),
            moment=moment,
            identity=result.identity,
            session_label=issued.session.label,
        )

    def _finish(
        self,
        result: LoginResult,
        *,
        moment: datetime,
        identity: AuthenticatedIdentity | None = None,
        session_label: str | None = None,
    ) -> LoginResult:
        """Record the attempt and hand the result back unchanged.

        Recorded as an *optional* event: a login must not fail because its audit record
        could not be written — the architecture requires fail-closed accounting for
        state-changing approvals, not for authentication. A failure here degrades the
        accounting state, which the status surface reports.
        """
        if self._recorder is None:
            return result

        outcome, error_type = _RECORDED_OUTCOMES.get(
            result.outcome, (AccountingOutcome.ERROR, AccountingErrorType.INTERNAL)
        )

        self._recorder.record(
            AccountingEvent(
                event_type=(
                    AccountingEventType.LOGIN_SUCCESS
                    if result.outcome is LoginOutcome.SUCCESS
                    else AccountingEventType.LOGIN_FAILURE
                ),
                outcome=outcome,
                user_id=None if identity is None else identity.user_id,
                auth_source=None if identity is None else identity.auth_source,
                session_label=session_label,
                error_type=error_type,
                timestamp=moment,
            )
        )

        return result

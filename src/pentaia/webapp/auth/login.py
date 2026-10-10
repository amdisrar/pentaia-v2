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

from pentaia.webapp.auth.base import AuthOutcome, AuthProvider
from pentaia.webapp.auth.throttle import LoginThrottle, throttling_username_key
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
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._provider = provider
        self._throttle = throttle
        self._session_store = session_store
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
        decision = self._throttle.admit(
            username_key=username_key, client_ip=client_ip, now=moment
        )

        if not decision.allowed:
            logger.warning("Login throttled reason=attempt_limit client_ip=%s", client_ip)

            return LoginResult(
                LoginOutcome.THROTTLED,
                retry_after_seconds=decision.retry_after_seconds,
            )

        if self._provider is None:
            logger.warning("Login refused reason=no_provider client_ip=%s", client_ip)

            return LoginResult(LoginOutcome.PROVIDER_NOT_CONFIGURED)

        # A password this large cannot be a credential this application verifies, so it
        # is refused without touching the directory. It is still counted as a failure, so
        # an oversized submission cannot be used to escape throttling.
        if isinstance(password, str) and len(password) > MAX_PASSWORD_LENGTH:
            logger.warning("Login failed reason=rejected client_ip=%s", client_ip)

            return LoginResult(LoginOutcome.REJECTED)

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

            return LoginResult(LoginOutcome.UNAVAILABLE)

        if not result.authenticated or result.identity is None:
            outcome = _FAILURE_OUTCOMES.get(result.outcome, LoginOutcome.UNAVAILABLE)

            logger.warning("Login failed reason=%s client_ip=%s", outcome.value, client_ip)

            return LoginResult(outcome)

        self._throttle.record_success(username_key=username_key, client_ip=client_ip)

        # Fixation protection: the session the caller already held, if any, is destroyed
        # before a new identifier is issued. Login never adopts a client-supplied value.
        if presented_session_id:
            self._session_store.invalidate(presented_session_id)

        issued = self._session_store.create(result.identity, now=moment)

        logger.info(
            "Login succeeded session_label=%s user_id=%s auth_source=%s",
            issued.session.label,
            result.identity.user_id,
            result.identity.auth_source,
        )

        return LoginResult(LoginOutcome.SUCCESS, issued=issued)

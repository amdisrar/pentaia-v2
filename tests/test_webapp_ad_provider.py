"""P4-05 Active Directory provider behaviour, classification and secret safety.

Everything here is offline: the transport is replaced by a fake binder, and the ldap3
client is replaced by recording doubles. No test needs a domain controller, and the
owner's Windows Server is never on the path of the normal suite.
"""

import dataclasses
import logging
import ssl
from typing import Any, ClassVar

import pytest
from ldap3.core import exceptions as ldap_exceptions

import pentaia.webapp.auth.ad as ad_module
from pentaia.webapp.auth.ad import (
    DEFAULT_AD_PORT,
    ADAuthProvider,
    ADConfig,
    Ldap3DirectoryBinder,
    build_ad_provider,
)
from pentaia.webapp.auth.base import (
    AuthOutcome,
    AuthProvider,
    AuthResult,
    ProviderMisconfigured,
    ProviderRejected,
    ProviderUnavailable,
)
from pentaia.webapp.identity import AuthenticatedIdentity

HOST = "dc01.example.test"
USERNAME = "User@Example.com"
NORMALIZED = "user@example.com"
PASSWORD = "correct horse battery staple"


class FakeBinder:
    """Stands in for the LDAPS transport."""

    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[tuple[str, str]] = []

    def bind(self, *, username: str, password: str) -> None:
        self.calls.append((username, password))

        if self.error is not None:
            raise self.error


def config() -> ADConfig:
    return ADConfig(host=HOST)


def provider(error: Exception | None = None) -> tuple[ADAuthProvider, FakeBinder]:
    binder = FakeBinder(error)

    return ADAuthProvider(config(), binder=binder), binder


# --- result contract -------------------------------------------------------


def test_the_provider_satisfies_the_provider_neutral_contract() -> None:
    instance = ADAuthProvider(config(), binder=FakeBinder())

    assert instance.name == "ad"
    assert isinstance(instance, AuthProvider)
    assert callable(instance.authenticate)


def test_a_successful_result_must_carry_an_identity() -> None:
    with pytest.raises(ValueError, match="carry an identity"):
        AuthResult(AuthOutcome.SUCCESS)


def test_a_failed_result_must_not_carry_an_identity() -> None:
    identity = AuthenticatedIdentity.from_provider(auth_source="ad", username="user")

    for outcome in (AuthOutcome.REJECTED, AuthOutcome.UNAVAILABLE, AuthOutcome.MISCONFIGURED):
        with pytest.raises(ValueError, match="only a successful result"):
            AuthResult(outcome, identity=identity)


def test_only_success_is_authenticated() -> None:
    assert AuthResult(AuthOutcome.SUCCESS, identity=AuthenticatedIdentity.from_provider(
        auth_source="ad", username="user"
    )).authenticated

    for outcome in (AuthOutcome.REJECTED, AuthOutcome.UNAVAILABLE, AuthOutcome.MISCONFIGURED):
        assert AuthResult(outcome).authenticated is False


# --- success and identity normalization -----------------------------------


def test_a_successful_bind_produces_the_canonical_identity() -> None:
    instance, binder = provider()

    result = instance.authenticate(USERNAME, PASSWORD)

    assert result.outcome is AuthOutcome.SUCCESS
    assert result.authenticated is True
    assert result.identity is not None
    assert result.identity.user_id == "ad:user@example.com"
    assert result.identity.username == NORMALIZED
    assert result.identity.auth_source == "ad"
    assert binder.calls == [(NORMALIZED, PASSWORD)]


def test_the_display_name_falls_back_to_the_normalized_username() -> None:
    """A direct bind returns no attributes, and no extra lookup is performed."""
    instance, _ = provider()

    result = instance.authenticate(USERNAME, PASSWORD)

    assert result.identity is not None
    assert result.identity.display_name == NORMALIZED


def test_the_result_carries_no_password_or_credential_field() -> None:
    instance, _ = provider()

    result = instance.authenticate(USERNAME, PASSWORD)

    fields = {field.name for field in dataclasses.fields(AuthResult)}
    assert fields == {"outcome", "identity"}
    assert PASSWORD not in repr(result)
    assert PASSWORD not in str(result)


def test_the_username_is_normalized_before_the_bind() -> None:
    instance, binder = provider()

    instance.authenticate("  USER@EXAMPLE.COM  ", PASSWORD)

    assert binder.calls == [(NORMALIZED, PASSWORD)]


def test_the_ad_provider_requires_a_upn_username() -> None:
    """One AD principal must have exactly one PentAiA identity.

    PentAiA derives `ad:<normalized_username>` from what the operator supplied, so
    accepting both `user@example.com` and `DOMAIN\\user` would produce two identities for
    one principal. The down-level form is refused rather than converted: converting
    would mean guessing a UPN suffix.
    """
    instance, binder = provider()

    result = instance.authenticate("EXAMPLE\\user", PASSWORD)

    assert result.outcome is AuthOutcome.REJECTED
    assert result.identity is None
    assert binder.calls == []


def test_a_upn_still_binds_and_yields_the_canonical_identity() -> None:
    instance, binder = provider()

    result = instance.authenticate("User@Example.com", PASSWORD)

    assert result.outcome is AuthOutcome.SUCCESS
    assert result.identity is not None
    assert result.identity.user_id == "ad:user@example.com"
    assert binder.calls == [("user@example.com", PASSWORD)]


@pytest.mark.parametrize(
    "value",
    [
        "EXAMPLE\\user",  # down-level form
        "example\\user@example.com",  # down-level with a UPN suffix
        "user",  # bare account name, no domain
        "user@",  # empty domain
        "@example.com",  # empty local part
        "user@@example.com",  # two separators
        "user@example@com",
        "user@.example.com",  # malformed domain
        "user@example.com.",  # trailing dot
        "user@example..com",  # empty domain label
        ".user@example.com",  # malformed local part
        "user.@example.com",
        "user..name@example.com",
    ],
)
def test_a_username_that_is_not_a_upn_is_refused_without_a_bind(value: str) -> None:
    """Refused before any connection, so no malformed value reaches the directory."""
    instance, binder = provider()

    result = instance.authenticate(value, PASSWORD)

    assert result.outcome is AuthOutcome.REJECTED
    assert result.identity is None
    assert binder.calls == []


@pytest.mark.parametrize(
    "value",
    ["user@example.com", "user@example", "first.last+tag@sub.example.test"],
)
def test_accepted_upn_shapes(value: str) -> None:
    """A single-label UPN suffix is allowed: no dot is required in the domain."""
    instance, binder = provider()

    result = instance.authenticate(value, PASSWORD)

    assert result.outcome is AuthOutcome.SUCCESS
    assert result.identity is not None
    assert result.identity.user_id == f"ad:{value}"
    assert binder.calls == [(value, PASSWORD)]


def test_the_upn_rule_is_not_baked_into_the_shared_identity_model() -> None:
    """RADIUS may legitimately authenticate other normalized username forms."""
    from pathlib import Path

    import pentaia.webapp.identity as identity_module

    # The generic model still accepts a normalized username that is not a UPN.
    identity = AuthenticatedIdentity.from_provider(
        auth_source="radius", username="svc-account"
    )
    assert identity.user_id == "radius:svc-account"

    # The UPN rule exists only in the AD provider.
    source = Path(identity_module.__file__).read_text()
    assert "validate_upn" not in source
    assert "local@domain" not in source


# --- attempts refused before contacting the directory ---------------------


@pytest.mark.parametrize("value", ["", None, 5, b"pw", ["pw"]])
def test_an_empty_or_non_string_password_is_refused_without_a_bind(value: object) -> None:
    """An empty password can become an anonymous bind that proves nothing."""
    instance, binder = provider()

    result = instance.authenticate(USERNAME, value)

    assert result.outcome is AuthOutcome.REJECTED
    assert binder.calls == []


def test_a_whitespace_password_is_a_credential_and_is_attempted() -> None:
    """Only a truly empty password is refused; altering a password would corrupt it."""
    instance, binder = provider()

    result = instance.authenticate(USERNAME, "   ")

    assert result.outcome is AuthOutcome.SUCCESS
    assert binder.calls == [(NORMALIZED, "   ")]


@pytest.mark.parametrize("value", ["", "   ", None, 5, "bad user", "user:name", "user\nname"])
def test_a_malformed_username_is_rejected_without_a_bind(value: object) -> None:
    instance, binder = provider()

    result = instance.authenticate(value, PASSWORD)

    assert result.outcome is AuthOutcome.REJECTED
    assert binder.calls == []


# --- outcome classification -----------------------------------------------


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ProviderRejected("no"), AuthOutcome.REJECTED),
        (ProviderUnavailable("down"), AuthOutcome.UNAVAILABLE),
        (ProviderMisconfigured("bad tls"), AuthOutcome.MISCONFIGURED),
    ],
)
def test_neutral_transport_errors_map_to_their_outcome(
    error: Exception, expected: AuthOutcome
) -> None:
    instance, _ = provider(error)

    assert instance.authenticate(USERNAME, PASSWORD).outcome is expected


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("unexpected"),
        ValueError("unexpected"),
        MemoryError(),
        KeyError("unexpected"),
    ],
)
def test_an_unclassified_error_fails_closed(error: Exception) -> None:
    """An unknown failure is never an admission."""
    instance, _ = provider(error)

    result = instance.authenticate(USERNAME, PASSWORD)

    assert result.outcome is AuthOutcome.UNAVAILABLE
    assert result.identity is None
    assert result.authenticated is False


def test_a_successful_bind_never_returns_a_failure() -> None:
    instance, _ = provider()

    assert instance.authenticate(USERNAME, PASSWORD).outcome is AuthOutcome.SUCCESS


# --- logging and secret handling ------------------------------------------


@pytest.mark.parametrize("error", [ProviderRejected("no"), ProviderUnavailable("down")])
def test_the_password_never_appears_in_the_log(
    error: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    instance, _ = provider(error)

    with caplog.at_level(logging.DEBUG, logger="pentaia.webapp.auth.ad"):
        instance.authenticate(USERNAME, PASSWORD)

    logged = "\n".join(record.getMessage() for record in caplog.records)

    assert PASSWORD not in logged
    assert "correct horse" not in logged


def test_the_password_never_appears_in_the_log_on_success(
    caplog: pytest.LogCaptureFixture,
) -> None:
    instance, _ = provider()

    with caplog.at_level(logging.DEBUG, logger="pentaia.webapp.auth.ad"):
        instance.authenticate(USERNAME, PASSWORD)

    logged = "\n".join(record.getMessage() for record in caplog.records)

    assert PASSWORD not in logged
    assert "user_id=ad:user@example.com" in logged


def test_a_rejected_username_is_not_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A malformed value may be an attack string and is not an identity."""
    instance, _ = provider()
    hostile = "attacker\nfake line"

    with caplog.at_level(logging.DEBUG, logger="pentaia.webapp.auth.ad"):
        instance.authenticate(hostile, PASSWORD)

    logged = "\n".join(record.getMessage() for record in caplog.records)

    assert "attacker" not in logged
    assert "malformed_username" in logged


def test_unexpected_error_logging_uses_the_type_name_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A library message could echo a credential, so it is never logged."""
    instance, _ = provider(RuntimeError("ldap said password=secret"))

    with caplog.at_level(logging.DEBUG, logger="pentaia.webapp.auth.ad"):
        instance.authenticate(USERNAME, PASSWORD)

    logged = "\n".join(record.getMessage() for record in caplog.records)

    assert "RuntimeError" in logged
    assert "ldap said" not in logged


def test_logging_names_the_host_and_port_but_never_a_credential(
    caplog: pytest.LogCaptureFixture,
) -> None:
    instance, _ = provider()

    with caplog.at_level(logging.INFO, logger="pentaia.webapp.auth.ad"):
        instance.authenticate(USERNAME, PASSWORD)

    logged = "\n".join(record.getMessage() for record in caplog.records)

    assert f"host={HOST}" in logged
    assert f"port={DEFAULT_AD_PORT}" in logged


# --- LDAPS transport wiring -----------------------------------------------


class RecordingConnection:
    """Minimal ldap3 Connection double."""

    instances: ClassVar[list["RecordingConnection"]] = []

    def __init__(self, server: Any, **kwargs: Any) -> None:
        self.server = server
        self.kwargs = kwargs
        self.unbound = False
        RecordingConnection.instances.append(self)

    def bind(self) -> bool:
        if self.kwargs.get("_error") is not None:
            raise self.kwargs["_error"]

        return self.kwargs.get("_result", True)

    def unbind(self) -> None:
        self.unbound = True


class RecordingServer:
    instances: ClassVar[list["RecordingServer"]] = []

    def __init__(self, host: str, **kwargs: Any) -> None:
        self.host = host
        self.kwargs = kwargs
        RecordingServer.instances.append(self)


@pytest.fixture()
def recorded_transport(monkeypatch: pytest.MonkeyPatch):
    """Record the semantics the binder asks ldap3 for."""
    RecordingConnection.instances = []
    RecordingServer.instances = []
    errors: dict[str, Any] = {"error": None, "result": True}

    def connection_factory(server: Any, **kwargs: Any) -> RecordingConnection:
        return RecordingConnection(
            server, _error=errors["error"], _result=errors["result"], **kwargs
        )

    monkeypatch.setattr(ad_module, "Server", RecordingServer)
    monkeypatch.setattr(ad_module, "Connection", connection_factory)

    return errors


def test_the_transport_is_ldaps_only_with_bounded_timeouts(recorded_transport) -> None:
    binder = Ldap3DirectoryBinder(ADConfig(host=HOST, connect_timeout=3, receive_timeout=4))

    binder.bind(username=NORMALIZED, password=PASSWORD)

    server = RecordingServer.instances[-1]
    connection = RecordingConnection.instances[-1]

    assert server.host == HOST
    assert server.kwargs["use_ssl"] is True
    assert server.kwargs["port"] == DEFAULT_AD_PORT
    assert server.kwargs["connect_timeout"] == 3
    assert server.kwargs["tls"].validate == ssl.CERT_REQUIRED
    assert connection.kwargs["receive_timeout"] == 4


def test_the_transport_performs_no_directory_read(recorded_transport) -> None:
    """A direct bind needs no search, and ldap3 would otherwise read the schema."""
    binder = Ldap3DirectoryBinder(config())

    binder.bind(username=NORMALIZED, password=PASSWORD)

    from ldap3 import NONE

    assert RecordingServer.instances[-1].kwargs["get_info"] == NONE


def test_the_transport_never_follows_a_referral(recorded_transport) -> None:
    binder = Ldap3DirectoryBinder(config())

    binder.bind(username=NORMALIZED, password=PASSWORD)

    assert RecordingConnection.instances[-1].kwargs["auto_referrals"] is False


def test_the_transport_uses_a_simple_bind_and_does_not_auto_bind(recorded_transport) -> None:
    from ldap3 import SIMPLE

    binder = Ldap3DirectoryBinder(config())

    binder.bind(username=NORMALIZED, password=PASSWORD)

    kwargs = RecordingConnection.instances[-1].kwargs

    assert kwargs["authentication"] == SIMPLE
    assert kwargs["auto_bind"] is False
    assert kwargs["raise_exceptions"] is True
    assert kwargs["user"] == NORMALIZED


def test_a_configured_ca_bundle_reaches_the_tls_layer(
    recorded_transport, tmp_path
) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("placeholder")

    Ldap3DirectoryBinder(ADConfig(host=HOST, ca_file=ca)).bind(
        username=NORMALIZED, password=PASSWORD
    )

    assert RecordingServer.instances[-1].kwargs["tls"].ca_certs_file == str(ca)


def test_the_connection_is_released_even_when_the_bind_fails(recorded_transport) -> None:
    recorded_transport["error"] = ldap_exceptions.LDAPInvalidCredentialsResult("no")

    with pytest.raises(ProviderRejected):
        Ldap3DirectoryBinder(config()).bind(username=NORMALIZED, password=PASSWORD)

    assert RecordingConnection.instances[-1].unbound is True


def test_a_failing_teardown_does_not_change_the_outcome(recorded_transport, monkeypatch) -> None:
    def exploding_unbind(self) -> None:
        raise RuntimeError("socket already gone")

    monkeypatch.setattr(RecordingConnection, "unbind", exploding_unbind)
    recorded_transport["error"] = ldap_exceptions.LDAPInvalidCredentialsResult("no")

    with pytest.raises(ProviderRejected):
        Ldap3DirectoryBinder(config()).bind(username=NORMALIZED, password=PASSWORD)


def test_a_bind_that_returns_false_is_a_rejection(recorded_transport) -> None:
    recorded_transport["result"] = False

    with pytest.raises(ProviderRejected):
        Ldap3DirectoryBinder(config()).bind(username=NORMALIZED, password=PASSWORD)


# --- library failure classification ---------------------------------------


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ldap_exceptions.LDAPInvalidCredentialsResult("no"), ProviderRejected),
        (ldap_exceptions.LDAPBindError("no"), ProviderRejected),
        (ldap_exceptions.LDAPSocketOpenError("refused"), ProviderUnavailable),
        (ldap_exceptions.LDAPSocketReceiveError("reset"), ProviderUnavailable),
        (ldap_exceptions.LDAPSocketSendError("broken"), ProviderUnavailable),
        (ldap_exceptions.LDAPCommunicationError("gone"), ProviderUnavailable),
        # socket.timeout is TimeoutError on supported Pythons, so one case covers both.
        (TimeoutError("timed out"), ProviderUnavailable),
        (ldap_exceptions.LDAPSSLConfigurationError("bad ca"), ProviderMisconfigured),
        (ssl.SSLCertVerificationError("untrusted"), ProviderMisconfigured),
        (ssl.SSLError("handshake"), ProviderMisconfigured),
        (ldap_exceptions.LDAPException("odd"), ProviderUnavailable),
    ],
)
def test_library_failures_are_classified(
    error: Exception, expected: type[Exception], recorded_transport
) -> None:
    recorded_transport["error"] = error

    with pytest.raises(expected):
        Ldap3DirectoryBinder(config()).bind(username=NORMALIZED, password=PASSWORD)


def test_a_certificate_failure_wrapped_as_a_socket_error_is_still_tls(
    recorded_transport,
) -> None:
    """ldap3 can surface a handshake failure as a communication error."""
    recorded_transport["error"] = ldap_exceptions.LDAPSocketOpenError(
        "socket error"
    )
    recorded_transport["error"].__cause__ = ssl.SSLCertVerificationError("untrusted issuer")

    with pytest.raises(ProviderMisconfigured):
        Ldap3DirectoryBinder(config()).bind(username=NORMALIZED, password=PASSWORD)


def test_a_deeply_wrapped_certificate_failure_is_still_tls(recorded_transport) -> None:
    root = ssl.SSLCertVerificationError("hostname mismatch")
    middle = ldap_exceptions.LDAPSocketReceiveError("wrapped")
    middle.__cause__ = root
    recorded_transport["error"] = middle

    with pytest.raises(ProviderMisconfigured):
        Ldap3DirectoryBinder(config()).bind(username=NORMALIZED, password=PASSWORD)


def test_a_cause_cycle_does_not_hang_the_classifier(recorded_transport) -> None:
    first = ldap_exceptions.LDAPSocketOpenError("a")
    second = ldap_exceptions.LDAPSocketOpenError("b")
    first.__cause__ = second
    second.__cause__ = first
    recorded_transport["error"] = first

    with pytest.raises(ProviderUnavailable):
        Ldap3DirectoryBinder(config()).bind(username=NORMALIZED, password=PASSWORD)


# --- end-to-end provider over the recorded transport ----------------------


def test_the_provider_reports_an_untrusted_certificate_as_misconfigured(
    recorded_transport,
) -> None:
    recorded_transport["error"] = ssl.SSLCertVerificationError("untrusted issuer")

    result = ADAuthProvider(config()).authenticate(USERNAME, PASSWORD)

    assert result.outcome is AuthOutcome.MISCONFIGURED
    assert result.identity is None


def test_the_provider_reports_a_timeout_as_unavailable(recorded_transport) -> None:
    recorded_transport["error"] = TimeoutError("timed out")

    result = ADAuthProvider(config()).authenticate(USERNAME, PASSWORD)

    assert result.outcome is AuthOutcome.UNAVAILABLE


def test_the_provider_reports_bad_credentials_as_rejected(recorded_transport) -> None:
    recorded_transport["error"] = ldap_exceptions.LDAPInvalidCredentialsResult("no")

    result = ADAuthProvider(config()).authenticate(USERNAME, PASSWORD)

    assert result.outcome is AuthOutcome.REJECTED


def test_the_provider_builds_an_identity_over_the_real_transport_path(
    recorded_transport,
) -> None:
    result = ADAuthProvider(config()).authenticate(USERNAME, PASSWORD)

    assert result.outcome is AuthOutcome.SUCCESS
    assert result.identity is not None
    assert result.identity.user_id == "ad:user@example.com"


# --- source-level security guards -----------------------------------------


def test_the_provider_module_contains_no_insecure_transport_path() -> None:
    from pathlib import Path

    source = Path(ad_module.__file__).read_text()

    for forbidden in (
        "CERT_NONE",
        "CERT_OPTIONAL",
        "use_ssl=False",
        "auto_referrals=True",
        "get_info=SCHEMA",
        "check_hostname = False",
    ):
        assert forbidden not in source, forbidden


def test_the_provider_module_contains_no_plaintext_ldap_url() -> None:
    """Checked against string literals, so documentation may still name the risk."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path(ad_module.__file__).read_text())
    literals = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]

    insecure = [value for value in literals if value.startswith(("ldap://", "ldaps://"))]

    assert not insecure, insecure


def test_the_provider_module_constructs_no_ldap_filter_or_search() -> None:
    """Direct bind needs no filter, so there is no injection surface to reason about."""
    from pathlib import Path

    source = Path(ad_module.__file__).read_text()

    for forbidden in ("search(", "extend.standard", "Filter(", "ldap_filter", "base_dn", "BASE_DN"):
        assert forbidden not in source, forbidden


def test_the_provider_module_implements_no_group_or_role_mapping() -> None:
    from pathlib import Path

    source = Path(ad_module.__file__).read_text().lower()

    for forbidden in ("memberof", "group", "role", "rbac", "permission"):
        assert forbidden not in source, forbidden


def test_the_ad_provider_only_knows_the_canonical_auth_source() -> None:
    """The application-level token is ``ad``; LDAP names the transport, not the source."""
    from pathlib import Path

    source = Path(ad_module.__file__).read_text()

    assert 'AUTH_SOURCE_AD' in source
    assert '"ldap"' not in source
    assert "'ldap'" not in source


def test_the_provider_does_not_expose_an_ldap_type_to_callers() -> None:
    """The provider's public surface is library-neutral."""
    instance = ADAuthProvider(config(), binder=FakeBinder())

    result = instance.authenticate(USERNAME, PASSWORD)

    assert type(result) is AuthResult
    assert type(result.identity) is AuthenticatedIdentity


def test_the_factory_builds_a_provider_from_configuration() -> None:
    instance = build_ad_provider(ADConfig(host=HOST))

    assert isinstance(instance, ADAuthProvider)
    assert isinstance(instance, AuthProvider)


def test_no_web_route_imports_the_ad_provider() -> None:
    """P4-05 stays provider/service code; login wiring is a later issue."""
    from pathlib import Path

    import pentaia.webapp

    root = Path(pentaia.webapp.__file__).parent

    for path in sorted(root.rglob("*.py")):
        if "auth" in path.parts and path.parent.name == "webapp":
            continue
        if path.parent.name != "api":
            continue
        assert "auth.ad" not in path.read_text(), path
        assert "ADAuthProvider" not in path.read_text(), path

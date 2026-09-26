#!/usr/bin/env python3
"""Developer/operator validation for Active Directory authentication over LDAPS.

This tool contains no LDAP, TLS or socket logic of its own: it drives the P4-05
provider, so what it validates is the production code path, not a second client.

**Probe mode** (no ``--scenario``) is the original tool and keeps its behaviour and
exit codes. It prompts for a UPN and a password and reports the normalized outcome::

    uv run python scripts/ad_ldaps_check.py
    uv run python scripts/ad_ldaps_check.py --attempts 3
    uv run python scripts/ad_ldaps_check.py --expect rejected     # assert the outcome

**Scenario mode** runs one named check with a fixed expectation and a PASS/FAIL
verdict. This is what the Microsoft Entra Domain Services validation uses::

    S1  success         real UPN + real password                 -> SUCCESS
    S2  wrong-password  real UPN + an in-process wrong password   -> REJECTED
    S3  roundtrip       S1 then S2 in one run                     -> SUCCESS, REJECTED
    S4  unreachable     no prompted credentials                   -> UNAVAILABLE
    S5  untrusted-ca    real host, CA bundle deliberately absent  -> MISCONFIGURED

Secrets: the password is read from the terminal with ``getpass`` and used for one
bind. It is never read from an environment variable, never taken from an argument,
never stored, echoed, printed or logged. S2-S5 use a password generated in-process
that is never derived from the real one.

Certificate validation is mandatory and this tool cannot weaken it. S5 demonstrates
enforcement by **removing trust** — using the system store instead of the configured
CA bundle — never by disabling verification. There is no skip-verification option.

Configuration comes from the ``PENTAIA_AD_*`` variables documented in README.md and
``.env.example``. ``--host``, ``--port`` and ``--timeout`` override configuration only;
they are not credentials.

Exit codes::

    0  the expected outcome was observed (probe mode without --expect: SUCCESS)
    1  probe mode: REJECTED
    2  probe mode: UNAVAILABLE
    3  probe mode: MISCONFIGURED, or a configuration problem in either mode
    4  usage problem
    5  scenario mode or --expect: the observed outcome did not match the expectation
"""

import argparse
import getpass
import os
import secrets
import sys

from pentaia.webapp.auth.ad import (
    CA_FILE_ENV,
    CONNECT_TIMEOUT_ENV,
    DEFAULT_AD_PORT,
    HOST_ENV,
    PORT_ENV,
    RECEIVE_TIMEOUT_ENV,
    ADAuthProvider,
    ADConfig,
    load_ad_config,
    validate_ad_port,
    validate_ad_timeout,
)
from pentaia.webapp.auth.base import AuthOutcome, AuthProvider, AuthResult

EXIT_CODES = {
    AuthOutcome.SUCCESS: 0,
    AuthOutcome.REJECTED: 1,
    AuthOutcome.UNAVAILABLE: 2,
    AuthOutcome.MISCONFIGURED: 3,
}

USAGE_PROBLEM = 4
EXPECTATION_FAILED = 5

GUIDANCE = {
    AuthOutcome.SUCCESS: "The credentials were proven over LDAPS.",
    AuthOutcome.REJECTED: (
        "The directory refused these credentials. Same result for a wrong password and "
        "an unknown user, by design."
    ),
    AuthOutcome.UNAVAILABLE: (
        "The directory could not be reached or did not answer within the configured "
        "timeout. Check PENTAIA_AD_HOST/PORT and network reachability."
    ),
    AuthOutcome.MISCONFIGURED: (
        "Local TLS or configuration problem. A private CA needs PENTAIA_AD_CA_FILE "
        "pointing at a readable bundle; an untrusted or mismatched certificate also "
        "lands here. Certificate validation cannot be disabled."
    ),
}

SCENARIOS = ("success", "wrong-password", "roundtrip", "unreachable", "untrusted-ca")

#: RFC 5737 TEST-NET-1. Reserved for documentation, so it is deliberately not a real
#: host and a connection attempt cannot reach a directory.
DEFAULT_UNREACHABLE_HOST = "192.0.2.1"
DEFAULT_UNREACHABLE_TIMEOUT_SECONDS = 3.0

#: RFC 2606 reserved TLD, so the placeholder can never be a real account.
PLACEHOLDER_UPN = "pentai-validator@example.invalid"

#: 24 random bytes, URL-safe encoded to 32 characters.
WRONG_PASSWORD_BYTES = 24


def generate_wrong_password() -> str:
    """Return a password that cannot be the real one, and was never derived from it."""
    return secrets.token_urlsafe(WRONG_PASSWORD_BYTES)


def read_username(explicit: str | None) -> str:
    """Prefer an explicit value, then the environment, then an interactive prompt."""
    if explicit:
        return explicit

    from_environment = os.environ.get("PENTAIA_AD_TEST_USER")

    if from_environment:
        return from_environment

    return input("UPN (for example user@example.test): ").strip()


def read_password() -> str:
    """Read the password interactively. It is never echoed and never stored."""
    return getpass.getpass("Password (not echoed): ")


def build_provider(config: ADConfig) -> AuthProvider:
    """Build the production provider.

    The single seam through which every scenario reaches the directory, so the
    automated tests can exercise the scenario logic offline.
    """
    return ADAuthProvider(config)


def describe(config: ADConfig) -> str:
    """Describe the effective configuration without exposing any secret."""
    ca = str(config.ca_file) if config.ca_file is not None else "(system trust store)"

    return (
        f"host={config.host} port={config.port} ca_file={ca} "
        f"connect_timeout={config.connect_timeout:g}s "
        f"receive_timeout={config.receive_timeout:g}s"
    )


def resolve_config(
    *,
    host: str | None = None,
    port: int | None = None,
    timeout: float | None = None,
    drop_ca: bool = False,
) -> ADConfig:
    """Build the configuration for one run, applying command-line overrides.

    The ``PENTAIA_AD_*`` environment is resolved by the provider's own loader, so an
    attempt to weaken transport security is refused here exactly as it is at startup
    and no validation is duplicated. Calling the loader once first also loads ``.env``
    the way the rest of the project does, so a value there is honoured; the second call
    then applies the overrides on top.
    """
    try:
        load_ad_config()
    except ValueError:
        # A configuration problem is reported by the caller. This first call exists to
        # load .env into the environment, which happens before validation runs.
        pass

    environ = dict(os.environ)

    if host is not None:
        environ[HOST_ENV] = host

    if port is not None:
        environ[PORT_ENV] = str(port)

    if timeout is not None:
        environ[CONNECT_TIMEOUT_ENV] = str(timeout)
        environ[RECEIVE_TIMEOUT_ENV] = str(timeout)

    if drop_ca:
        environ.pop(CA_FILE_ENV, None)

    return load_ad_config(environ)


def print_identity(result: AuthResult) -> None:
    """Print the canonical identity for a successful result."""
    identity = result.identity

    if identity is None:
        return

    print(f"  canonical identity : {identity.user_id}")
    print(f"  username           : {identity.username}")
    print(f"  display name       : {identity.display_name}")
    print(f"  auth source        : {identity.auth_source}")
    print(f"  authenticated at   : {identity.authenticated_at.isoformat()}")


def report_step(label: str, expected: AuthOutcome, result: AuthResult) -> bool:
    """Print one observed outcome against its expectation and return the verdict."""
    passed = result.outcome is expected

    print(f"  {label}")
    print(f"    expected : {expected.value}")
    print(f"    observed : {result.outcome.value}")
    print_identity(result)
    print(f"    verdict  : {'PASS' if passed else 'FAIL'}")

    if not passed:
        print(f"    {GUIDANCE[result.outcome]}")

    return passed


def _print_target(config: ADConfig, scenario: str) -> None:
    print(f"scenario: {scenario}")
    print(f"target  : {describe(config)}")
    print("note    : certificate validation is mandatory and cannot be disabled here\n")


def _report_config_problem(exc: ValueError) -> int:
    # Configuration errors describe settings, never secrets, so they are safe to print.
    print(f"Configuration problem: {exc}", file=sys.stderr)
    print(
        f"Required: {HOST_ENV}. Optional: {PORT_ENV} (default {DEFAULT_AD_PORT}), "
        f"{CA_FILE_ENV}, {CONNECT_TIMEOUT_ENV}, {RECEIVE_TIMEOUT_ENV}.",
        file=sys.stderr,
    )

    return EXIT_CODES[AuthOutcome.MISCONFIGURED]


# --- scenarios -------------------------------------------------------------


def run_success(config: ADConfig, username: str) -> int:
    """S1: a real UPN and the real password must authenticate."""
    password = read_password()
    result = build_provider(config).authenticate(username, password)

    passed = report_step(
        "S1 direct-user LDAPS bind with the supplied password",
        AuthOutcome.SUCCESS,
        result,
    )

    return 0 if passed else EXPECTATION_FAILED


def run_wrong_password(config: ADConfig, username: str) -> int:
    """S2: a deliberately wrong password must be refused. Nothing is prompted."""
    print("note    : one failed sign-in is sent. Entra Domain Services locks an account")
    print("          after repeated failures, so run this once.\n")

    result = build_provider(config).authenticate(username, generate_wrong_password())

    passed = report_step(
        "S2 bind with an in-process incorrect password",
        AuthOutcome.REJECTED,
        result,
    )

    return 0 if passed else EXPECTATION_FAILED


def run_roundtrip(config: ADConfig, username: str) -> int:
    """S3: the same UPN succeeds with the real password and fails without it."""
    print("note    : one failed sign-in is sent. Entra Domain Services locks an account")
    print("          after repeated failures, so run this once.\n")

    provider = build_provider(config)
    password = read_password()

    first = provider.authenticate(username, password)
    passed = report_step("S3 step 1: the real password", AuthOutcome.SUCCESS, first)

    if not passed:
        # A pointless second attempt would only cost another failed sign-in.
        print("\n  step 2 skipped: step 1 did not succeed, so the comparison is moot\n")

        return EXPECTATION_FAILED

    second = provider.authenticate(username, generate_wrong_password())
    passed = report_step(
        "S3 step 2: an in-process incorrect password",
        AuthOutcome.REJECTED,
        second,
    )

    return 0 if passed else EXPECTATION_FAILED


def run_unreachable(config: ADConfig, username: str) -> int:
    """S4: an endpoint that cannot answer must fail closed as unavailable."""
    print("note    : no credentials are prompted. A placeholder UPN is used, and the")
    print(f"          target defaults to {DEFAULT_UNREACHABLE_HOST} (RFC 5737, not routable).")
    print("          If you point --host at a reachable directory, one failed sign-in")
    print("          will be sent.\n")

    result = build_provider(config).authenticate(username, generate_wrong_password())

    passed = report_step(
        "S4 connection to an unreachable endpoint",
        AuthOutcome.UNAVAILABLE,
        result,
    )

    return 0 if passed else EXPECTATION_FAILED


def run_untrusted_ca(config: ADConfig, username: str) -> int:
    """S5: without the private CA bundle, the certificate must be refused.

    This is how mandatory verification is demonstrated against a real endpoint: the
    configured trust anchor is removed, rather than verification being switched off.
    """
    print("note    : the configured CA bundle is deliberately not used, so only the")
    print("          system trust store applies. No credentials are prompted; the TLS")
    print("          handshake is expected to fail before any bind is sent.\n")

    result = build_provider(config).authenticate(username, generate_wrong_password())
    passed = report_step(
        "S5 bind without the configured CA bundle",
        AuthOutcome.MISCONFIGURED,
        result,
    )

    if not passed and result.outcome is AuthOutcome.SUCCESS:
        print("          The endpoint's chain is trusted by the system store, so this run")
        print("          does not demonstrate mandatory verification. Inspect it with:")
        print("          openssl s_client -connect <host>:636 -showcerts")

    return 0 if passed else EXPECTATION_FAILED


SCENARIO_RUNNERS = {
    "success": run_success,
    "wrong-password": run_wrong_password,
    "roundtrip": run_roundtrip,
    "unreachable": run_unreachable,
    "untrusted-ca": run_untrusted_ca,
}


# --- modes -----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check Active Directory authentication over LDAPS (manual, offline by default)."
    )
    parser.add_argument(
        "--username",
        default=None,
        help=(
            "UPN to authenticate. Prefer PENTAIA_AD_TEST_USER or the interactive prompt: "
            "a username on the command line is visible to other local processes."
        ),
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=1,
        help="Probe mode: how many attempts to run in one session (default 1).",
    )
    parser.add_argument(
        "--scenario",
        default=None,
        help=(
            "Run one named validation scenario instead of the interactive probe: "
            f"{', '.join(SCENARIOS)}."
        ),
    )
    parser.add_argument(
        "--expect",
        default=None,
        help=(
            "Probe mode only: assert the outcome of every attempt and exit "
            f"{EXPECTATION_FAILED} if it differs. One of: "
            f"{', '.join(outcome.value for outcome in AuthOutcome)}."
        ),
    )
    parser.add_argument(
        "--host",
        default=None,
        help=f"Override {HOST_ENV}. Configuration, not a credential.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help=f"Override {PORT_ENV}. Defaults to {DEFAULT_AD_PORT}.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help=(
            "Override both connect and receive timeouts in seconds, for "
            f"{CONNECT_TIMEOUT_ENV} and {RECEIVE_TIMEOUT_ENV}."
        ),
    )

    return parser


def parse_expected_outcome(value: str) -> AuthOutcome | None:
    """Parse one --expect value, or None when it is not an outcome name."""
    for outcome in AuthOutcome:
        if outcome.value == value.strip().lower():
            return outcome

    return None


def run_probe(args: argparse.Namespace) -> int:
    """The original interactive probe. Its behaviour and exit codes are unchanged."""
    expected = None

    if args.expect is not None:
        expected = parse_expected_outcome(args.expect)

        if expected is None:
            print(
                f"--expect must be one of: {', '.join(o.value for o in AuthOutcome)}.",
                file=sys.stderr,
            )

            return USAGE_PROBLEM

    try:
        config = resolve_config(host=args.host, port=args.port, timeout=args.timeout)
    except ValueError as exc:
        return _report_config_problem(exc)

    print(f"Active Directory over LDAPS -> {describe(config)}")
    print("Certificate validation is mandatory; the password is never stored or logged.\n")

    provider = build_provider(config)
    last_outcome = AuthOutcome.UNAVAILABLE
    all_matched = True

    for attempt in range(1, args.attempts + 1):
        username = read_username(args.username)

        if not username:
            print("No username supplied.", file=sys.stderr)

            return USAGE_PROBLEM

        # getpass never echoes and the value is not stored anywhere.
        password = read_password()

        result = provider.authenticate(username, password)
        last_outcome = result.outcome

        if expected is not None and result.outcome is not expected:
            all_matched = False

        print(f"\nattempt {attempt}: outcome={result.outcome.value}")
        print_identity(result)
        print(f"  {GUIDANCE[result.outcome]}\n")

    if expected is not None:
        print(f"expected={expected.value} observed={last_outcome.value}")

        return 0 if all_matched else EXPECTATION_FAILED

    return EXIT_CODES[last_outcome]


def run_scenario_mode(args: argparse.Namespace) -> int:
    """Run one named scenario with a fixed expectation and a PASS/FAIL verdict."""
    if args.scenario not in SCENARIO_RUNNERS:
        print(
            f"Unknown --scenario. Choose one of: {', '.join(SCENARIOS)}.",
            file=sys.stderr,
        )

        return USAGE_PROBLEM

    host = args.host
    timeout = args.timeout
    username = args.username

    # Scenarios that authenticate for real prompt for the UPN. The rest use the
    # reserved placeholder, so no real credential is involved and none is read.
    if args.scenario in {"success", "wrong-password", "roundtrip"}:
        username = read_username(args.username)

        if not username:
            print("No username supplied.", file=sys.stderr)

            return USAGE_PROBLEM
    elif username is None:
        username = PLACEHOLDER_UPN

    if args.scenario == "unreachable":
        if host is None:
            host = DEFAULT_UNREACHABLE_HOST

        if timeout is None:
            timeout = DEFAULT_UNREACHABLE_TIMEOUT_SECONDS

    try:
        config = resolve_config(
            host=host,
            port=args.port,
            timeout=timeout,
            drop_ca=args.scenario == "untrusted-ca",
        )
    except ValueError as exc:
        return _report_config_problem(exc)

    _print_target(config, args.scenario)

    return SCENARIO_RUNNERS[args.scenario](config, username)


def main(argv: list[str] | None = None) -> int:
    """Entry point. ``argv`` is accepted so the automated tests can drive it."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.attempts < 1:
        print("--attempts must be at least 1.", file=sys.stderr)

        return USAGE_PROBLEM

    if args.scenario is not None and args.expect is not None:
        print(
            "--expect asserts a single outcome and cannot be combined with --scenario, "
            "which carries its own expectations.",
            file=sys.stderr,
        )

        return USAGE_PROBLEM

    # Validated with the provider's own validators, so the rules live in one place.
    if args.port is not None:
        try:
            validate_ad_port(args.port)
        except ValueError as exc:
            print(f"Invalid --port: {exc}", file=sys.stderr)

            return USAGE_PROBLEM

    if args.timeout is not None:
        try:
            validate_ad_timeout(args.timeout, field="--timeout")
        except ValueError as exc:
            print(f"Invalid --timeout: {exc}", file=sys.stderr)

            return USAGE_PROBLEM

    if args.scenario is not None:
        return run_scenario_mode(args)

    return run_probe(args)


if __name__ == "__main__":
    raise SystemExit(main())

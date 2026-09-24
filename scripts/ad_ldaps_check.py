#!/usr/bin/env python3
"""Optional manual check of Active Directory authentication over LDAPS.

This is **not** part of the automated test suite. It is the operator-facing tool for
validating the P4-05 provider against a real domain controller, and it only runs when a
human asks for it. The normal suite is offline and deterministic.

Secrets never appear on the command line: the username may come from the environment,
and the password is always read from the terminal without echo. Neither is written
anywhere. When this is run, the password is used for one bind attempt and discarded.

Usage::

    PENTAIA_AD_HOST=dc01.example.test \\
    PENTAIA_AD_CA_FILE=/etc/ssl/certs/enterprise-ca.pem \\
    uv run python scripts/ad_ldaps_check.py

Exit codes::

    0  SUCCESS         credentials proven, canonical identity printed
    1  REJECTED        the directory refused the credentials
    2  UNAVAILABLE     the directory could not be reached, or timed out
    3  MISCONFIGURED   local configuration or TLS/certificate problem
    4  usage problem

The scenarios worth walking through, and the environment change each needs, are
documented in README.md under "Active Directory (LDAPS) authentication".
"""

import argparse
import getpass
import os
import sys

from pentaia.webapp.auth.ad import ADAuthProvider, ADConfig, load_ad_config
from pentaia.webapp.auth.base import AuthOutcome

EXIT_CODES = {
    AuthOutcome.SUCCESS: 0,
    AuthOutcome.REJECTED: 1,
    AuthOutcome.UNAVAILABLE: 2,
    AuthOutcome.MISCONFIGURED: 3,
}

USAGE_PROBLEM = 4

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


def describe(config: ADConfig) -> str:
    """Describe the effective configuration without exposing any secret."""
    ca = str(config.ca_file) if config.ca_file is not None else "(system trust store)"

    return (
        f"host={config.host} port={config.port} ca_file={ca} "
        f"connect_timeout={config.connect_timeout:g}s "
        f"receive_timeout={config.receive_timeout:g}s"
    )


def read_username(explicit: str | None) -> str:
    """Prefer an explicit value, then the environment, then an interactive prompt."""
    if explicit:
        return explicit

    from_environment = os.environ.get("PENTAIA_AD_TEST_USER")

    if from_environment:
        return from_environment

    return input("UPN (for example user@example.test): ").strip()


def main() -> int:
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
        help="How many attempts to run in one session (default 1).",
    )
    args = parser.parse_args()

    if args.attempts < 1:
        print("--attempts must be at least 1.", file=sys.stderr)

        return USAGE_PROBLEM

    try:
        config = load_ad_config()
    except ValueError as exc:
        # Configuration errors are safe to print: they describe settings, never secrets.
        print(f"Configuration problem: {exc}", file=sys.stderr)
        print(
            "Required: PENTAIA_AD_HOST. Optional: PENTAIA_AD_PORT (default 636), "
            "PENTAIA_AD_CA_FILE, PENTAIA_AD_CONNECT_TIMEOUT, PENTAIA_AD_RECEIVE_TIMEOUT.",
            file=sys.stderr,
        )

        return EXIT_CODES[AuthOutcome.MISCONFIGURED]

    print(f"Active Directory over LDAPS -> {describe(config)}")
    print("Certificate validation is mandatory; the password is never stored or logged.\n")

    provider = ADAuthProvider(config)
    last_outcome = AuthOutcome.UNAVAILABLE

    for attempt in range(1, args.attempts + 1):
        username = read_username(args.username)

        if not username:
            print("No username supplied.", file=sys.stderr)

            return USAGE_PROBLEM

        # getpass never echoes and the value is not stored anywhere.
        password = getpass.getpass("Password (not echoed): ")

        result = provider.authenticate(username, password)
        last_outcome = result.outcome

        print(f"\nattempt {attempt}: outcome={result.outcome.value}")

        if result.identity is not None:
            print(f"  canonical identity : {result.identity.user_id}")
            print(f"  username           : {result.identity.username}")
            print(f"  display name       : {result.identity.display_name}")
            print(f"  auth source        : {result.identity.auth_source}")
            print(f"  authenticated at   : {result.identity.authenticated_at.isoformat()}")

        print(f"  {GUIDANCE[result.outcome]}\n")

    return EXIT_CODES[last_outcome]


if __name__ == "__main__":
    raise SystemExit(main())

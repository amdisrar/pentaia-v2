"""Automated tests for the AD validation helper, scripts/ad_ldaps_check.py.

These tests are offline and deterministic: the provider is replaced at the script's
single ``build_provider`` seam, so no socket, directory or credential is involved.

**They are not the real LDAPS validation.** Only running the scenarios against a real
Microsoft Entra Domain Services endpoint constitutes that.
"""

import argparse
import importlib.util
from dataclasses import dataclass
from pathlib import Path

import pytest

from pentaia.webapp.auth.ad import (
    CA_FILE_ENV,
    DEFAULT_AD_PORT,
    HOST_ENV,
    MAX_TIMEOUT_SECONDS,
    PORT_ENV,
    UNSUPPORTED_INSECURE_SETTINGS,
    validate_upn_username,
)
from pentaia.webapp.auth.base import AuthOutcome, AuthResult
from pentaia.webapp.identity import AuthenticatedIdentity

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "ad_ldaps_check.py"

REAL_PASSWORD = "correct-horse-battery-staple"
UPN = "user@example.test"
HOST = "dc01.example.test"


def load_script():
    """Load the helper as a module. It is a script, not an installed package."""
    spec = importlib.util.spec_from_file_location("ad_ldaps_check", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


SCRIPT = load_script()


class FakeProvider:
    """Records every bind and replays a scripted sequence of outcomes."""

    def __init__(self, outcomes: list[AuthOutcome]) -> None:
        self._outcomes = list(outcomes)
        self.calls: list[tuple[str, str]] = []

    def authenticate(self, username: object, password: object) -> AuthResult:
        self.calls.append((str(username), str(password)))
        outcome = self._outcomes.pop(0) if self._outcomes else AuthOutcome.UNAVAILABLE

        identity = None
        if outcome is AuthOutcome.SUCCESS:
            identity = AuthenticatedIdentity.from_provider(auth_source="ad", username=username)

        return AuthResult(outcome, identity=identity)


@dataclass
class Harness:
    provider: FakeProvider
    configs: list
    prompts: int
    password: str


@pytest.fixture()
def harness(monkeypatch: pytest.MonkeyPatch):
    """Install a recording provider and controllable prompts, with a valid host."""
    monkeypatch.setenv(HOST_ENV, HOST)
    monkeypatch.setenv("PENTAIA_AD_TEST_USER", UPN)
    monkeypatch.delenv(CA_FILE_ENV, raising=False)
    monkeypatch.delenv(PORT_ENV, raising=False)

    def build(outcomes: list[AuthOutcome]) -> Harness:
        provider = FakeProvider(outcomes)
        state = Harness(provider=provider, configs=[], prompts=0, password=REAL_PASSWORD)

        def build_provider(config):
            state.configs.append(config)

            return provider

        def read_password() -> str:
            state.prompts += 1

            return state.password

        monkeypatch.setattr(SCRIPT, "build_provider", build_provider)
        monkeypatch.setattr(SCRIPT, "read_password", read_password)

        return state

    return build


# --- preserved contract ----------------------------------------------------


def test_exit_codes_are_unchanged() -> None:
    """Probe-mode exit codes are part of the documented contract."""
    assert SCRIPT.EXIT_CODES[AuthOutcome.SUCCESS] == 0
    assert SCRIPT.EXIT_CODES[AuthOutcome.REJECTED] == 1
    assert SCRIPT.EXIT_CODES[AuthOutcome.UNAVAILABLE] == 2
    assert SCRIPT.EXIT_CODES[AuthOutcome.MISCONFIGURED] == 3
    assert SCRIPT.USAGE_PROBLEM == 4
    assert SCRIPT.EXPECTATION_FAILED == 5


def test_the_five_scenarios_are_registered() -> None:
    assert SCRIPT.SCENARIOS == (
        "success",
        "wrong-password",
        "roundtrip",
        "unreachable",
        "untrusted-ca",
    )
    assert set(SCRIPT.SCENARIO_RUNNERS) == set(SCRIPT.SCENARIOS)


def test_probe_mode_still_reports_the_outcome_as_its_exit_code(
    harness, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without --expect the original outcome-derived exit code is returned."""
    state = harness([AuthOutcome.REJECTED])

    code = SCRIPT.main(["--username", UPN])

    assert code == SCRIPT.EXIT_CODES[AuthOutcome.REJECTED] == 1
    assert state.prompts == 1
    assert "attempt 1: outcome=rejected" in capsys.readouterr().out


def test_probe_mode_honours_attempts(harness) -> None:
    state = harness([AuthOutcome.REJECTED, AuthOutcome.REJECTED, AuthOutcome.REJECTED])

    assert SCRIPT.main(["--username", UPN, "--attempts", "3"]) == 1
    assert len(state.provider.calls) == 3


def test_probe_mode_with_expect_asserts_the_outcome(harness) -> None:
    harness([AuthOutcome.REJECTED, AuthOutcome.REJECTED])

    assert SCRIPT.main(["--username", UPN, "--attempts", "2", "--expect", "rejected"]) == 0


def test_probe_mode_with_expect_fails_when_the_outcome_differs(
    harness, capsys: pytest.CaptureFixture[str]
) -> None:
    harness([AuthOutcome.REJECTED])

    code = SCRIPT.main(["--username", UPN, "--expect", "success"])

    assert code == SCRIPT.EXPECTATION_FAILED
    assert "expected=success observed=rejected" in capsys.readouterr().out


def test_probe_mode_reading_the_username_from_the_environment(
    harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = harness([AuthOutcome.SUCCESS])

    assert SCRIPT.main([]) == 0
    assert state.provider.calls[0][0] == UPN


# --- usage problems --------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["--scenario", "bogus"],
        ["--expect", "success", "--scenario", "success"],
        ["--port", "0"],
        ["--port", "70000"],
        ["--timeout", "0"],
        ["--timeout", str(MAX_TIMEOUT_SECONDS + 1)],
        ["--attempts", "0"],
        ["--expect", "nonsense"],
    ],
)
def test_usage_problems_are_reported_without_contacting_a_directory(argv: list[str]) -> None:
    """A usage mistake must not be mistaken for an unavailable directory (exit 2)."""
    assert SCRIPT.main(argv) == SCRIPT.USAGE_PROBLEM


def test_an_unknown_scenario_lists_the_valid_ones(capsys: pytest.CaptureFixture[str]) -> None:
    assert SCRIPT.main(["--scenario", "bogus"]) == SCRIPT.USAGE_PROBLEM
    assert "success" in capsys.readouterr().err


def test_a_configuration_problem_is_exit_three(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(HOST_ENV, "")

    assert SCRIPT.main(["--scenario", "untrusted-ca"]) == 3
    assert "Configuration problem" in capsys.readouterr().err


# --- helpers ---------------------------------------------------------------


def test_the_generated_wrong_password_cannot_be_the_real_one() -> None:
    generated = SCRIPT.generate_wrong_password()

    assert generated
    assert len(generated) >= 24
    assert generated != REAL_PASSWORD
    assert REAL_PASSWORD not in generated
    assert not any(character.isspace() for character in generated)


def test_generated_passwords_are_unique() -> None:
    assert len({SCRIPT.generate_wrong_password() for _ in range(50)}) == 50


def test_the_placeholder_upn_is_a_valid_upn_and_is_reserved() -> None:
    assert validate_upn_username(SCRIPT.PLACEHOLDER_UPN) == SCRIPT.PLACEHOLDER_UPN
    assert SCRIPT.PLACEHOLDER_UPN.endswith(".invalid")


def test_the_unreachable_default_is_a_reserved_non_routable_address() -> None:
    assert SCRIPT.DEFAULT_UNREACHABLE_HOST == "192.0.2.1"


def test_describe_exposes_no_secret() -> None:
    from pentaia.webapp.auth.ad import ADConfig

    described = SCRIPT.describe(ADConfig(host=HOST))

    assert f"host={HOST}" in described
    assert f"port={DEFAULT_AD_PORT}" in described
    assert "ca_file=(system trust store)" in described
    assert REAL_PASSWORD not in described


def test_parsing_an_expected_outcome() -> None:
    assert SCRIPT.parse_expected_outcome("rejected") is AuthOutcome.REJECTED
    assert SCRIPT.parse_expected_outcome("  SUCCESS ") is AuthOutcome.SUCCESS
    assert SCRIPT.parse_expected_outcome("nonsense") is None


# --- configuration resolution ---------------------------------------------


def test_host_port_and_timeout_overrides_are_applied() -> None:
    config = SCRIPT.resolve_config(host="other.example.test", port=1636, timeout=2)

    assert config.host == "other.example.test"
    assert config.port == 1636
    assert config.connect_timeout == 2
    assert config.receive_timeout == 2


def test_dropping_the_ca_bundle_leaves_the_system_trust_store(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("placeholder")
    monkeypatch.setenv(HOST_ENV, HOST)
    monkeypatch.setenv(CA_FILE_ENV, str(ca))

    assert SCRIPT.resolve_config().ca_file == ca
    assert SCRIPT.resolve_config(drop_ca=True).ca_file is None


@pytest.mark.parametrize("variable", UNSUPPORTED_INSECURE_SETTINGS)
def test_an_attempt_to_weaken_transport_security_is_refused(
    monkeypatch: pytest.MonkeyPatch, variable: str
) -> None:
    """The helper inherits the provider's refusal instead of adding its own option."""
    monkeypatch.setenv(variable, "false")

    with pytest.raises(ValueError, match="mandatory"):
        SCRIPT.resolve_config()


def test_an_invalid_port_override_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """The host is set, so this fails on the port rather than on a missing host."""
    monkeypatch.setenv(HOST_ENV, HOST)

    with pytest.raises(ValueError, match=PORT_ENV):
        SCRIPT.resolve_config(port=0)


# --- S1 success ------------------------------------------------------------


def test_s1_passes_on_success_and_prints_the_canonical_identity(
    harness, capsys: pytest.CaptureFixture[str]
) -> None:
    state = harness([AuthOutcome.SUCCESS])

    assert SCRIPT.main(["--scenario", "success", "--username", UPN]) == 0

    out = capsys.readouterr().out
    assert "scenario: success" in out
    assert "expected : success" in out
    assert "observed : success" in out
    assert "verdict  : PASS" in out
    assert f"canonical identity : ad:{UPN}" in out
    assert state.prompts == 1
    assert state.provider.calls == [(UPN, REAL_PASSWORD)]


def test_s1_fails_when_the_credentials_are_refused(harness) -> None:
    harness([AuthOutcome.REJECTED])

    assert SCRIPT.main(["--scenario", "success", "--username", UPN]) == SCRIPT.EXPECTATION_FAILED


# --- S2 wrong password -----------------------------------------------------


def test_s2_passes_when_a_wrong_password_is_refused(
    harness, capsys: pytest.CaptureFixture[str]
) -> None:
    state = harness([AuthOutcome.REJECTED])

    assert SCRIPT.main(["--scenario", "wrong-password", "--username", UPN]) == 0

    out = capsys.readouterr().out
    assert "verdict  : PASS" in out
    # No password is prompted for a negative test.
    assert state.prompts == 0
    sent_username, sent_password = state.provider.calls[0]
    assert sent_username == UPN
    assert sent_password != REAL_PASSWORD
    assert sent_password


def test_s2_fails_when_a_wrong_password_is_accepted(harness) -> None:
    """If this ever passes for real, the positive result means nothing."""
    harness([AuthOutcome.SUCCESS])

    assert SCRIPT.main(["--scenario", "wrong-password", "--username", UPN]) == (
        SCRIPT.EXPECTATION_FAILED
    )


# --- S3 roundtrip ----------------------------------------------------------


def test_s3_runs_both_steps_and_passes(harness, capsys: pytest.CaptureFixture[str]) -> None:
    state = harness([AuthOutcome.SUCCESS, AuthOutcome.REJECTED])

    assert SCRIPT.main(["--scenario", "roundtrip", "--username", UPN]) == 0

    out = capsys.readouterr().out
    assert out.count("verdict  : PASS") == 2
    assert state.prompts == 1
    assert len(state.provider.calls) == 2
    assert state.provider.calls[0] == (UPN, REAL_PASSWORD)
    assert state.provider.calls[1][1] != REAL_PASSWORD


def test_s3_skips_the_second_bind_when_the_first_fails(
    harness, capsys: pytest.CaptureFixture[str]
) -> None:
    """A pointless retry would only cost another failed sign-in."""
    state = harness([AuthOutcome.UNAVAILABLE])

    assert SCRIPT.main(["--scenario", "roundtrip", "--username", UPN]) == (
        SCRIPT.EXPECTATION_FAILED
    )

    assert len(state.provider.calls) == 1
    assert "step 2 skipped" in capsys.readouterr().out


# --- S4 unreachable --------------------------------------------------------


def test_s4_uses_the_documented_unreachable_default(harness) -> None:
    state = harness([AuthOutcome.UNAVAILABLE])

    assert SCRIPT.main(["--scenario", "unreachable"]) == 0

    config = state.configs[0]
    assert config.host == SCRIPT.DEFAULT_UNREACHABLE_HOST
    assert config.connect_timeout == SCRIPT.DEFAULT_UNREACHABLE_TIMEOUT_SECONDS


def test_s4_prompts_for_no_credentials_and_uses_the_placeholder(harness) -> None:
    state = harness([AuthOutcome.UNAVAILABLE])

    assert SCRIPT.main(["--scenario", "unreachable"]) == 0

    assert state.prompts == 0
    assert state.provider.calls[0][0] == SCRIPT.PLACEHOLDER_UPN


def test_s4_honours_a_host_override(harness) -> None:
    state = harness([AuthOutcome.UNAVAILABLE])

    assert SCRIPT.main(["--scenario", "unreachable", "--host", "127.0.0.1", "--timeout", "2"]) == 0

    assert state.configs[0].host == "127.0.0.1"
    assert state.configs[0].connect_timeout == 2


def test_s4_fails_when_the_endpoint_answers(harness) -> None:
    harness([AuthOutcome.SUCCESS])

    assert SCRIPT.main(["--scenario", "unreachable"]) == SCRIPT.EXPECTATION_FAILED


# --- S5 untrusted CA ------------------------------------------------------


def test_s5_runs_without_the_configured_ca_bundle(
    harness, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("placeholder")
    monkeypatch.setenv(CA_FILE_ENV, str(ca))
    state = harness([AuthOutcome.MISCONFIGURED])

    assert SCRIPT.main(["--scenario", "untrusted-ca"]) == 0

    # The CA bundle the operator configured is deliberately not used for this run.
    assert state.configs[0].ca_file is None
    assert state.prompts == 0


def test_s5_fails_when_the_chain_is_trusted_anyway(
    harness, capsys: pytest.CaptureFixture[str]
) -> None:
    """Success here means the run does not demonstrate mandatory verification."""
    harness([AuthOutcome.SUCCESS])

    assert SCRIPT.main(["--scenario", "untrusted-ca"]) == SCRIPT.EXPECTATION_FAILED

    out = capsys.readouterr().out
    assert "does not demonstrate mandatory verification" in out
    assert "openssl s_client" in out


# --- secret handling ------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["--scenario", "success", "--username", UPN],
        ["--scenario", "roundtrip", "--username", UPN],
    ],
)
def test_the_password_never_appears_in_the_output(
    harness, capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    harness([AuthOutcome.SUCCESS, AuthOutcome.REJECTED])

    SCRIPT.main(argv)

    captured = capsys.readouterr()
    assert REAL_PASSWORD not in captured.out
    assert REAL_PASSWORD not in captured.err


def test_the_script_never_reads_a_password_from_the_environment() -> None:
    """Interactive only: an environment variable is readable by other processes."""
    source = SCRIPT_PATH.read_text()

    assert "PENTAIA_AD_TEST_PASSWORD" not in source
    assert "environ.get(\"PENTAIA_AD_PASSWORD\")" not in source
    assert "--password" not in source


def test_the_script_reuses_the_provider_rather_than_an_ldap_client() -> None:
    source = SCRIPT_PATH.read_text()

    assert "import ldap3" not in source
    assert "from ldap3" not in source
    assert "import socket" not in source
    assert "import ssl" not in source
    assert "ADAuthProvider" in source


@pytest.mark.parametrize(
    "forbidden",
    ["CERT_NONE", "check_hostname = False", "verify=False", "--insecure", "skip_verify"],
)
def test_the_script_offers_no_way_to_weaken_verification(forbidden: str) -> None:
    assert forbidden not in SCRIPT_PATH.read_text()


def test_the_script_accepts_argv_so_it_can_be_driven_by_tests() -> None:
    import inspect

    signature = inspect.signature(SCRIPT.main)

    assert "argv" in signature.parameters


def test_the_parser_documents_every_scenario() -> None:
    parser = SCRIPT.build_parser()
    actions = {action.dest: action for action in parser._actions}

    assert "scenario" in actions
    assert "expect" in actions
    for scenario in SCRIPT.SCENARIOS:
        assert scenario in actions["scenario"].help


def test_the_probe_parser_keeps_its_original_options() -> None:
    """Existing usage must keep working exactly as documented."""
    args = SCRIPT.build_parser().parse_args(["--username", UPN, "--attempts", "2"])

    assert isinstance(args, argparse.Namespace)
    assert args.username == UPN
    assert args.attempts == 2
    assert args.scenario is None

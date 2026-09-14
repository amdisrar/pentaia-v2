import pytest

from pentaia import nmap_wrapper
from pentaia.discovery_profiles import (
    MAX_SELECTABLE_PORTS,
    NMAP_DEFAULT_PROFILE,
    NMAP_PARAMETERS,
    NMAP_PROFILES,
    NUCLEI_PARAMETERS,
    build_nmap_options,
    model_parameter_names,
    validate_nmap_ports,
    validate_nmap_profile,
)
from pentaia.tools import nmap_service_scan, nuclei_vulnerability_scan


def _schema_properties(tool) -> set[str]:
    return set(tool.tool_call_schema.model_json_schema()["properties"])


# --- profiles --------------------------------------------------------------


def test_default_profile_preserves_the_original_behaviour() -> None:
    profile = validate_nmap_profile(NMAP_DEFAULT_PROFILE)

    assert profile.name == "service"
    assert profile.options == ("-sV",)


@pytest.mark.parametrize("name", ["service", "quick", "full_tcp", "os"])
def test_known_profiles_are_accepted(name: str) -> None:
    assert validate_nmap_profile(name).name == name


@pytest.mark.parametrize(
    "value",
    ["", "stealth", "-sS", "service; rm -rf /", "SERVICE", None, 7, ["service"]],
)
def test_unknown_profiles_fail_closed(value) -> None:
    with pytest.raises(ValueError, match="Unsupported Nmap profile"):
        validate_nmap_profile(value)


def test_every_profile_option_is_a_code_owned_constant() -> None:
    """A profile must never be able to inject arbitrary option text."""
    for profile in NMAP_PROFILES.values():
        for option in profile.options:
            assert option.startswith("-")
            for unsafe in [";", "|", "&", "`", "$", ">", "<", " ", "\n"]:
                assert unsafe not in option


# --- port selection --------------------------------------------------------


def test_ports_are_deduplicated_and_sorted() -> None:
    assert validate_nmap_ports([443, 22, 443, 80]) == [22, 80, 443]


def test_no_ports_is_allowed() -> None:
    assert validate_nmap_ports(None) == []
    assert validate_nmap_ports([]) == []


@pytest.mark.parametrize(
    "value",
    [
        "22",
        [0],
        [65536],
        [-1],
        [True],
        [22.5],
        ["22"],
        [None],
        {"22": True},
        22,
    ],
)
def test_invalid_port_selections_fail_closed(value) -> None:
    with pytest.raises(ValueError, match="Nmap port"):
        validate_nmap_ports(value)


def test_port_selection_is_bounded() -> None:
    with pytest.raises(ValueError, match="At most"):
        validate_nmap_ports(list(range(1, MAX_SELECTABLE_PORTS + 2)))


def test_port_selection_is_rejected_by_profiles_that_do_not_accept_it() -> None:
    profile = validate_nmap_profile("full_tcp")

    with pytest.raises(ValueError, match="does not accept a port selection"):
        build_nmap_options(profile, [22])


# --- native command construction -------------------------------------------


def test_profile_without_ports_builds_the_expected_options() -> None:
    assert build_nmap_options(validate_nmap_profile("quick"), []) == ["-T4", "-F"]


def test_profile_with_ports_builds_the_expected_options() -> None:
    options = build_nmap_options(validate_nmap_profile("service"), [22, 80])

    assert options == ["-sV", "-p", "22,80"]


def test_wrapper_emits_only_code_owned_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_run_command(command: str, timeout: int):
        captured["command"] = command
        captured["timeout"] = timeout
        return "ok", "", 0

    monkeypatch.setattr(nmap_wrapper, "run_command", fake_run_command)

    nmap_wrapper.nmap_scan("172.16.0.64", profile="service", ports=[80, 22])

    assert captured["command"] == "nmap -sV -p 22,80 172.16.0.64"
    assert captured["timeout"] == 120


def test_wrapper_defaults_to_the_service_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_run_command(command: str, timeout: int):
        captured["command"] = command
        return "", "", 0

    monkeypatch.setattr(nmap_wrapper, "run_command", fake_run_command)

    nmap_wrapper.nmap_scan("172.16.0.64")

    # Unchanged from the original behaviour: `nmap -sV <target>`.
    assert captured["command"] == "nmap -sV 172.16.0.64"


@pytest.mark.parametrize(
    ("profile", "ports"),
    [
        ("full_tcp", [22]),
        ("stealth", None),
        ("service", [99999]),
        ("service", ["-sS"]),
    ],
)
def test_invalid_requests_never_reach_the_executor(
    monkeypatch: pytest.MonkeyPatch,
    profile,
    ports,
) -> None:
    called = False

    def fake_run_command(command: str, timeout: int):
        nonlocal called
        called = True
        return "", "", 0

    monkeypatch.setattr(nmap_wrapper, "run_command", fake_run_command)

    with pytest.raises(ValueError):
        nmap_wrapper.nmap_scan("172.16.0.64", profile=profile, ports=ports)

    assert called is False


# --- tool surface ----------------------------------------------------------


def test_nmap_tool_reports_validation_failures_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 99999 is a valid integer, so it passes the schema and reaches the wrapper's
    # range check, which must fail closed with a concise message.
    result = nmap_service_scan.invoke({"target": "172.16.0.64", "ports": [99999]})

    assert "Target or scan-option validation failed" in result
    assert "between 1 and 65535" in result


def test_profile_is_constrained_to_the_allowlist_in_the_schema() -> None:
    """An unknown profile is rejected by the tool schema before any code runs."""
    schema = nmap_service_scan.tool_call_schema.model_json_schema()
    profile = schema["properties"]["profile"]

    allowed = set(profile.get("enum") or [])

    assert allowed == set(NMAP_PROFILES)
    assert "stealth" not in allowed


# --- parameter ownership ---------------------------------------------------


def test_nmap_tool_exposes_exactly_the_model_owned_parameters() -> None:
    """No parameter may reach the model without an explicit ownership entry."""
    assert _schema_properties(nmap_service_scan) == model_parameter_names(NMAP_PARAMETERS)


def test_nuclei_tool_exposes_exactly_the_model_owned_parameters() -> None:
    assert _schema_properties(nuclei_vulnerability_scan) == model_parameter_names(
        NUCLEI_PARAMETERS
    )


def test_no_registry_entry_claims_model_ownership_for_a_hidden_parameter() -> None:
    """Runtime- and code-owned values must never be model-selectable."""
    for registry in (NMAP_PARAMETERS, NUCLEI_PARAMETERS):
        for parameter in registry:
            assert parameter.ownership in {"model", "runtime", "code"}
            assert parameter.description


def test_tool_schema_offers_no_free_form_option_fields() -> None:
    """The failure mode this architecture exists to prevent."""
    forbidden = {
        "extra_args",
        "raw_options",
        "command",
        "native_flags",
        "options",
        "flags",
    }

    for tool in (nmap_service_scan, nuclei_vulnerability_scan):
        assert not (_schema_properties(tool) & forbidden)

from pathlib import Path

import pytest

from pentaia.phase3_artifact import (
    ARTIFACT_DIRECTORY,
    ARTIFACT_PREFIX,
    ARTIFACT_SUCCESS_MARKER,
    VerificationArtifact,
    artifact_content,
    artifact_path,
    artifact_verified,
    build_write_command,
    session_digest,
)
from pentaia.phase3_session import session_name

ACTION = "validate_vsftpd_234_backdoor"
TARGET = "172.16.0.64"
TIMESTAMP = "2026-09-14T20:00:00Z"


def _content() -> str:
    return artifact_content(action_id=ACTION, target=TARGET, timestamp=TIMESTAMP)


# --- path and identity -----------------------------------------------------


def test_digest_is_stable_and_matches_the_console_session() -> None:
    digest = session_digest(action_id=ACTION, target=TARGET)

    assert digest == session_digest(action_id=ACTION, target=TARGET)
    assert len(digest) == 12
    # The marker path must be predictable from the action alone, so it uses the
    # same digest as the held-console session name.
    assert session_name(action_id=ACTION, target=TARGET).endswith(digest)


def test_path_is_predictable_and_confined_to_tmp() -> None:
    path = artifact_path(action_id=ACTION, target=TARGET)

    assert path == f"{ARTIFACT_DIRECTORY}/{ARTIFACT_PREFIX}-{session_digest(action_id=ACTION, target=TARGET)}.txt"
    assert path.startswith(f"{ARTIFACT_DIRECTORY}/")


def test_path_contains_no_shell_metacharacters() -> None:
    path = artifact_path(action_id=ACTION, target=TARGET)

    for unsafe in [";", "|", "&", "`", "$", ">", "<", " ", "'", '"', "\n"]:
        assert unsafe not in path


def test_different_targets_get_different_markers() -> None:
    assert artifact_path(action_id=ACTION, target="172.16.0.64") != artifact_path(
        action_id=ACTION, target="172.16.0.65"
    )


# --- content ---------------------------------------------------------------


def test_content_is_harmless_and_informational() -> None:
    content = _content()

    assert content.startswith(ARTIFACT_SUCCESS_MARKER)
    assert f"Session: {session_digest(action_id=ACTION, target=TARGET)}" in content
    assert f"Target: {TARGET}" in content
    assert f"Action: {ACTION}" in content
    assert f"Timestamp: {TIMESTAMP}" in content


def test_content_carries_no_credentials_or_commands() -> None:
    content = _content().lower()

    for forbidden in ["password", "key", "token", "rm -rf", "curl", "wget"]:
        assert forbidden not in content


# --- command construction --------------------------------------------------


def test_write_command_writes_then_reads_back() -> None:
    path = artifact_path(action_id=ACTION, target=TARGET)
    command = build_write_command(path=path, content=_content())

    assert command.startswith("sessions -c \"")
    assert command.endswith("\"")
    assert "echo" in command
    assert "cat" in command
    assert path in command


def test_write_command_never_contains_the_contiguous_marker() -> None:
    """The property that makes the read-back meaningful evidence.

    If the marker text appeared verbatim in the command we typed, seeing it in the
    console would prove nothing: it could simply be the command echoed back. The
    contents are therefore passed as separate printf arguments.
    """
    path = artifact_path(action_id=ACTION, target=TARGET)
    content = _content()
    command = build_write_command(path=path, content=content)

    assert content not in command
    for line in content.splitlines():
        assert line in command  # each line is present...
    # ...but never as the contiguous multi-line block the file must produce.
    assert "\n".join(content.splitlines()[:2]) not in command


def test_the_shell_flag_is_used_not_the_meterpreter_flag() -> None:
    """-C is Meterpreter-only and skips a command shell outright.

    Observed live: `sessions -C "..."` answered
    "[-] Session #1 is not a Meterpreter shell. Skipping..." and wrote nothing.
    """
    from pentaia.phase3_artifact import CONSOLE_RUN_FLAG

    command = build_write_command(path="/tmp/x", content=_content())

    assert CONSOLE_RUN_FLAG == "-c"
    assert command.startswith("sessions -c ")
    assert "sessions -C " not in command


def test_the_module_exposes_no_way_to_delete_the_marker() -> None:
    """PentAiA writes the proof marker and deliberately never removes it.

    Removing it stays the operator's decision on the target, so the module must not
    offer a builder that would let a future change quietly erase the evidence.
    """
    from pentaia import phase3_artifact

    assert not hasattr(phase3_artifact, "build_cleanup_command")

    source = phase3_artifact.__file__
    assert source is not None
    assert "rm -f" not in Path(source).read_text()


def test_commands_reject_content_that_would_break_the_console_argument() -> None:
    with pytest.raises(ValueError, match="unsafe"):
        build_write_command(path="/tmp/x", content="PAYLOAD$(id)MARKER")


# --- verification ----------------------------------------------------------


def test_verified_only_when_the_read_back_is_present() -> None:
    content = _content()
    pane = f"msf exploit(unix/ftp/vsftpd_234_backdoor) > sessions -C \"...\"\n{content}\nmsf > "

    assert artifact_verified(pane_text=pane, content=content) is True


def test_not_verified_when_only_the_command_was_echoed() -> None:
    """A command echo must never be mistaken for proof the file was written."""
    path = artifact_path(action_id=ACTION, target=TARGET)
    content = _content()
    pane = f"msf > {build_write_command(path=path, content=content)}\nmsf > "

    assert artifact_verified(pane_text=pane, content=content) is False


@pytest.mark.parametrize("pane", ["", None, 7, "unrelated output"])
def test_not_verified_for_unusable_console_text(pane) -> None:
    assert artifact_verified(pane_text=pane, content=_content()) is False


def test_verification_requires_expected_content() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        artifact_verified(pane_text="anything", content="")


# --- result shape ----------------------------------------------------------


def test_result_serializes_for_evidence() -> None:
    artifact = VerificationArtifact(
        path="/tmp/pentaia-poc-abc.txt",
        content=_content(),
        created=True,
        verified=True,
        evidence="ok",
    )

    payload = artifact.to_dict()

    assert payload["path"] == "/tmp/pentaia-poc-abc.txt"
    assert payload["created"] is True
    assert payload["verified"] is True

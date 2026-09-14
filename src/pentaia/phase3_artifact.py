"""Code-owned proof-of-success artifact for a validated Phase 3 session.

After a supported action establishes a session, PentAiA leaves a small, harmless
marker on the authorized target so a successful validation produces evidence *on
the box* and not only in a console pane.

Everything about the artifact is code-owned: the path, the contents and the write
command. The model supplies none of it, and the marker is part of the action the
human already approved. PentAiA never removes the marker afterwards: it is the
evidence, and deleting it stays the operator's decision on the target.

This module is deliberately pure -- no I/O, no tmux, no SSH -- so the command
construction and the read-back verification are testable in isolation. The session
module performs the actual send and capture.
"""

import hashlib
import shlex
from dataclasses import asdict, dataclass
from typing import Any

ARTIFACT_DIRECTORY = "/tmp"
ARTIFACT_PREFIX = "pentaia-poc"
ARTIFACT_SUCCESS_MARKER = "PENTAIA: POC SUCCESSFUL"

# Metasploit's "sessions -c" runs a shell command on a session, while "-C" runs a
# *Meterpreter* command. Every predefined action here yields a command shell, and
# "-C" skips those outright with:
#   [-] Session #N is not a Meterpreter shell. Skipping...
# so verification could never succeed. With no "-i" the command runs on every
# session in the console, which is exactly one by construction: the console is
# created per action and target, and a second one for the same pair is refused.
CONSOLE_RUN_FLAG = "-c"

# Characters that would break out of the double-quoted msfconsole argument.
_UNSAFE_INNER_CHARS = ('"', "$", "`", "\\")


@dataclass(frozen=True)
class VerificationArtifact:
    """The outcome of writing and reading back one proof-of-success marker."""

    path: str
    content: str
    created: bool
    verified: bool
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def session_digest(*, action_id: str, target: str) -> str:
    """Stable short identifier for one action against one target.

    Matches the digest used in the held-console session name, so the marker path
    is predictable from the action alone and does not depend on a runtime uuid.
    """
    return hashlib.sha256(f"{action_id}:{target}".encode()).hexdigest()[:12]


def artifact_path(*, action_id: str, target: str) -> str:
    """The approved, predictable location of the marker on the target."""
    digest = session_digest(action_id=action_id, target=target)

    return artifact_path_for_digest(digest)


def artifact_path_for_digest(digest: str) -> str:
    """The marker path for an already computed session digest."""
    if not digest:
        raise ValueError("A session digest is required to locate the marker.")

    return f"{ARTIFACT_DIRECTORY}/{ARTIFACT_PREFIX}-{digest}.txt"


def artifact_content(*, action_id: str, target: str, timestamp: str) -> str:
    """The harmless, informational contents of the marker."""
    digest = session_digest(action_id=action_id, target=target)

    return "\n".join(
        [
            ARTIFACT_SUCCESS_MARKER,
            f"Session: {digest}",
            f"Target: {target}",
            f"Action: {action_id}",
            f"Timestamp: {timestamp}",
        ]
    )


def _require_console_safe(inner: str) -> str:
    for unsafe in _UNSAFE_INNER_CHARS:
        if unsafe in inner:
            raise ValueError(
                "Artifact command contains a character that is unsafe inside the console argument."
            )

    return inner


def build_write_command(*, path: str, content: str) -> str:
    """Build the console line that writes the marker and reads it back.

    The contents are written one quoted line at a time rather than as a single
    literal string. That matters for verification: the contiguous marker text
    therefore never appears in the command we typed, so seeing it in the console
    can only mean the file was written *and* read back.
    """
    lines = content.splitlines()
    if not lines:
        raise ValueError("Artifact content must not be empty.")

    quoted_path = shlex.quote(path)
    parts = [f"echo {shlex.quote(lines[0])} > {quoted_path}"]
    parts += [f"echo {shlex.quote(line)} >> {quoted_path}" for line in lines[1:]]
    parts.append(f"cat {quoted_path}")

    return f'sessions {CONSOLE_RUN_FLAG} "{_require_console_safe(" && ".join(parts))}"'


def artifact_verified(*, pane_text: object, content: str) -> bool:
    """True only when the console shows the marker that was just written.

    The command is built so its own text cannot produce this match, so a positive
    result means the target really did write and return the file. A failure here is
    reported plainly and never treated as proof.
    """
    if not isinstance(pane_text, str) or not pane_text:
        return False

    if not content:
        raise ValueError("Expected artifact content must not be empty.")

    return content in pane_text

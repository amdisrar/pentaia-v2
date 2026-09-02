import os
import socket
import logging

import paramiko
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


def run_command(command: str, timeout: int = 30) -> tuple[str, str, int]:
    host = os.environ["KALI_HOST"]
    port = int(os.getenv("KALI_PORT", "22"))
    username = os.environ["KALI_USERNAME"]
    key_path = os.environ["KALI_SSH_KEY"]

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

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
            logger.info("Executing remote command: %s", command)

            _, stdout, stderr = client.exec_command(
                command,
                timeout=timeout,
            )

            exit_code = stdout.channel.recv_exit_status()

            logger.info(
                "Remote command completed with exit code %s",
                exit_code,
            )

            return (
                stdout.read().decode().strip(),
                stderr.read().decode().strip(),
                exit_code,
            )

        except socket.timeout as exc:
            logger.exception(
                "Remote command timed out after %s seconds",
                timeout,
            )
            raise RuntimeError(
                f"Remote command timed out after {timeout} seconds."
            ) from exc

    finally:
        client.close()
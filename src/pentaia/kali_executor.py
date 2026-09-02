import os

import paramiko
from dotenv import load_dotenv

load_dotenv()


def run_command(command: str, timeout: int = 30) -> tuple[str, str, int]:
    host = os.environ["KALI_HOST"]
    port = int(os.getenv("KALI_PORT", "22"))
    username = os.environ["KALI_USERNAME"]
    key_path = os.environ["KALI_SSH_KEY"]

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            key_filename=key_path,
            timeout=10,
        )

        stdin, stdout, stderr = client.exec_command(
            command,
            timeout=timeout,
        )

        exit_code = stdout.channel.recv_exit_status()

        return (
            stdout.read().decode().strip(),
            stderr.read().decode().strip(),
            exit_code,
        )

    finally:
        client.close()
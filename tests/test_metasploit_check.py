from pentaia import metasploit_check


def test_metasploit_check_reports_available(monkeypatch):
    monkeypatch.setattr(
        metasploit_check,
        "run_command",
        lambda command, timeout=60: (
            "/usr/bin/msfconsole\nFramework Version: 6.4.70-dev",
            "",
            0,
        ),
    )

    result = metasploit_check.check_metasploit()

    assert result["available"] is True
    assert result["exit_code"] == 0
    assert "/usr/bin/msfconsole" in str(result["stdout"])
    assert "Framework Version" in str(result["stdout"])


def test_metasploit_check_reports_missing(monkeypatch):
    monkeypatch.setattr(
        metasploit_check,
        "run_command",
        lambda command, timeout=60: (
            "",
            "command not found",
            127,
        ),
    )

    result = metasploit_check.check_metasploit()

    assert result["available"] is False
    assert result["exit_code"] == 127
    assert result["stderr"] == "command not found"


def test_metasploit_check_uses_harmless_status_command(monkeypatch):
    captured: dict[str, object] = {}

    def fake_run_command(command: str, timeout: int = 60):
        captured["command"] = command
        captured["timeout"] = timeout
        return "/usr/bin/msfconsole\nFramework Version: test", "", 0

    monkeypatch.setattr(metasploit_check, "run_command", fake_run_command)

    metasploit_check.check_metasploit()

    assert captured["command"] == "command -v msfconsole && msfconsole --version"
    assert captured["timeout"] == 60

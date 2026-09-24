"""Dependency and execution-boundary tests for the Phase 4 web layer.

Two rules from the Phase 4 architecture are enforced here at source level rather than
at runtime, so they hold for code paths a test never exercises:

1. The dependency direction is one-way. The web layer may import the Phase 1-3 core;
   the core must never import the web layer. Without this, Phase 1-3 gradually becomes
   dependent on FastAPI and browser sessions.
2. The web layer is not an execution path. Handlers must not import the SSH executor,
   the tool wrappers, or ``subprocess``/``paramiko`` directly, so the browser cannot
   become a second route to Kali. Reaching Kali stays behind the existing controlled
   wrappers.
"""

import ast
from pathlib import Path

import pytest

import pentaia

SOURCE_ROOT = Path(pentaia.__file__).resolve().parent
WEBAPP_ROOT = SOURCE_ROOT / "webapp"

# Modules the Phase 1-3 core must never depend on.
WEB_LAYER_MODULES = ("fastapi", "starlette", "uvicorn", "pentaia.webapp")

# Modules the web layer must never import directly. Note that importing the agent
# graph remains allowed: conversation integration (P4-11) legitimately goes through
# the existing service layer, which owns the wrappers.
EXECUTION_MODULES = (
    "subprocess",
    "paramiko",
    "pentaia.kali_executor",
    "pentaia.nmap_wrapper",
    "pentaia.nuclei_wrapper",
    "pentaia.metasploit_wrapper",
    "pentaia.tools",
)


def _python_files(root: Path) -> list[Path]:
    return sorted(
        path for path in root.rglob("*.py") if "__pycache__" not in path.parts
    )


def _core_files() -> list[Path]:
    return [
        path for path in _python_files(SOURCE_ROOT) if WEBAPP_ROOT not in path.parents
    ]


def _webapp_files() -> list[Path]:
    return _python_files(WEBAPP_ROOT)


def _imported_modules(path: Path) -> set[str]:
    """Every module name imported by one file, including ``from`` targets."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
            modules.update(f"{node.module}.{alias.name}" for alias in node.names)

    return modules


def _offending(modules: set[str], prefixes: tuple[str, ...]) -> list[str]:
    return sorted(
        module
        for module in modules
        if any(
            module == prefix or module.startswith(f"{prefix}.")
            for prefix in prefixes
        )
    )


@pytest.mark.parametrize("path", _core_files(), ids=lambda path: path.name)
def test_the_core_never_imports_the_web_layer(path: Path) -> None:
    offenders = _offending(_imported_modules(path), WEB_LAYER_MODULES)

    assert not offenders, f"{path} must not import the web layer: {offenders}"


@pytest.mark.parametrize("path", _webapp_files(), ids=lambda path: path.name)
def test_the_web_layer_never_imports_an_execution_module(path: Path) -> None:
    offenders = _offending(_imported_modules(path), EXECUTION_MODULES)

    assert not offenders, f"{path} must not import: {offenders}"


def test_the_boundary_tests_actually_inspect_the_code() -> None:
    """Guard against the tests silently passing because they found no files."""
    core = _core_files()
    webapp = _webapp_files()

    assert len(core) > 20
    assert {"app.py", "config.py", "__init__.py"} <= {path.name for path in webapp}
    assert WEBAPP_ROOT not in {path.parent for path in core}


def test_the_existing_cli_entry_point_still_imports_and_dispatches() -> None:
    """P4-02 must not disturb the current CLI.

    Only the import contract and argument dispatch are checked. Running an agent turn
    needs Gemini and a lab target, which a unit test must never touch, and
    ``pentaia session list`` would SSH to Kali.
    """
    from pentaia.session_cli import run_session_command

    assert callable(pentaia.main)

    captured: list[str] = []
    assert run_session_command([], output=captured.append) == 2
    assert any("Usage: pentaia session" in line for line in captured)


def test_the_web_layer_is_not_wired_into_the_cli() -> None:
    """The web application must be additive; the CLI must not depend on it."""
    cli_modules = _imported_modules(SOURCE_ROOT / "__init__.py")

    assert not _offending(cli_modules, ("pentaia.webapp", "fastapi", "uvicorn"))

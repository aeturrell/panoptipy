"""Tests for registry.py module."""

import pytest

from panoptipy.checks import (
    Check,
    CheckResult,
    CheckStatus,
    CognitiveComplexityCheck,
    DocstringCheck,
    HasTestsCheck,
    LargeFilesCheck,
    NotebookOutputCheck,
    PrivateKeyCheck,
    PydoclintCheck,
    PyprojectTomlValidateCheck,
    ReadmeCheck,
    RuffFormatCheck,
    RuffLintingCheck,
    SqlLintingCheck,
)
from panoptipy.config import Config
from panoptipy.registry import CheckRegistry


class DummyCheck(Check):
    """A dummy check for testing."""

    def __init__(self):
        super().__init__("dummy_check", "A dummy check for testing")

    def run(self, codebase):
        return CheckResult(
            check_id=self.check_id,
            status=CheckStatus.PASS,
            message="Dummy check passed",
        )


@pytest.fixture
def registry():
    """Create a check registry for testing."""
    return CheckRegistry()


@pytest.fixture
def registry_with_config():
    """Create a check registry with config for testing."""
    config = Config(Config.DEFAULT_CONFIG.copy())
    return CheckRegistry(config=config)


def test_registry_init(registry):
    """Test registry initialization."""
    assert registry.checks == {}
    assert registry.plugin_manager is not None
    assert registry.config is None


def test_registry_init_with_config(registry_with_config):
    """Test registry initialization with config."""
    assert registry_with_config.config is not None
    assert isinstance(registry_with_config.config, Config)


def test_register_check(registry):
    """Test registering a check."""
    check = DummyCheck()
    registry.register(check)

    assert "dummy_check" in registry.checks
    assert registry.checks["dummy_check"] == check


def test_register_multiple_checks(registry):
    """Test registering multiple checks."""
    check1 = DummyCheck()

    class AnotherCheck(Check):
        def __init__(self):
            super().__init__("another_check", "Another check")

        def run(self, codebase):
            return CheckResult("another_check", CheckStatus.PASS, "Pass")

    check2 = AnotherCheck()

    registry.register(check1)
    registry.register(check2)

    assert len(registry.checks) == 2
    assert "dummy_check" in registry.checks
    assert "another_check" in registry.checks


def test_load_builtin_checks(registry_with_config):
    """Test loading built-in checks."""
    registry_with_config.load_builtin_checks()

    # Check that all built-in checks are registered
    expected_checks = [
        "docstrings",
        "ruff_linting",
        "ruff_format",
        "large_files",
        "private_key",
        "notebook_output",
        "pydoclint",
        "pyproject_toml_validate",
        "has_tests",
        "readme",
        "sql_linting",
        "cognitive_complexity",
    ]

    for check_id in expected_checks:
        assert check_id in registry_with_config.checks


def test_load_builtin_checks_types(registry_with_config):
    """Test that built-in checks have correct types."""
    registry_with_config.load_builtin_checks()

    assert isinstance(registry_with_config.checks["docstrings"], DocstringCheck)
    assert isinstance(registry_with_config.checks["ruff_linting"], RuffLintingCheck)
    assert isinstance(registry_with_config.checks["ruff_format"], RuffFormatCheck)
    assert isinstance(registry_with_config.checks["large_files"], LargeFilesCheck)
    assert isinstance(registry_with_config.checks["private_key"], PrivateKeyCheck)
    assert isinstance(
        registry_with_config.checks["notebook_output"], NotebookOutputCheck
    )
    assert isinstance(registry_with_config.checks["pydoclint"], PydoclintCheck)
    assert isinstance(
        registry_with_config.checks["pyproject_toml_validate"],
        PyprojectTomlValidateCheck,
    )
    assert isinstance(registry_with_config.checks["has_tests"], HasTestsCheck)
    assert isinstance(registry_with_config.checks["readme"], ReadmeCheck)
    assert isinstance(registry_with_config.checks["sql_linting"], SqlLintingCheck)
    assert isinstance(
        registry_with_config.checks["cognitive_complexity"], CognitiveComplexityCheck
    )


def test_register_overwrites_check(registry):
    """Test that registering a check with same ID overwrites the previous one."""
    check1 = DummyCheck()
    registry.register(check1)

    class NewDummyCheck(Check):
        def __init__(self):
            super().__init__("dummy_check", "New dummy check")

        def run(self, codebase):
            return CheckResult("dummy_check", CheckStatus.FAIL, "New dummy check")

    check2 = NewDummyCheck()
    registry.register(check2)

    assert len(registry.checks) == 1
    assert registry.checks["dummy_check"] == check2
    assert registry.checks["dummy_check"].description == "New dummy check"


def test_load_plugins(registry):
    """Test loading plugins (should not error even if no plugins installed)."""
    # This should not raise an error even if no plugins are installed
    registry.load_plugins()

    # The method should complete without error
    assert True


def test_registry_plugin_manager_hookspecs(registry):
    """Test that plugin manager has correct hook specifications."""

    # Check that the hook spec is registered
    assert registry.plugin_manager.project_name == "panoptipy"


def test_registry_checks_are_check_instances(registry_with_config):
    """Test that all registered checks are Check instances."""
    registry_with_config.load_builtin_checks()

    for check_id, check in registry_with_config.checks.items():
        assert isinstance(check, Check)
        assert hasattr(check, "run")
        assert hasattr(check, "check_id")
        assert hasattr(check, "description")

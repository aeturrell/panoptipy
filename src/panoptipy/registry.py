from typing import Optional

import pluggy

from .checks import (
    Check,
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
from .config import Config

# Define a hook specification namespace
hookspec = pluggy.HookspecMarker("panoptipy")
hookimpl = pluggy.HookimplMarker("panoptipy")


class PanoptiPyHooks:
    """Hook specifications for panoptipy."""

    @hookspec
    def register_checks(self, registry):
        """Register custom checks with the registry."""


# In your registry module
class CheckRegistry:
    """Registry for code quality checks."""

    def __init__(self, config: Optional[Config] = None):
        self.checks = {}
        self.plugin_manager = pluggy.PluginManager("panoptipy")
        self.plugin_manager.add_hookspecs(PanoptiPyHooks)
        self.config = config

    def register(self, check: Check):
        """Register a check with the registry."""
        self.checks[check.check_id] = check

    def load_plugins(self):
        """Load all plugins."""
        self.plugin_manager.load_setuptools_entrypoints("panoptipy")
        self.plugin_manager.hook.register_checks(registry=self)

    def load_builtin_checks(self):
        """Load the built-in checks."""
        # Register built-in checks
        self.register(DocstringCheck())
        self.register(RuffLintingCheck())
        self.register(RuffFormatCheck())
        self.register(LargeFilesCheck(config=self.config))
        self.register(PrivateKeyCheck())
        self.register(NotebookOutputCheck())
        self.register(PydoclintCheck())
        self.register(PyprojectTomlValidateCheck())
        self.register(HasTestsCheck())
        self.register(ReadmeCheck(config=self.config))
        self.register(SqlLintingCheck())
        # Add extra checks here

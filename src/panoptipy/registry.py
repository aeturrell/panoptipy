import pluggy

from .checks.base import (
    Check,
    DocstringCheck,
    LargeFilesCheck,
    NotebookOutputCheck,
    PrivateKeyCheck,
    PydoclintCheck,
    PyprojectTomlValidateCheck,
    RuffFormatCheck,
    RuffLintingCheck,
)

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

    def __init__(self):
        self.checks = {}
        self.plugin_manager = pluggy.PluginManager("panoptipy")
        self.plugin_manager.add_hookspecs(PanoptiPyHooks)

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
        self.register(LargeFilesCheck())
        self.register(PrivateKeyCheck())
        self.register(NotebookOutputCheck())
        self.register(PydoclintCheck())
        self.register(PyprojectTomlValidateCheck())
        # Register more built-in checks here as they're added

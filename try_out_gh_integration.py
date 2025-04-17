from src.panoptipy.registry import CheckRegistry
from src.panoptipy.config import Config
from src.panoptipy.github_integration import GithubScanner, GithubReporter

from pathlib import Path

# Initialize your check registry and config
registry = CheckRegistry()
registry.load_builtin_checks()
config_in = None
config = Config.load(Path(config_in) if config_in else None)

# Create GitHub scanner with your GitHub token
scanner = GithubScanner(
    registry=registry,
    config=config,
    token="your-github-token"
)

# Scan all repositories for a team
results = scanner.scan_team_repos(
    org_name="your-organization",
    team_name="your-team",
    skip_forks=True,
    skip_archived=True
)

# Generate a detailed report
reporter = GithubReporter()
report = reporter.generate_detailed_report(results)

# Process the report as needed (e.g., save to file, display in UI)
import json
with open("scan_report.json", "w") as f:
    json.dump(report, f, indent=2)
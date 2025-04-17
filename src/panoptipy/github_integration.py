"""GitHub integration module for panoptipy using GitHub GraphQL API.

This module provides functionality to scan multiple repositories from a GitHub
organization and team using the panoptipy scanner and GitHub's GraphQL API.
"""

import logging
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union, Any

from git import Repo, GitCommandError
import requests

from .core import Scanner
from .checks.base import CheckResult
from .config import Config
from .rating import CodebaseRating
from .registry import CheckRegistry

logger = logging.getLogger(__name__)


@dataclass
class RepoScanResult:
    """Result of scanning a single repository."""

    repo_name: str
    repo_url: str
    check_results: List[CheckResult]
    rating: CodebaseRating
    error: Optional[str] = None


@dataclass
class GithubScanResult:
    """Results from scanning GitHub repositories."""

    org_name: str
    team_name: str
    repo_results: Dict[str, RepoScanResult] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    @property
    def successful_repos(self) -> List[str]:
        """List repositories that were successfully scanned."""
        return [
            name
            for name, result in self.repo_results.items()
            if result.error is None
        ]

    @property
    def failed_repos(self) -> List[str]:
        """List repositories that failed to scan."""
        return [
            name
            for name, result in self.repo_results.items()
            if result.error is not None
        ]


class GitHubGraphQLClient:
    """Client for GitHub GraphQL API."""

    def __init__(self, token: str, api_url: str = "https://api.github.com/graphql"):
        """Initialize the GraphQL client.

        Args:
            token: GitHub personal access token
            api_url: GitHub GraphQL API URL (default for GitHub.com)
        """
        self.token = token
        self.api_url = api_url
        self.headers = {"Authorization": f"Bearer {token}"}

    def execute(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute a GraphQL query.

        Args:
            query: GraphQL query string
            variables: Variables for the query

        Returns:
            Response data from GitHub

        Raises:
            ValueError: If the query fails
        """
        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        response = requests.post(
            self.api_url,
            json=payload,
            headers=self.headers
        )

        if response.status_code != 200:
            raise ValueError(
                f"Query failed with status code {response.status_code}: {response.text}"
            )

        result = response.json()
        if "errors" in result:
            errors = result["errors"]
            raise ValueError(f"GraphQL query returned errors: {errors}")

        return result["data"]


class GithubScanner:
    """Scanner for GitHub repositories belonging to a specific team using GraphQL API."""

    def __init__(
        self,
        registry: CheckRegistry,
        config: Config,
        token: str,
        api_url: str = "https://api.github.com/graphql",
    ):
        """Initialize the GitHub scanner.

        Args:
            registry: Registry containing checks to run
            config: Configuration for the scanner
            token: GitHub personal access token with appropriate permissions
            api_url: GitHub GraphQL API URL (optional, for GitHub Enterprise)
        """
        self.registry = registry
        self.config = config
        self.token = token
        self.scanner = Scanner(registry, config)
        self.client = GitHubGraphQLClient(token, api_url)

    def _get_team_id(self, org_name: str, team_name: str) -> str:
        """Get the Node ID of a team using GraphQL.

        Args:
            org_name: Name of the GitHub organization
            team_name: Name of the team within the organization

        Returns:
            The team's Node ID

        Raises:
            ValueError: If team or organization not found
        """
        query = """
        query GetTeamId($org: String!, $team: String!) {
          organization(login: $org) {
            team(slug: $team) {
              id
            }
          }
        }
        """
        
        # Convert team name to slug format (lowercase, hyphens)
        team_slug = team_name.lower().replace(" ", "-")
        
        variables = {
            "org": org_name,
            "team": team_slug
        }
        
        try:
            data = self.client.execute(query, variables)
            
            if not data.get("organization"):
                raise ValueError(f"Organization not found: {org_name}")
                
            if not data["organization"].get("team"):
                raise ValueError(f"Team '{team_name}' not found in organization '{org_name}'")
                
            return data["organization"]["team"]["id"]
        except Exception as e:
            logger.error(f"Error getting team ID: {e}")
            raise ValueError(f"Failed to get team ID: {str(e)}")

    def _get_team_repos(self, team_id: str, skip_forks: bool = True, skip_archived: bool = True) -> List[Dict[str, Any]]:
        """Get repositories accessible to the specified team using GraphQL.

        Args:
            team_id: Node ID of the GitHub team
            skip_forks: Whether to skip repositories that are forks
            skip_archived: Whether to skip archived repositories

        Returns:
            List of repository information dictionaries

        Raises:
            ValueError: If API request fails
        """
        query = """
        query GetTeamRepos($teamId: ID!, $cursor: String) {
          node(id: $teamId) {
            ... on Team {
              repositories(first: 100, after: $cursor) {
                pageInfo {
                  hasNextPage
                  endCursor
                }
                nodes {
                  name
                  url
                  sshUrl
                  isArchived
                  isFork
                  isPrivate
                }
              }
            }
          }
        }
        """
        
        all_repos = []
        cursor = None
        has_next_page = True
        
        while has_next_page:
            variables = {
                "teamId": team_id,
                "cursor": cursor
            }
            
            data = self.client.execute(query, variables)
            repos_data = data["node"]["repositories"]
            
            for repo in repos_data["nodes"]:
                # Apply filters
                if (skip_forks and repo["isFork"]) or (skip_archived and repo["isArchived"]):
                    continue
                all_repos.append(repo)
            
            page_info = repos_data["pageInfo"]
            has_next_page = page_info["hasNextPage"]
            cursor = page_info["endCursor"] if has_next_page else None
        
        logger.info(f"Found {len(all_repos)} repositories after filtering")
        return all_repos

    def _clone_repo(self, repo_info: Dict[str, Any], target_dir: Union[str, Path]) -> Path:
        """Clone a GitHub repository to a local directory.

        Args:
            repo_info: Repository information from GraphQL API
            target_dir: Directory to clone into

        Returns:
            Path to the cloned repository

        Raises:
            RuntimeError: If clone fails
        """
        target_path = Path(target_dir) / repo_info["name"]
        logger.info(f"Cloning {repo_info['url']} to {target_path}")

        try:
            # Use either SSH URL or HTTPS URL with token for authentication
            if repo_info["isPrivate"]:
                clone_url = repo_info["url"].replace(
                    "https://github.com/",
                    f"https://{self.token}@github.com/"
                )
            else:
                clone_url = repo_info["url"]
                
            Repo.clone_from(clone_url, target_path)
            return target_path
        except GitCommandError as e:
            raise RuntimeError(f"Failed to clone repository {repo_info['name']}: {e}")

    def scan_team_repos(
        self,
        org_name: str,
        team_name: str,
        skip_forks: bool = True,
        skip_archived: bool = True,
    ) -> GithubScanResult:
        """Scan all repositories accessible to a team in a GitHub organization.

        Args:
            org_name: Name of the GitHub organization
            team_name: Name of the team within the organization
            skip_forks: Whether to skip repositories that are forks
            skip_archived: Whether to skip archived repositories

        Returns:
            GithubScanResult containing scan results for each repository
        """
        result = GithubScanResult(org_name=org_name, team_name=team_name)

        try:
            team_id = self._get_team_id(org_name, team_name)
            repos = self._get_team_repos(team_id, skip_forks, skip_archived)
            logger.info(f"Scanning {len(repos)} repositories")
            
            with tempfile.TemporaryDirectory() as tmp_dir:
                for repo in repos:
                    try:
                        repo_path = self._clone_repo(repo, tmp_dir)
                        check_results = self.scanner.scan(repo_path)
                        rating = self.scanner.rate(check_results)
                        
                        result.repo_results[repo["name"]] = RepoScanResult(
                            repo_name=repo["name"],
                            repo_url=repo["url"],
                            check_results=check_results,
                            rating=rating,
                        )
                        
                        logger.info(f"Successfully scanned repository: {repo['name']}")
                    except Exception as e:
                        logger.error(f"Error scanning repository {repo['name']}: {e}")
                        result.repo_results[repo["name"]] = RepoScanResult(
                            repo_name=repo["name"],
                            repo_url=repo["url"],
                            check_results=[],
                            rating=None,
                            error=str(e),
                        )
        except Exception as e:
            logger.error(f"Error retrieving repositories: {e}")
            result.errors.append(f"Failed to retrieve repositories: {str(e)}")
        
        return result


class GithubReporter:
    """Reporter for GitHub scan results."""

    def generate_summary(self, result: GithubScanResult) -> Dict[str, Any]:
        """Generate a summary of GitHub scan results.

        Args:
            result: GitHub scan results to summarize

        Returns:
            Dictionary with summary information
        """
        summary = {
            "organization": result.org_name,
            "team": result.team_name,
            "total_repos": len(result.repo_results),
            "successful_repos": len(result.successful_repos),
            "failed_repos": len(result.failed_repos),
            "errors": result.errors,
            "repositories": {},
        }
        
        for repo_name, repo_result in result.repo_results.items():
            if repo_result.error:
                summary["repositories"][repo_name] = {
                    "status": "error",
                    "error": repo_result.error,
                    "url": repo_result.repo_url,
                }
            else:
                check_counts = {}
                for check_result in repo_result.check_results:
                    status = check_result.status.value
                    check_counts[status] = check_counts.get(status, 0) + 1
                
                summary["repositories"][repo_name] = {
                    "status": "success",
                    "url": repo_result.repo_url,
                    "rating": {
                        "score": repo_result.rating.score,
                        "grade": repo_result.rating.grade,
                        "category_scores": repo_result.rating.category_scores,
                    },
                    "check_counts": check_counts,
                }
        
        return summary

    def generate_detailed_report(self, result: GithubScanResult) -> Dict[str, Any]:
        """Generate a detailed report of GitHub scan results.

        Args:
            result: GitHub scan results to report

        Returns:
            Dictionary with detailed report information
        """
        report = self.generate_summary(result)
        
        for repo_name, repo_result in result.repo_results.items():
            if repo_result.error:
                continue
                
            repo_details = report["repositories"][repo_name]
            repo_details["checks"] = []
            
            for check_result in repo_result.check_results:
                check_info = {
                    "id": check_result.check_id,
                    "status": check_result.status.value,
                    "message": check_result.message,
                }
                if check_result.details:
                    check_info["details"] = check_result.details
                
                repo_details["checks"].append(check_info)
        
        return report

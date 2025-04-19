"""GitHub integration for panoptipy.

This module contains functionality to scan GitHub repositories using
GitHub's GraphQL API.
"""

import logging
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import requests
from git import Repo

logger = logging.getLogger(__name__)

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"


@dataclass
class GitHubRepo:
    """Represents a GitHub repository."""

    name: str
    full_name: str
    clone_url: str
    description: Optional[str] = None
    is_private: bool = False
    is_fork: bool = False

    def __str__(self):
        return f"{self.full_name} ({'private' if self.is_private else 'public'})"


class GitHubClient:
    """Client for interacting with GitHub API."""

    def __init__(self, token: str):
        """Initialize GitHub client with authentication token.

        Args:
            token: GitHub personal access token
        """
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def execute_query(self, query: str, variables: Optional[Dict] = None) -> Dict:
        """Execute a GraphQL query against GitHub API.

        Args:
            query: GraphQL query string
            variables: Variables for the query

        Returns:
            JSON response from the API

        Raises:
            RuntimeError: If the API request fails
        """
        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        response = requests.post(
            GITHUB_GRAPHQL_URL,
            headers=self.headers,
            json=payload,
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"GitHub API request failed: {response.status_code} {response.text}"
            )

        result = response.json()
        if "errors" in result:
            raise RuntimeError(f"GitHub GraphQL query error: {result['errors']}")

        return result

    def get_user_repositories(
        self, username: str, include_private: str = "PUBLIC"
    ) -> List[GitHubRepo]:
        """Get repositories for a GitHub user.

        Args:
            username: GitHub username
            include_private: Whether to include private repositories (requires appropriate token permissions)

        Returns:
            List of GitHubRepo objects
        """
        query = """
        query($username: String!, $includePrivate: RepositoryPrivacy!) {
          user(login: $username) {
            repositories(first: 100, privacy: $includePrivate, orderBy: {field: UPDATED_AT, direction: DESC}) {
              nodes {
                name
                nameWithOwner
                url
                description
                isPrivate
                isFork
                sshUrl
                httpsUrl: url
              }
            }
          }
        }
        """

        variables = {
            "username": username,
            "includePrivate": include_private,
        }

        result = self.execute_query(query, variables)

        try:
            repos_data = result["data"]["user"]["repositories"]["nodes"]
            repos = []

            for repo_data in repos_data:
                # Skip private repos if not requested
                if repo_data["isPrivate"] and include_private!="PRIVATE":
                    continue

                repos.append(
                    GitHubRepo(
                        name=repo_data["name"],
                        full_name=repo_data["nameWithOwner"],
                        clone_url=repo_data["httpsUrl"],
                        description=repo_data["description"],
                        is_private=repo_data["isPrivate"],
                        is_fork=repo_data["isFork"],
                    )
                )

            return repos
        except KeyError as e:
            logger.error(f"Error parsing GitHub API response: {e}")
            raise RuntimeError(f"Failed to get repositories for user {username}")

    def get_team_repositories(self, org: str, team_slug: str) -> List[GitHubRepo]:
        """Get repositories accessible to a team within an organization.

        Args:
            org: GitHub organization name
            team_slug: Team slug (name in URL format)

        Returns:
            List of GitHubRepo objects
        """
        query = """
        query($org: String!, $team: String!) {
          organization(login: $org) {
            team(slug: $team) {
              repositories(first: 100) {
                nodes {
                  name
                  nameWithOwner
                  url
                  description
                  isPrivate
                  isFork
                  httpsUrl: url
                }
              }
            }
          }
        }
        """

        variables = {
            "org": org,
            "team": team_slug,
        }

        result = self.execute_query(query, variables)

        try:
            repos_data = result["data"]["organization"]["team"]["repositories"]["nodes"]
            repos = []

            for repo_data in repos_data:
                repos.append(
                    GitHubRepo(
                        name=repo_data["name"],
                        full_name=repo_data["nameWithOwner"],
                        clone_url=repo_data["httpsUrl"],
                        description=repo_data["description"],
                        is_private=repo_data["isPrivate"],
                        is_fork=repo_data["isFork"],
                    )
                )

            return repos
        except KeyError as e:
            logger.error(f"Error parsing GitHub API response: {e}")
            raise RuntimeError(
                f"Failed to get repositories for team {team_slug} in org {org}"
            )


class GitHubScanner:
    """Handles scanning of GitHub repositories."""

    def __init__(self, github_client: GitHubClient, temp_dir: Optional[Path] = None):
        """Initialize scanner with GitHub client.

        Args:
            github_client: Authenticated GitHub client
            temp_dir: Optional temporary directory for cloning repos
        """
        self.github_client = github_client
        self.temp_dir = temp_dir or Path(tempfile.mkdtemp(prefix="panoptipy-"))

    def __del__(self):
        """Clean up temporary directory on object destruction."""
        if self.temp_dir and self.temp_dir.exists():
            try:
                shutil.rmtree(self.temp_dir)
            except Exception as e:
                logger.warning(
                    f"Failed to clean up temporary directory {self.temp_dir}: {e}"
                )

    def clone_repository(self, repo: GitHubRepo) -> Path:
        """Clone a GitHub repository to a temporary directory.

        Args:
            repo: GitHub repository to clone

        Returns:
            Path to the cloned repository
        """
        repo_dir = self.temp_dir / repo.name

        # Clean up existing directory if it exists
        if repo_dir.exists():
            shutil.rmtree(repo_dir)

        logger.info(f"Cloning repository {repo.full_name} to {repo_dir}")

        # Use the GitHub token for authentication in the clone URL
        clone_url = repo.clone_url
        if "https://" in clone_url:
            auth_url = clone_url.replace(
                "https://", f"https://x-access-token:{self.github_client.token}@"
            )
        else:
            auth_url = clone_url

        try:
            Repo.clone_from(auth_url, repo_dir)
            return repo_dir
        except Exception as e:
            logger.error(f"Failed to clone repository {repo.full_name}: {e}")
            raise RuntimeError(f"Failed to clone repository {repo.full_name}")

    def scan_user_repositories(
        self,
        username: str,
        scanner_func,
        include_private: str = "PUBLIC",
        exclude_forks: bool = True,
        max_repos: Optional[int] = None,
    ) -> Dict[Path, List]:
        """Scan repositories owned by a GitHub user.

        Args:
            username: GitHub username
            scanner_func: Function to scan a repository path
            include_private: Whether to include private repositories
            exclude_forks: Whether to exclude forked repositories
            max_repos: Maximum number of repositories to scan

        Returns:
            Dictionary mapping repository paths to scan results
        """
        repos = self.github_client.get_user_repositories(username, include_private)

        if exclude_forks:
            repos = [r for r in repos if not r.is_fork]

        if max_repos:
            repos = repos[:max_repos]

        logger.info(f"Found {len(repos)} repositories for user {username}")

        results = {}
        for repo in repos:
            try:
                repo_path = self.clone_repository(repo)
                repo_results = scanner_func(repo_path)
                results[repo_path] = repo_results
            except Exception as e:
                logger.error(f"Error scanning repository {repo.full_name}: {e}")
                results[Path(repo.full_name)] = []

        return results

    def scan_team_repositories(
        self,
        org: str,
        team_slug: str,
        scanner_func,
        exclude_forks: bool = True,
        max_repos: Optional[int] = None,
    ) -> Dict[Path, List]:
        """Scan repositories accessible to a team within an organization.

        Args:
            org: GitHub organization name
            team_slug: Team slug (name in URL format)
            scanner_func: Function to scan a repository path
            exclude_forks: Whether to exclude forked repositories
            max_repos: Maximum number of repositories to scan

        Returns:
            Dictionary mapping repository paths to scan results
        """
        repos = self.github_client.get_team_repositories(org, team_slug)

        if exclude_forks:
            repos = [r for r in repos if not r.is_fork]

        if max_repos:
            repos = repos[:max_repos]

        logger.info(
            f"Found {len(repos)} repositories for team {team_slug} in org {org}"
        )

        results = {}
        for repo in repos:
            try:
                repo_path = self.clone_repository(repo)
                repo_results = scanner_func(repo_path)
                results[repo_path] = repo_results
            except Exception as e:
                logger.error(f"Error scanning repository {repo.full_name}: {e}")
                results[Path(repo.full_name)] = []

        return results

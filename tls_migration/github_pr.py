"""
tls_migration/github_pr.py
---------------------------
Single chokepoint for all GitHub write operations performed by Cryptiq.

Allowed operations (hard-enforced, everything else raises PermissionError):
  - Create a branch
  - Commit a file change
  - Open a pull request

Forbidden operations (will raise PermissionError even if requested):
  - Merge a pull request
  - Force-push
  - Delete a branch or repository object

Required token scopes:
  SCOPES: repo (for private repos) or public_repo (for public repos).
  The token must NOT have admin:org, delete_repo, or workflow scope.
  Minimum: contents:write, pull_requests:write on the target repo.

Env var: GITHUB_TOKEN (never hardcoded, never committed).
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Optional

# PyGithub — install with: pip install PyGithub
from github import Github, GithubException

# Operations the chokepoint permits. Anything else is forbidden.
_ALLOWED_OPERATIONS = frozenset({"branch_create", "commit", "open_pr"})


def _assert_allowed(operation: str) -> None:
    """Hard-assert the operation is permitted. Raises PermissionError if not."""
    if operation not in _ALLOWED_OPERATIONS:
        raise PermissionError(
            f"Cryptiq GitHub chokepoint: operation '{operation}' is not allowed. "
            f"Allowed: {sorted(_ALLOWED_OPERATIONS)}. "
            "The engine may only create branches, commit changes, and open pull requests."
        )


@dataclass
class PRResult:
    pr_url: str
    pr_number: int
    branch: str
    repo: str


def open_migration_pr(
    repo_full_name: str,
    base_branch: str,
    new_branch: str,
    file_path: str,
    new_file_content: str,
    pr_title: str,
    pr_body: str,
    label: Optional[str] = "cryptiq-migration",
    github_token: Optional[str] = None,
) -> PRResult:
    """
    Create a branch, commit a single file change, and open a pull request.

    Args:
        repo_full_name   : "owner/repo"
        base_branch      : Branch to base the PR on (e.g. "main")
        new_branch       : Name of the branch to create (e.g. "cryptiq/migrate-alb-listener-443")
        file_path        : Path to the file within the repo (e.g. "demo-infra/main.tf")
        new_file_content : Full content of the file after the change
        pr_title         : PR title
        pr_body          : PR body (must include the diff, rationale, and "will not merge" line)
        label            : Label to apply to the PR (default "cryptiq-migration")
        github_token     : Overrides GITHUB_TOKEN env var (for testing)

    Returns:
        PRResult with pr_url, pr_number, branch, repo
    """
    token = github_token or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise EnvironmentError("GITHUB_TOKEN env var is not set.")

    g = Github(token)
    repo = g.get_repo(repo_full_name)

    # ── Step 1: Create branch ─────────────────────────────────────────────────
    _assert_allowed("branch_create")
    base_ref = repo.get_branch(base_branch)
    repo.create_git_ref(ref=f"refs/heads/{new_branch}", sha=base_ref.commit.sha)

    # ── Step 2: Commit file ───────────────────────────────────────────────────
    _assert_allowed("commit")
    try:
        existing = repo.get_contents(file_path, ref=new_branch)
        repo.update_file(
            path=file_path,
            message=f"cryptiq: migrate ssl_policy to post-quantum hybrid",
            content=new_file_content,
            sha=existing.sha,
            branch=new_branch,
        )
    except GithubException as e:
        if e.status == 404:
            repo.create_file(
                path=file_path,
                message=f"cryptiq: migrate ssl_policy to post-quantum hybrid",
                content=new_file_content,
                branch=new_branch,
            )
        else:
            raise

    # ── Step 3: Open PR ───────────────────────────────────────────────────────
    _assert_allowed("open_pr")
    pr = repo.create_pull(
        title=pr_title,
        body=pr_body,
        head=new_branch,
        base=base_branch,
    )

    if label:
        try:
            repo.get_label(label)
        except GithubException:
            repo.create_label(label, "0075ca")
        pr.add_to_labels(label)

    return PRResult(
        pr_url=pr.html_url,
        pr_number=pr.number,
        branch=new_branch,
        repo=repo_full_name,
    )


# ---------------------------------------------------------------------------
# Forbidden-operation guard (used in tests and for belt-and-suspenders safety)
# ---------------------------------------------------------------------------

def assert_not_merge(operation: str) -> None:
    """Call with any operation string to enforce the no-merge invariant."""
    _assert_allowed(operation)

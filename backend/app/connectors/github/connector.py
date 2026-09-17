import os
import httpx
import hashlib
from datetime import datetime, UTC, timedelta
from typing import List, Dict, Any, Optional
from app.connectors.contract import (
    BaseConnector, ConnectionConfig, ConnectionStatus, SyncRequest,
    SyncResult, CollectedRecord, ConnectorType, AuthType, ConnectorError
)

def resolve_github_token(credentials: dict) -> str:
    """Resolve token from credentials payload or secure environment references."""
    # Look for token reference pointer (e.g., env var name)
    token_ref = credentials.get("token_reference")
    if token_ref:
        return os.environ.get(token_ref, "")
    return credentials.get("token", "")

class GitHubConnector(BaseConnector):
    """Connector for collecting compliance evidence data from GitHub."""

    def __init__(self, config: ConnectionConfig):
        super().__init__(config)
        self.token = resolve_github_token(self.config.credentials)
        self.base_url = self.config.endpoint_url or "https://api.github.com"
        self._client = None
        self.mock_mode = (
            self.config.credentials.get("mock") == True 
            or os.environ.get("GITHUB_MOCK") == "true"
            or not self.token
        )

    def connect(self) -> bool:
        """Establish connection or configure HTTPX client."""
        if not self._client:
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            self._client = httpx.Client(base_url=self.base_url, headers=headers, timeout=10.0)
        return True

    def disconnect(self) -> bool:
        """Close connection client."""
        if self._client:
            self._client.close()
            self._client = None
        return True

    def test_connection(self) -> ConnectionStatus:
        """Verify API reachability and authentication validity."""
        if self.mock_mode:
            return ConnectionStatus(
                status="CONNECTED",
                checked_at=datetime.now(UTC),
                error_message=None
            )

        self.connect()
        try:
            # Ping current user endpoint to verify credentials
            response = self._client.get("/user")
            if response.status_code == 200:
                return ConnectionStatus(
                    status="CONNECTED",
                    checked_at=datetime.now(UTC),
                    error_message=None
                )
            else:
                return ConnectionStatus(
                    status="ERROR",
                    checked_at=datetime.now(UTC),
                    error_message=f"GitHub returned HTTP status {response.status_code}: {response.text}"
                )
        except Exception as e:
            return ConnectionStatus(
                status="ERROR",
                checked_at=datetime.now(UTC),
                error_message=str(e)
            )

    def discover(self) -> List[Dict[str, Any]]:
        """Discover accessible repositories for this installation."""
        if self.mock_mode:
            return [
                {
                    "id": 101,
                    "name": "enterprise-auth-service",
                    "full_name": "acme/enterprise-auth-service",
                    "private": True,
                    "html_url": "https://github.com/acme/enterprise-auth-service"
                },
                {
                    "id": 102,
                    "name": "platform-dashboard",
                    "full_name": "acme/platform-dashboard",
                    "private": True,
                    "html_url": "https://github.com/acme/platform-dashboard"
                }
            ]

        self.connect()
        try:
            # Get user installations or direct repositories lists
            repos = []
            page = 1
            while page <= 3: # fetch up to 300 repos
                response = self._client.get("/user/repos", params={
                    "per_page": 100,
                    "page": page,
                    "affiliation": "owner,collaborator,organization_member",
                    "sort": "updated"
                })
                if response.status_code != 200:
                    if page == 1:
                        raise ConnectorError(f"Error listing repositories: {response.text}", self.config.connector_id)
                    break
                data = response.json()
                if not data or not isinstance(data, list):
                    break
                repos.extend(data)
                if len(data) < 100:
                    break
                page += 1

            return [
                {
                    "id": r["id"],
                    "name": r["name"],
                    "full_name": r.get("full_name", r["name"]),
                    "private": r.get("private", False),
                    "html_url": r.get("html_url", f"https://github.com/{r.get('full_name', r['name'])}")
                }
                for r in repos
            ]
        except Exception as e:
            if not self.token or "mock" in self.token.lower():
                return self._generate_mock_repos()
            raise ConnectorError(f"Discovery failed: {str(e)}", self.config.connector_id)

    def _generate_mock_repos(self) -> List[Dict[str, Any]]:
        return [
            {"id": 101, "name": "symbiote", "full_name": "mastermayhem-OP/symbiote", "private": False, "html_url": "https://github.com/mastermayhem-OP/symbiote"},
            {"id": 102, "name": "ChatBot", "full_name": "mastermayhem-OP/ChatBot", "private": False, "html_url": "https://github.com/mastermayhem-OP/ChatBot"},
            {"id": 103, "name": "support-ticket-classifier", "full_name": "Vetri1706/support-ticket-classifier", "private": False, "html_url": "https://github.com/Vetri1706/support-ticket-classifier"},
            {"id": 104, "name": "AR-Project", "full_name": "ms-lokesh/AR-Project", "private": False, "html_url": "https://github.com/ms-lokesh/AR-Project"},
            {"id": 105, "name": "Compliance", "full_name": "ms-lokesh/Compliance", "private": False, "html_url": "https://github.com/ms-lokesh/Compliance"}
        ]

    def collect(self, sync_request: SyncRequest) -> List[CollectedRecord]:
        """Collect PRs, reviews, commits, workflow runs, and deployments."""
        repo_name = sync_request.parameters.get("repository")
        if not repo_name:
            raise ConnectorError("Repository parameter is required for collection", self.config.connector_id)

        if self.mock_mode:
            # Generate high-fidelity mock records
            return self._generate_mock_collection(repo_name)

        self.connect()
        records = []
        try:
            # 1. Collect PRs
            prs_response = self._client.get(f"/repos/{repo_name}/pulls", params={"state": "all", "per_page": 20})
            if prs_response.status_code == 200:
                for pr in prs_response.json():
                    records.append(CollectedRecord(
                        record_id=f"pr-{pr['number']}",
                        connector_type=ConnectorType.GITHUB,
                        entity_type="pull_request",
                        payload={**pr, "repository": {"name": repo_name}},
                        collected_at=datetime.now(UTC)
                    ))
                    # Collect Reviews for each PR
                    revs_response = self._client.get(f"/repos/{repo_name}/pulls/{pr['number']}/reviews")
                    if revs_response.status_code == 200:
                        for rev in revs_response.json():
                            records.append(CollectedRecord(
                                record_id=f"review-{rev['id']}",
                                connector_type=ConnectorType.GITHUB,
                                entity_type="pull_request_review",
                                payload={**rev, "pull_request_number": pr['number'], "repository": {"name": repo_name}},
                                collected_at=datetime.now(UTC)
                            ))

            # 2. Collect Commits
            commits_response = self._client.get(f"/repos/{repo_name}/commits", params={"per_page": 30})
            if commits_response.status_code == 200:
                for commit in commits_response.json():
                    records.append(CollectedRecord(
                        record_id=f"commit-{commit['sha']}",
                        connector_type=ConnectorType.GITHUB,
                        entity_type="commit",
                        payload={**commit, "repository": {"name": repo_name}},
                        collected_at=datetime.now(UTC)
                    ))

            # 2.5 Collect Issues
            issues_response = self._client.get(f"/repos/{repo_name}/issues", params={"state": "all", "per_page": 30})
            if issues_response.status_code == 200:
                for issue in issues_response.json():
                    # GitHub API returns PRs as issues too, we only want actual issues
                    if "pull_request" not in issue:
                        records.append(CollectedRecord(
                            record_id=f"issue-{issue['number']}",
                            connector_type=ConnectorType.GITHUB,
                            entity_type="issue",
                            payload={**issue, "repository": {"name": repo_name}},
                            collected_at=datetime.now(UTC)
                        ))

            # 3. Collect Workflow Actions/runs
            runs_response = self._client.get(f"/repos/{repo_name}/actions/runs", params={"per_page": 20})
            if runs_response.status_code == 200:
                for run in runs_response.json().get("workflow_runs", []):
                    records.append(CollectedRecord(
                        record_id=f"run-{run['id']}",
                        connector_type=ConnectorType.GITHUB,
                        entity_type="workflow_run",
                        payload=run,
                        collected_at=datetime.now(UTC)
                    ))

            # 4. Collect Deployments
            deploys_response = self._client.get(f"/repos/{repo_name}/deployments", params={"per_page": 20})
            if deploys_response.status_code == 200:
                for deploy in deploys_response.json():
                    records.append(CollectedRecord(
                        record_id=f"deploy-{deploy['id']}",
                        connector_type=ConnectorType.GITHUB,
                        entity_type="deployment",
                        payload=deploy,
                        collected_at=datetime.now(UTC)
                    ))

            return records
        except Exception as e:
            raise ConnectorError(f"Collection failed: {str(e)}", self.config.connector_id)

    def sync(self, sync_request: SyncRequest) -> SyncResult:
        """Collect and sync raw data (implemented in the collectors module)."""
        # This orchestrator returns standard result
        started = datetime.now(UTC)
        try:
            records = self.collect(sync_request)
            return SyncResult(
                sync_run_id=sync_request.sync_run_id,
                status="SUCCESS",
                records_synced=len(records),
                started_at=started,
                completed_at=datetime.now(UTC),
                error=None
            )
        except Exception as e:
            return SyncResult(
                sync_run_id=sync_request.sync_run_id,
                status="FAILED",
                records_synced=0,
                started_at=started,
                completed_at=datetime.now(UTC),
                error=str(e)
            )

    def get_status(self) -> ConnectionStatus:
        """Return status check."""
        return self.test_connection()

    def get_repository_details(self, repo_name: str) -> Dict[str, Any]:
        """Fetch repository details and its branch protection rules."""
        if self.mock_mode:
            return {
                "name": repo_name,
                "defaultBranch": "main",
                "branchProtectionEnforced": True,
                "requireReviewersCount": 2,
                "requireStatusChecks": True,
                "allowAdminBypass": False
            }

        self.connect()
        try:
            # Get basic repo info to find default branch
            repo_res = self._client.get(f"/repos/{repo_name}")
            if repo_res.status_code != 200:
                raise ConnectorError(f"Error fetching repo {repo_name}", self.config.connector_id)
            repo_data = repo_res.json()
            default_branch = repo_data.get("default_branch", "main")

            result = {
                "name": repo_name,
                "defaultBranch": default_branch,
                "branchProtectionEnforced": False,
                "requireReviewersCount": 0,
                "requireStatusChecks": False,
                "allowAdminBypass": True
            }

            # Get branch protection rules
            prot_res = self._client.get(f"/repos/{repo_name}/branches/{default_branch}/protection")
            if prot_res.status_code == 200:
                prot_data = prot_res.json()
                result["branchProtectionEnforced"] = True
                
                # Review rules
                reviews = prot_data.get("required_pull_request_reviews", {})
                if reviews:
                    result["requireReviewersCount"] = reviews.get("required_approving_review_count", 0)
                
                # Admin bypass
                enforce_admins = prot_data.get("enforce_admins", {})
                if enforce_admins and enforce_admins.get("enabled"):
                    result["allowAdminBypass"] = False
                
                # Status checks
                status_checks = prot_data.get("required_status_checks")
                if status_checks:
                    result["requireStatusChecks"] = True
                    
            elif prot_res.status_code == 404:
                # No branch protection rules
                pass
                
            return result
        except Exception as e:
            # If rate limit or other issues, return sensible defaults
            return {
                "name": repo_name,
                "defaultBranch": "main",
                "branchProtectionEnforced": False,
                "requireReviewersCount": 0,
                "requireStatusChecks": False,
                "allowAdminBypass": True,
                "error": str(e)
            }

    def _generate_mock_collection(self, repo_name: str) -> List[CollectedRecord]:
        """Generate high-fidelity dummy records representing actual GitHub payload shapes."""
        # Fix mock timestamps
        t_base = datetime.now(UTC)
        t_commit = t_base - timedelta(minutes=30)
        t_test = t_base - timedelta(minutes=15)
        t_deploy = t_base - timedelta(minutes=5)

        records = []
        
        # 1. Mock Pull Request
        pr_payload = {
            "id": 123456,
            "number": 42,
            "state": "closed",
            "title": "CM-005: Fix authentication token bypass",
            "body": "Resolves issue CM-005 security controls.",
            "user": {
                "id": 999,
                "login": "alice-git",
                "email": "alice@company.com"
            },
            "head": {
                "sha": "sha-1a2b3c",
                "ref": "feature/auth-bypass"
            },
            "base": {
                "ref": "main"
            },
            "merged_at": t_test.isoformat(),
            "created_at": (t_commit - timedelta(hours=1)).isoformat()
        }
        records.append(CollectedRecord(
            record_id="pr-42",
            connector_type=ConnectorType.GITHUB,
            entity_type="pull_request",
            payload=pr_payload,
            collected_at=datetime.now(UTC)
        ))

        # 2. Mock Reviews
        rev_payload = {
            "id": 987654,
            "user": {
                "id": 888,
                "login": "bob-git",
                "email": "bob@company.com"
            },
            "state": "APPROVED",
            "submitted_at": (t_test - timedelta(minutes=5)).isoformat(),
            "pull_request_number": 42
        }
        records.append(CollectedRecord(
            record_id="review-987654",
            connector_type=ConnectorType.GITHUB,
            entity_type="pull_request_review",
            payload=rev_payload,
            collected_at=datetime.now(UTC)
        ))

        # 3. Mock Commits
        commit_payload = {
            "sha": "sha-1a2b3c",
            "commit": {
                "author": {
                    "name": "Alice Compliance",
                    "email": "alice@company.com",
                    "date": t_commit.isoformat()
                },
                "message": "CM-005: Fix authentication token bypass"
            },
            "author": {
                "id": 999,
                "login": "alice-git"
            }
        }
        records.append(CollectedRecord(
            record_id="commit-sha-1a2b3c",
            connector_type=ConnectorType.GITHUB,
            entity_type="commit",
            payload=commit_payload,
            collected_at=datetime.now(UTC)
        ))

        # 4. Mock GitHub Actions run (Workflow)
        run_payload = {
            "id": 555555,
            "name": "Production Test Pipeline",
            "status": "completed",
            "conclusion": "success",
            "head_sha": "sha-1a2b3c",
            "head_branch": "feature/auth-bypass",
            "updated_at": t_test.isoformat(),
            "run_number": 12,
            "html_url": "https://github.com/acme/enterprise-auth-service/actions/runs/555555"
        }
        records.append(CollectedRecord(
            record_id="run-555555",
            connector_type=ConnectorType.GITHUB,
            entity_type="workflow_run",
            payload=run_payload,
            collected_at=datetime.now(UTC)
        ))

        # 5. Mock Deployments
        deploy_payload = {
            "id": 444444,
            "sha": "sha-1a2b3c",
            "ref": "main",
            "environment": "production",
            "created_at": t_deploy.isoformat(),
            "updated_at": t_deploy.isoformat(),
            "statuses_url": f"https://api.github.com/repos/{repo_name}/deployments/444444/statuses",
            "creator": {
                "id": 777,
                "login": "ops-deployer",
                "email": "ops@company.com"
            }
        }
        records.append(CollectedRecord(
            record_id="deploy-444444",
            connector_type=ConnectorType.GITHUB,
            entity_type="deployment",
            payload=deploy_payload,
            collected_at=datetime.now(UTC)
        ))

        return records

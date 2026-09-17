from datetime import datetime, timezone
from typing import Dict, Any, Optional
from app.models.orm import (
    ChangeORM, ApprovalORM, TestORM, DeploymentORM, EnvironmentORM, ApplicationORM,
    UserORM, ORMChangeType, ORMTestStatus, ORMEnvType, ORMCheckResultType
)

def parse_iso_datetime(dt_str: Optional[str]) -> Optional[datetime]:
    """Helper to parse ISO-8601 string from GitHub to naive UTC datetime object."""
    if not dt_str:
        return None
    try:
        # Standard GitHub format: e.g. 2026-08-22T07:12:00Z
        clean_str = dt_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_str)
        if dt.tzinfo:
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        return None

class GitHubNormalizer:
    """Transforms raw GitHub JSON payloads to Common Change Data Model (CCDM) database models."""

    @staticmethod
    def normalize_pull_request(payload: Dict[str, Any], tenant_id: str) -> ChangeORM:
        """Map GitHub pull request event to Change model."""
        pr_data = payload.get("pull_request") if "pull_request" in payload else payload
        
        pr_number = pr_data.get("number")
        title = pr_data.get("title", "")
        body = pr_data.get("body") or ""

        # Parse Change Type from title prefix, e.g. "EMERGENCY: Fix auth bypass"
        change_type = ORMChangeType.NORMAL
        upper_title = title.upper()
        if "EMERGENCY:" in upper_title or "HOTFIX:" in upper_title:
            change_type = ORMChangeType.EMERGENCY
        elif "STANDARD:" in upper_title or "CHORE:" in upper_title:
            change_type = ORMChangeType.STANDARD

        # Status resolution
        state = pr_data.get("state", "open")
        merged_at = parse_iso_datetime(pr_data.get("merged_at"))
        
        status = "OPEN"
        if state == "closed":
            status = "CLOSED" if merged_at else "CANCELLED"

        change_id = f"chg-pr-{pr_number}"

        # Setup dates
        created_at = parse_iso_datetime(pr_data.get("created_at"))
        updated_at = parse_iso_datetime(pr_data.get("updated_at"))

        # Resolve Requester login handle
        author_login = pr_data.get("user", {}).get("login", "unknown")
        
        return ChangeORM(
            change_id=change_id,
            tenant_id=tenant_id,
            external_id=str(pr_number),
            source="github",
            title=title,
            description=body,
            change_type=change_type,
            requester_id=f"usr-{author_login}", # Placeholder user ID prefix for identity link lookup later
            owner_id=f"usr-{author_login}",
            risk_level="medium",
            environment_id="env-prod", # Default production scope
            application_id=payload.get("repository", {}).get("name", "app-default"), # Use repo name
            status=status,
            planned_start=created_at,
            planned_end=updated_at,
            implemented_at=merged_at,
            completed_at=merged_at,
            created_at=created_at or datetime.utcnow(),
            updated_at=updated_at or datetime.utcnow()
        )

    @staticmethod
    def normalize_review(payload: Dict[str, Any], tenant_id: str) -> ApprovalORM:
        """Map GitHub Pull Request Review payload to Approval model."""
        review_node = payload.get("review") if isinstance(payload.get("review"), dict) else payload
        review_id = payload.get("id") or review_node.get("id")
        pr_number = payload.get("pull_request_number") or payload.get("pull_request", {}).get("number")
        state = payload.get("state") or review_node.get("state") or "PENDING"
        submitted_at = parse_iso_datetime(payload.get("submitted_at") or review_node.get("submitted_at"))
        user_node = payload.get("user") or review_node.get("user") or {}
        reviewer_login = user_node.get("login", "unknown")

        state_str = str(state).upper()
        if state_str == "APPROVED":
            decision = "APPROVED"
        elif state_str == "DISMISSED":
            decision = "dismissed"
        else:
            decision = "REJECTED"

        return ApprovalORM(
            approval_id=f"appr-{review_id}",
            tenant_id=tenant_id,
            change_id=f"chg-pr-{pr_number}",
            approver_id=f"usr-{reviewer_login}",
            role="reviewer",
            decision=decision,
            approved_at=submitted_at or datetime.utcnow(),
            source="github"
        )

    @staticmethod
    def normalize_workflow_run(payload: Dict[str, Any], tenant_id: str) -> TestORM:
        """Map GitHub Action workflow_run payload to Test model."""
        run_id = payload.get("id")
        conclusion = payload.get("conclusion")
        status = payload.get("status")
        commit_sha = payload.get("head_sha")
        completed_at = parse_iso_datetime(payload.get("updated_at"))
        
        # Test state mapping
        test_status = ORMTestStatus.UNKNOWN
        if status == "completed":
            test_status = ORMTestStatus.PASS if conclusion == "success" else ORMTestStatus.FAIL

        return TestORM(
            test_id=f"run-{run_id}",
            tenant_id=tenant_id,
            change_id=None, # Filled later in correlation engine
            source="github_actions",
            pipeline_id=str(run_id),
            commit_id=commit_sha,
            test_type="INTEGRATION",
            status=test_status,
            started_at=parse_iso_datetime(payload.get("run_started_at")) or datetime.utcnow(),
            completed_at=completed_at,
            evidence_reference=payload.get("html_url")
        )

    @staticmethod
    def normalize_deployment(payload: Dict[str, Any], tenant_id: str) -> DeploymentORM:
        """Map GitHub Deployment event payload to Deployment model."""
        deploy_data = payload.get("deployment") if "deployment" in payload else payload
        
        deploy_id = deploy_data.get("id")
        commit_sha = deploy_data.get("sha")
        ref = deploy_data.get("ref", "main")
        env_name = deploy_data.get("environment", "production")
        created_at = parse_iso_datetime(deploy_data.get("created_at") or deploy_data.get("updated_at"))
        
        creator = deploy_data.get("creator") or payload.get("sender") or {}
        creator_login = creator.get("login", "unknown")

        # Map environment label to standardized entity ID
        env_id = "env-prod"
        if env_name.lower() in ["staging", "stage"]:
            env_id = "env-staging"
        elif env_name.lower() in ["development", "dev"]:
            env_id = "env-dev"

        return DeploymentORM(
            deployment_id=f"dep-{deploy_id}",
            tenant_id=tenant_id,
            change_id=None, # Correlated later
            application_id="app-default", # Correlated later
            environment_id=env_id,
            repository_id=None, # Populated by collection scope
            version=ref,
            commit_id=commit_sha,
            deployed_by=f"usr-{creator_login}",
            deployed_at=created_at or datetime.utcnow(),
            status="SUCCESS", # Webhook status checks may update this
            source="github"
        )

    @staticmethod
    def normalize_issue(payload: Dict[str, Any], tenant_id: str) -> ChangeORM:
        """Map GitHub Issue to Change model."""
        issue_number = payload.get("number")
        title = payload.get("title", "")
        body = payload.get("body") or ""
        state = payload.get("state", "open")
        
        status = "OPEN" if state == "open" else "CLOSED"
        change_id = f"chg-iss-{issue_number}"
        
        created_at = parse_iso_datetime(payload.get("created_at"))
        updated_at = parse_iso_datetime(payload.get("updated_at"))
        author_login = payload.get("user", {}).get("login", "unknown")
        
        return ChangeORM(
            change_id=change_id,
            tenant_id=tenant_id,
            external_id=str(issue_number),
            source="github",
            title=title,
            description=body,
            change_type=ORMChangeType.NORMAL,
            requester_id=f"usr-{author_login}",
            owner_id=f"usr-{author_login}",
            risk_level="low",
            environment_id="env-prod",
            application_id=payload.get("repository", {}).get("name", "app-default"),
            status=status,
            planned_start=created_at,
            planned_end=updated_at,
            implemented_at=None,
            completed_at=updated_at if status == "CLOSED" else None,
            created_at=created_at or datetime.utcnow(),
            updated_at=updated_at or datetime.utcnow()
        )

    @staticmethod
    def normalize_commit(payload: Dict[str, Any], tenant_id: str) -> ChangeORM:
        """Map GitHub Commit to Change model."""
        sha = payload.get("sha")
        commit_data = payload.get("commit", {})
        title = commit_data.get("message", "Commit")
        author_data = payload.get("author") or {}
        author_login = author_data.get("login") or commit_data.get("author", {}).get("name", "unknown")
        
        created_at = parse_iso_datetime(commit_data.get("author", {}).get("date"))
        
        return ChangeORM(
            change_id=f"chg-com-{sha[:8]}",
            tenant_id=tenant_id,
            external_id=sha,
            source="github",
            title=title,
            description="",
            change_type=ORMChangeType.NORMAL,
            requester_id=f"usr-{author_login}",
            owner_id=f"usr-{author_login}",
            risk_level="high",
            environment_id="env-prod",
            application_id=payload.get("repository", {}).get("name", "app-default"),
            status="MERGED", # Commits are implemented immediately
            planned_start=created_at,
            planned_end=created_at,
            implemented_at=created_at,
            completed_at=created_at,
            created_at=created_at or datetime.utcnow(),
            updated_at=created_at or datetime.utcnow()
        )

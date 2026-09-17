from sqlalchemy.orm import Session
from app.db.mongodb import MongoDBClient
from app.normalization.github_adapter import GitHubNormalizer
from app.normalization.jira_adapter import JiraNormalizer
from app.models.orm import (
    UserORM, EnvironmentORM, ApplicationORM, ChangeORM, ApprovalORM, TestORM,
    DeploymentORM, ORMEnvType
)
from datetime import datetime, UTC

class NormalizationService:
    """Orchestrates raw event normalization and upserts relational entities in PostgreSQL."""

    def __init__(self, db: Session):
        self.db = db
        self.mongo = MongoDBClient()

    def normalize_sync_run_payloads(self, tenant_id: str, sync_run_id: str) -> int:
        """Fetch all raw events for a sync run and normalize them into PostgreSQL."""
        self.mongo.connect()
        col = self.mongo.raw_events_collection
        
        raw_events = list(col.find({
            "tenant_id": tenant_id,
            "sync_run_id": sync_run_id
        }))
        
        self.mongo.disconnect()

        if not raw_events:
            return 0

        # Ensure base lookups exist to satisfy foreign keys
        self._ensure_baseline_entities(tenant_id)

        normalized_count = 0

        for event in raw_events:
            ev_type = event.get("event_type")
            payload = event.get("payload")

            if not payload:
                continue

            try:
                if ev_type == "pull_request":
                    change = GitHubNormalizer.normalize_pull_request(payload, tenant_id)
                    # Ensure users exist before adding changes
                    self._ensure_user_exists(tenant_id, change.requester_id)
                    self.db.merge(change)
                    normalized_count += 1
                
                elif ev_type == "pull_request_review":
                    review = GitHubNormalizer.normalize_review(payload, tenant_id)
                    # Ensure user and change exist
                    self._ensure_user_exists(tenant_id, review.approver_id)
                    self._ensure_stub_change_exists(tenant_id, review.change_id)
                    self.db.merge(review)
                    normalized_count += 1
                
                elif ev_type == "workflow_run":
                    test_run = GitHubNormalizer.normalize_workflow_run(payload, tenant_id)
                    self.db.merge(test_run)
                    normalized_count += 1

                elif ev_type == "deployment":
                    deploy = GitHubNormalizer.normalize_deployment(payload, tenant_id)
                    # Set repository from event metadata
                    deploy.repository_id = "repo-default"
                    # Ensure user exists
                    self._ensure_user_exists(tenant_id, deploy.deployed_by)
                    self.db.merge(deploy)
                    normalized_count += 1
                
                elif ev_type == "issue":
                    change = GitHubNormalizer.normalize_issue(payload, tenant_id)
                    self._ensure_user_exists(tenant_id, change.requester_id)
                    self.db.merge(change)
                    normalized_count += 1
                    
                elif ev_type == "commit":
                    change = GitHubNormalizer.normalize_commit(payload, tenant_id)
                    self._ensure_user_exists(tenant_id, change.requester_id)
                    self.db.merge(change)
                    normalized_count += 1
                    
                elif ev_type == "jira_issue":
                    change = JiraNormalizer.normalize_issue(payload, tenant_id)
                    self._ensure_user_exists(tenant_id, change.requester_id)
                    self._ensure_user_exists(tenant_id, change.owner_id)
                    self.db.merge(change)
                    
                    approvals = JiraNormalizer.extract_approvals(payload, tenant_id)
                    for approval in approvals:
                        self._ensure_user_exists(tenant_id, approval.approver_id)
                        self.db.merge(approval)

                    auths = JiraNormalizer.extract_authorizations(payload, tenant_id)
                    for auth in auths:
                        self._ensure_user_exists(tenant_id, auth.authorized_by)
                        self.db.merge(auth)

                    identities = JiraNormalizer.extract_identities(payload, tenant_id)
                    for ident in identities:
                        self.db.merge(ident)
                        
                    normalized_count += 1
            except Exception as e:
                print(f"Error normalizing event {ev_type}: {e}")

        self.db.commit()
        return normalized_count

    def _ensure_baseline_entities(self, tenant_id: str):
        """Pre-populate default environment and application configurations."""
        # 1. Environments
        prod_env = self.db.query(EnvironmentORM).filter_by(environment_id="env-prod").first()
        if not prod_env:
            self.db.add(EnvironmentORM(
                environment_id="env-prod",
                tenant_id=tenant_id,
                name="Production Environment",
                type=ORMEnvType.PRODUCTION,
                criticality="HIGH"
            ))
        
        staging_env = self.db.query(EnvironmentORM).filter_by(environment_id="env-staging").first()
        if not staging_env:
            self.db.add(EnvironmentORM(
                environment_id="env-staging",
                tenant_id=tenant_id,
                name="Staging Environment",
                type=ORMEnvType.STAGING,
                criticality="MEDIUM"
            ))

        # 2. Application
        app = self.db.query(ApplicationORM).filter_by(application_id="app-default").first()
        if not app:
            self.db.add(ApplicationORM(
                application_id="app-default",
                tenant_id=tenant_id,
                name="Acme Platform",
                owner="Security Team",
                environment_id="env-prod",
                status="ACTIVE"
            ))

        # 3. Repository
        from app.models.orm import RepositoryORM
        repo = self.db.query(RepositoryORM).filter_by(repository_id="repo-default").first()
        if not repo:
            self.db.add(RepositoryORM(
                repository_id="repo-default",
                external_id="101",
                name="enterprise-auth-service",
                provider="github",
                organization="acme",
                default_branch="main",
                production_branch="production",
                status="ACTIVE"
            ))
        
        self.db.commit()

    def _ensure_user_exists(self, tenant_id: str, user_id: str):
        """Upsert a stub user to prevent relational foreign key validation crashes."""
        user = self.db.query(UserORM).filter_by(internal_user_id=user_id, tenant_id=tenant_id).first()
        if not user:
            # Extract login handle
            username = user_id.replace("usr-", "")
            self.db.add(UserORM(
                internal_user_id=user_id,
                tenant_id=tenant_id,
                name=username.capitalize(),
                email=f"{username}@company.com",
                role="Developer",
                status="ACTIVE"
            ))
            self.db.commit()

    def _ensure_stub_change_exists(self, tenant_id: str, change_id: str):
        """Create a stub change if review/approval is processed before its PR event is synced."""
        change = self.db.query(ChangeORM).filter_by(change_id=change_id, tenant_id=tenant_id).first()
        if not change:
            self._ensure_user_exists(tenant_id, "usr-unknown")
            self.db.add(ChangeORM(
                change_id=change_id,
                tenant_id=tenant_id,
                external_id=change_id.replace("chg-pr-", ""),
                source="github",
                title="Stub PR (Ingestion Pipeline)",
                description="",
                change_type="NORMAL",
                requester_id="usr-unknown",
                owner_id="usr-unknown",
                risk_level="medium",
                environment_id="env-prod",
                application_id="app-default",
                status="OPEN"
            ))
            self.db.commit()

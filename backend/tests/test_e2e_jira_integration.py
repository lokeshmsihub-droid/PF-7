import pytest
import time
from datetime import datetime, UTC, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.orm import (
    Base, ConnectorORM, ConnectorAccountORM, SyncRunORM, ChangeORM,
    ApprovalORM, AuthorizationORM, IdentityLinkORM, TestORM, DeploymentORM,
    ChangeRelationshipORM, EvidenceMetadataORM, CheckResultORM, FindingORM,
    ORMChangeType, ORMTestStatus, ORMEnvType
)
from app.connectors.jira.connector import JiraConnector
from app.connectors.contract import ConnectionConfig, ConnectorType, AuthType, SyncRequest, SyncType
from app.normalization.jira_adapter import JiraNormalizer
from app.services.normalization_service import NormalizationService
from app.services.correlation_service import CorrelationService
from app.services.change_control_orchestrator import ChangeControlOrchestrator
from app.core.security import generate_oauth_state, validate_oauth_state, encrypt_token, decrypt_token

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

# ---------------------------------------------------------
# 1. OAuth 2.0 Security & State Tests
# ---------------------------------------------------------

def test_oauth_state_generation_and_validation():
    tenant_id = "tenant-test-corp"
    state = generate_oauth_state(tenant_id=tenant_id, provider="jira", redirect_url="/dashboard")
    
    assert state is not None
    assert "." in state
    
    # Valid state validation
    data = validate_oauth_state(state, expected_tenant_id=tenant_id)
    assert data["tenant_id"] == tenant_id
    assert data["provider"] == "jira"
    assert data["redirect_url"] == "/dashboard"

def test_oauth_state_tampering_rejected():
    state = generate_oauth_state(tenant_id="tenant-1", provider="jira")
    parts = state.split(".")
    tampered_state = f"{parts[0]}.bad_signature_12345"
    
    with pytest.raises(ValueError, match="Invalid OAuth state signature"):
        validate_oauth_state(tampered_state)

def test_oauth_state_single_use_replay_prevention():
    state = generate_oauth_state(tenant_id="tenant-replay", provider="jira")
    # First use succeeds
    validate_oauth_state(state)
    
    # Second use fails (replay protection)
    with pytest.raises(ValueError, match="already been consumed"):
        validate_oauth_state(state)

def test_token_encryption_at_rest():
    raw_token = "atlassian_super_secret_oauth_token_xyz"
    encrypted = encrypt_token(raw_token)
    assert encrypted != raw_token
    
    decrypted = decrypt_token(encrypted)
    assert decrypted == raw_token

# ---------------------------------------------------------
# 2. Jira Connector Discovery & Token Refresh
# ---------------------------------------------------------

def test_jira_connector_accessible_resources_discovery():
    sites = JiraConnector.get_accessible_resources("mock_token")
    assert len(sites) >= 1
    assert sites[0]["id"] == "cloud-site-mock-uuid-1"
    assert "read:jira-work" in sites[0]["scopes"]

def test_jira_connector_discovery_endpoints():
    config = ConnectionConfig(
        connector_id="jira-mock-test",
        connector_type=ConnectorType.JIRA,
        auth_type=AuthType.OAUTH2,
        credentials={"mock": True, "cloud_id": "cloud-mock-1"}
    )
    connector = JiraConnector(config)
    
    projects = connector.discover_projects()
    assert len(projects) >= 1
    assert any(p["key"] == "CHG" for p in projects)
    
    issue_types = connector.discover_issue_types()
    assert len(issue_types) >= 1
    assert any(it["name"] == "Change" for it in issue_types)
    
    fields = connector.discover_fields()
    assert len(fields) >= 1
    assert any(f["id"] == "customfield_risk" for f in fields)

def test_jira_connector_token_refresh():
    config = ConnectionConfig(
        connector_id="jira-refresh-test",
        connector_type=ConnectorType.JIRA,
        auth_type=AuthType.OAUTH2,
        credentials={
            "mock": True,
            "access_token": "expired_access_token",
            "refresh_token": "valid_refresh_token",
            "token_expires_at": int(time.time()) - 100
        }
    )
    connector = JiraConnector(config)
    new_token = connector.refresh_access_token()
    assert new_token == "mock_refreshed_access_token"
    assert connector.token_expires_at > time.time()

# ---------------------------------------------------------
# 3. Normalization & Custom Field Mapping
# ---------------------------------------------------------

def test_jira_normalization_custom_fields_and_status():
    payload = {
        "key": "CHG-200",
        "fields": {
            "summary": "Database Index Optimization",
            "description": "Improve query latencies for payment service.",
            "creator": {"emailAddress": "lead-dev@acme.com", "displayName": "Lead Dev"},
            "assignee": {"emailAddress": "ops-manager@acme.com", "displayName": "Ops Manager"},
            "status": {"name": "CAB Approved"},
            "created": "2026-08-25T00:00:00.000+0000",
            "updated": "2026-08-25T04:00:00.000+0000",
            "cf_custom_risk": {"value": "High"},
            "cf_custom_env": {"value": "Production"},
            "cf_is_emergency": {"value": "No"},
            "cf_start": "2026-08-25T05:00:00.000+0000",
            "cf_end": "2026-08-25T07:00:00.000+0000"
        },
        "changelog": {
            "histories": [
                {
                    "id": "chg-h-1",
                    "created": "2026-08-25T03:00:00.000+0000",
                    "author": {"emailAddress": "cab-officer@acme.com", "displayName": "CAB Officer"},
                    "items": [
                        {"field": "status", "fromString": "Draft", "toString": "CAB Approved"}
                    ]
                }
            ]
        }
    }
    
    custom_map = {
        "risk_field": "cf_custom_risk",
        "environment_field": "cf_custom_env",
        "emergency_field": "cf_is_emergency",
        "planned_start_field": "cf_start",
        "planned_end_field": "cf_end"
    }
    
    change = JiraNormalizer.normalize_issue(payload, "tenant-test", custom_field_map=custom_map)
    assert change.change_id == "chg-jira-CHG-200"
    assert change.status == "CAB Approved"
    assert change.risk_level == "high"
    assert change.environment_id == "env-prod"
    assert change.requester_id == "usr-lead-dev@acme.com"
    
    approvals = JiraNormalizer.extract_approvals(payload, "tenant-test")
    assert len(approvals) == 1
    assert approvals[0].approver_id == "usr-cab-officer@acme.com"
    assert approvals[0].role == "cab_approver"
    assert approvals[0].decision == "APPROVED"
    
    auths = JiraNormalizer.extract_authorizations(payload, "tenant-test")
    assert len(auths) == 1
    assert auths[0].authorized_by == "usr-lead-dev@acme.com"
    
    identities = JiraNormalizer.extract_identities(payload, "tenant-test")
    assert len(identities) >= 2

# ---------------------------------------------------------
# 4. Correlation & End-to-End Compliance Evaluation
# ---------------------------------------------------------

def test_jira_github_correlation_and_compliance(db_session):
    tenant_id = "tenant-e2e-acme"
    
    # 1. Create Jira Change & Approval in DB
    jira_change = ChangeORM(
        change_id="chg-jira-CHG-101",
        tenant_id=tenant_id,
        external_id="CHG-101",
        source="jira",
        title="STANDARD: CM-005 Auth Token Refactoring",
        description="Fixes auth token generation issues. PR #101.",
        change_type=ORMChangeType.STANDARD,
        requester_id="usr-alice@acme.com",
        owner_id="usr-bob@acme.com",
        risk_level="low",
        environment_id="env-prod",
        application_id="jira-CHG",
        status="APPROVED",
        planned_start=datetime.now(UTC).replace(tzinfo=None),
        planned_end=datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=2),
        implemented_at=datetime.now(UTC).replace(tzinfo=None),
        created_at=datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=4),
        updated_at=datetime.now(UTC).replace(tzinfo=None)
    )
    db_session.add(jira_change)
    
    approval = ApprovalORM(
        approval_id="appr-jira-CHG-101-1",
        tenant_id=tenant_id,
        change_id="chg-jira-CHG-101",
        approver_id="usr-bob@acme.com",
        role="cab_approver",
        decision="APPROVED",
        approved_at=datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=2),
        source="jira"
    )
    db_session.add(approval)
    
    # 2. Create GitHub PR Change referencing CHG-101
    github_pr = ChangeORM(
        change_id="chg-pr-101",
        tenant_id=tenant_id,
        external_id="101",
        source="github",
        title="[CHG-101] Implement Token Expiry Handling",
        description="Resolves Jira ticket CHG-101.",
        change_type=ORMChangeType.STANDARD,
        requester_id="usr-alice",
        owner_id="usr-alice",
        risk_level="low",
        environment_id="env-prod",
        application_id="mastermayhem-OP/symbiote",
        status="MERGED",
        created_at=datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=3),
        updated_at=datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=1)
    )
    db_session.add(github_pr)
    db_session.commit()
    
    # 3. Run Correlation Service
    corr_service = CorrelationService(db_session)
    res = corr_service.correlate_sync_run_entities(tenant_id)
    
    # Check that relationship was created
    rel = db_session.query(ChangeRelationshipORM).filter_by(
        tenant_id=tenant_id,
        source_id="chg-jira-CHG-101",
        target_id="chg-pr-101"
    ).first()
    
    assert rel is not None
    assert rel.correlation_method == "JIRA_KEY_IN_PR"
    assert "CHG-101" in rel.correlation_evidence

# ---------------------------------------------------------
# 5. Cross-Tenant Isolation
# ---------------------------------------------------------

def test_tenant_isolation_on_jira_data(db_session):
    tenant_a = "tenant-alpha"
    tenant_b = "tenant-beta"
    
    account_a = ConnectorAccountORM(
        account_id="sys-jira-alpha",
        tenant_id=tenant_a,
        connector_id="jira",
        name="Jira Alpha",
        auth_type="OAUTH2",
        config={"site_name": "alpha-site"},
        status="ACTIVE"
    )
    account_b = ConnectorAccountORM(
        account_id="sys-jira-beta",
        tenant_id=tenant_b,
        connector_id="jira",
        name="Jira Beta",
        auth_type="OAUTH2",
        config={"site_name": "beta-site"},
        status="ACTIVE"
    )
    db_session.add_all([account_a, account_b])
    db_session.commit()
    
    # Tenant A querying accounts
    alpha_accounts = db_session.query(ConnectorAccountORM).filter_by(tenant_id=tenant_a).all()
    assert len(alpha_accounts) == 1
    assert alpha_accounts[0].account_id == "sys-jira-alpha"
    
    # Tenant B querying accounts
    beta_accounts = db_session.query(ConnectorAccountORM).filter_by(tenant_id=tenant_b).all()
    assert len(beta_accounts) == 1
    assert beta_accounts[0].account_id == "sys-jira-beta"

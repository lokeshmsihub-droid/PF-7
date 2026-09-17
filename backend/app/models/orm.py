from datetime import datetime
from typing import List, Optional
from sqlalchemy import Table, Column, String, Text, DateTime, Integer, ForeignKey, JSON, Enum, UniqueConstraint, Boolean, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin
import enum

# Controlled values for Relationships
class EntityType(str, enum.Enum):
    CHANGE = "CHANGE"
    PULL_REQUEST = "PULL_REQUEST"
    COMMIT = "COMMIT"
    TEST = "TEST"
    DEPLOYMENT = "DEPLOYMENT"
    APPROVAL = "APPROVAL"
    AUTHORIZATION = "AUTHORIZATION"
    EVIDENCE = "EVIDENCE"

class RelationshipType(str, enum.Enum):
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    TRIGGERS = "TRIGGERS"
    IMPLEMENTS = "IMPLEMENTS"
    TESTS = "TESTS"
    APPROVES = "APPROVES"
    AUTHORIZES = "AUTHORIZES"
    GENERATES_EVIDENCE = "GENERATES_EVIDENCE"
    CONTAINS = "CONTAINS"

# ORM specific Enums
class ORMChangeType(str, enum.Enum):
    NORMAL = "NORMAL"
    STANDARD = "STANDARD"
    EMERGENCY = "EMERGENCY"

class ORMTestStatus(str, enum.Enum):
    __test__ = False
    PASS = "PASS"
    FAIL = "FAIL"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"

class ORMEnvType(str, enum.Enum):
    DEVELOPMENT = "DEVELOPMENT"
    TEST = "TEST"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"

class ORMCheckResultType(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


class FrameworkORM(Base):
    __tablename__ = "frameworks"
    framework_id: Mapped[str] = mapped_column(String(50), primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    version: Mapped[str] = mapped_column(String(50), default="2017")
    authority: Mapped[str] = mapped_column(String(100), default="AICPA")
    status: Mapped[str] = mapped_column(String(50), default="ACTIVE")

    controls: Mapped[List["ControlORM"]] = relationship(back_populates="framework")


class ControlORM(Base, TimestampMixin):
    __tablename__ = "controls"
    control_id: Mapped[str] = mapped_column(String(50), primary_key=True)
    framework_id: Mapped[str] = mapped_column(ForeignKey("frameworks.framework_id"), index=True)
    criterion: Mapped[str] = mapped_column(String(50), index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    lifecycle_stage: Mapped[str] = mapped_column(String(100), nullable=False)
    applicability: Mapped[str] = mapped_column(String(100), default="PRODUCTION")
    evidence_requirements: Mapped[dict] = mapped_column(JSON, default=list) # List of structured EvidenceRequirements
    status: Mapped[str] = mapped_column(String(50), default="ACTIVE")
    
    # Versioning
    version: Mapped[str] = mapped_column(String(50), default="1.0.0")
    effective_from: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    effective_until: Mapped[Optional[datetime]] = mapped_column(DateTime)

    framework: Mapped["FrameworkORM"] = relationship(back_populates="controls")
    checks: Mapped[List["ComplianceCheckORM"]] = relationship(back_populates="control")
    findings: Mapped[List["FindingORM"]] = relationship(back_populates="control")
    exceptions: Mapped[List["ExceptionORM"]] = relationship(back_populates="control")


class ComplianceCheckORM(Base):
    __tablename__ = "compliance_checks"
    check_id: Mapped[str] = mapped_column(String(50), primary_key=True)
    control_id: Mapped[str] = mapped_column(ForeignKey("controls.control_id"), index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), default="medium")
    lifecycle_stage: Mapped[str] = mapped_column(String(100), nullable=False)
    required_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    evaluation_logic: Mapped[dict] = mapped_column(JSON, nullable=False) # Structured rules and relationships
    evidence_requirements: Mapped[dict] = mapped_column(JSON, default=list)
    reremediation_guidance: Mapped[Optional[str]] = mapped_column(Text)
    applicability: Mapped[str] = mapped_column(String(100), default="PRODUCTION")
    result_types: Mapped[dict] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="ACTIVE")
    
    # Versioning
    version: Mapped[str] = mapped_column(String(50), default="1.0.0")
    effective_from: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    effective_until: Mapped[Optional[datetime]] = mapped_column(DateTime)

    control: Mapped["ControlORM"] = relationship(back_populates="checks")
    results: Mapped[List["CheckResultORM"]] = relationship(back_populates="check")
    findings: Mapped[List["FindingORM"]] = relationship(back_populates="check")
    remediation_tasks: Mapped[List["RemediationTaskORM"]] = relationship(back_populates="check")


class UserORM(Base):
    __tablename__ = "users"
    internal_user_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="ACTIVE")

    identity_links: Mapped[List["IdentityLinkORM"]] = relationship(back_populates="user")


class IdentityLinkORM(Base):
    __tablename__ = "identity_links"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    internal_user_id: Mapped[str] = mapped_column(ForeignKey("users.internal_user_id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    external_user_id: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    external_username: Mapped[str] = mapped_column(String(100), nullable=False)
    external_reference: Mapped[Optional[str]] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(50), default="ACTIVE")

    user: Mapped["UserORM"] = relationship(back_populates="identity_links")

    __table_args__ = (
        UniqueConstraint("tenant_id", "source", "external_user_id", name="uq_identity_link_tenant_source_ext_id"),
    )


class ConnectorORM(Base):
    __tablename__ = "connectors"
    connector_id: Mapped[str] = mapped_column(String(50), primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    type: Mapped[str] = mapped_column(String(50), nullable=False)  # github, jira, aws
    status: Mapped[str] = mapped_column(String(50), default="ACTIVE")

    accounts: Mapped[List["ConnectorAccountORM"]] = relationship(back_populates="connector")


class ConnectorAccountORM(Base):
    __tablename__ = "connector_accounts"
    account_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    connector_id: Mapped[str] = mapped_column(ForeignKey("connectors.connector_id"), index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    auth_type: Mapped[str] = mapped_column(String(50), nullable=False)
    config: Mapped[dict] = mapped_column(JSON, nullable=False)  # Contains credential_reference config
    status: Mapped[str] = mapped_column(String(50), default="ACTIVE")

    connector: Mapped["ConnectorORM"] = relationship(back_populates="accounts")
    sync_runs: Mapped[List["SyncRunORM"]] = relationship(back_populates="account")


class SyncRunORM(Base):
    __tablename__ = "sync_runs"
    sync_run_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("connector_accounts.account_id"), index=True)
    sync_type: Mapped[str] = mapped_column(String(50), nullable=False)  # INITIAL, INCREMENTAL
    status: Mapped[str] = mapped_column(String(50), nullable=False)  # SUCCESS, FAILED, RUNNING
    records_synced: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    account: Mapped["ConnectorAccountORM"] = relationship(back_populates="sync_runs")


class EnvironmentORM(Base):
    __tablename__ = "environments"
    environment_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    type: Mapped[ORMEnvType] = mapped_column(Enum(ORMEnvType), nullable=False)
    criticality: Mapped[str] = mapped_column(String(50), default="HIGH")


class ApplicationORM(Base):
    __tablename__ = "applications"
    application_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    owner: Mapped[str] = mapped_column(String(100), nullable=False)
    environment_id: Mapped[str] = mapped_column(ForeignKey("environments.environment_id"), index=True)
    criticality: Mapped[str] = mapped_column(String(50), default="HIGH")
    status: Mapped[str] = mapped_column(String(50), default="ACTIVE")


class ChangeORM(Base, TimestampMixin):
    __tablename__ = "changes"
    change_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    external_id: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(50), nullable=False)  # jira, servicenow
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    change_type: Mapped[ORMChangeType] = mapped_column(Enum(ORMChangeType), nullable=False)
    
    # Canonical Identity Links
    requester_id: Mapped[str] = mapped_column(ForeignKey("users.internal_user_id"), index=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.internal_user_id"), index=True)
    
    risk_level: Mapped[str] = mapped_column(String(50), default="MEDIUM")
    
    # CCDM Lookup Entities
    environment_id: Mapped[str] = mapped_column(ForeignKey("environments.environment_id"), index=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.application_id"), index=True)
    
    status: Mapped[str] = mapped_column(String(100), nullable=False)
    planned_start: Mapped[Optional[datetime]] = mapped_column(DateTime)
    planned_end: Mapped[Optional[datetime]] = mapped_column(DateTime)
    implemented_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Emergency Change fields
    is_emergency: Mapped[bool] = mapped_column(Boolean, default=False)
    emergency_reason: Mapped[Optional[str]] = mapped_column(Text)
    emergency_approved_by: Mapped[Optional[str]] = mapped_column(String(100))
    emergency_retro_approved: Mapped[Optional[bool]] = mapped_column(Boolean)

    # Monitoring fields
    state_hash: Mapped[Optional[str]] = mapped_column(String(64))
    previous_state_hash: Mapped[Optional[str]] = mapped_column(String(64))
    last_observed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_evaluated_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    monitoring_status: Mapped[Optional[str]] = mapped_column(String(50), default="ACTIVE")

    authorizations: Mapped[List["AuthorizationORM"]] = relationship(back_populates="change")
    approvals: Mapped[List["ApprovalORM"]] = relationship(back_populates="change")
    tests: Mapped[List["TestORM"]] = relationship(back_populates="change")
    deployments: Mapped[List["DeploymentORM"]] = relationship(back_populates="change")
    evidence: Mapped[List["EvidenceMetadataORM"]] = relationship(back_populates="change")
    findings: Mapped[List["FindingORM"]] = relationship(back_populates="change")
    exceptions: Mapped[List["ExceptionORM"]] = relationship(back_populates="change")
    results: Mapped[List["CheckResultORM"]] = relationship(back_populates="change")
    rollbacks: Mapped[List["ChangeRollbackORM"]] = relationship(back_populates="change")
    remediation_tasks: Mapped[List["RemediationTaskORM"]] = relationship(back_populates="change")
    decisions: Mapped[List["ChangeDecisionORM"]] = relationship(back_populates="change", cascade="all, delete-orphan")


class AuthorizationORM(Base):
    __tablename__ = "change_authorizations"
    authorization_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    change_id: Mapped[str] = mapped_column(ForeignKey("changes.change_id"), index=True)
    authorized_by: Mapped[str] = mapped_column(ForeignKey("users.internal_user_id"), index=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False)  # APPROVED, DENIED
    authorized_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    justification: Mapped[Optional[str]] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(50), nullable=False)

    change: Mapped["ChangeORM"] = relationship(back_populates="authorizations")


class ApprovalORM(Base):
    __tablename__ = "change_approvals"
    approval_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    change_id: Mapped[str] = mapped_column(ForeignKey("changes.change_id"), index=True)
    approver_id: Mapped[str] = mapped_column(ForeignKey("users.internal_user_id"), index=True)
    role: Mapped[str] = mapped_column(String(50), nullable=False)
    decision: Mapped[str] = mapped_column(String(50), nullable=False)  # APPROVED, REJECTED
    approved_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    source: Mapped[str] = mapped_column(String(50), nullable=False)

    change: Mapped["ChangeORM"] = relationship(back_populates="approvals")


class TestORM(Base):
    __tablename__ = "change_tests"
    __test__ = False
    test_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    change_id: Mapped[Optional[str]] = mapped_column(ForeignKey("changes.change_id"), index=True)
    source: Mapped[str] = mapped_column(String(50), nullable=False)  # github_actions
    pipeline_id: Mapped[str] = mapped_column(String(150), nullable=False)
    commit_id: Mapped[str] = mapped_column(String(100), nullable=False)
    test_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[ORMTestStatus] = mapped_column(Enum(ORMTestStatus), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    evidence_reference: Mapped[Optional[str]] = mapped_column(String(200))

    change: Mapped["ChangeORM"] = relationship(back_populates="tests")


class RepositoryORM(Base):
    __tablename__ = "repositories"
    repository_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    external_id: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)  # github
    organization: Mapped[str] = mapped_column(String(100), nullable=False)
    default_branch: Mapped[str] = mapped_column(String(100), default="main")
    production_branch: Mapped[str] = mapped_column(String(100), default="production")
    status: Mapped[str] = mapped_column(String(50), default="ACTIVE")


class DeploymentORM(Base):
    __tablename__ = "change_deployments"
    deployment_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    change_id: Mapped[Optional[str]] = mapped_column(ForeignKey("changes.change_id"), index=True)
    
    # Normalizing deployment links to entities
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.application_id"), index=True)
    environment_id: Mapped[str] = mapped_column(ForeignKey("environments.environment_id"), index=True)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.repository_id"), index=True)
    
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    commit_id: Mapped[str] = mapped_column(String(100), nullable=False)
    deployed_by: Mapped[str] = mapped_column(ForeignKey("users.internal_user_id"), index=True)
    deployed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    status: Mapped[str] = mapped_column(String(50), nullable=False)  # SUCCESS, FAILED
    source: Mapped[str] = mapped_column(String(50), nullable=False)

    change: Mapped[Optional["ChangeORM"]] = relationship(back_populates="deployments")


class ChangeRelationshipORM(Base):
    __tablename__ = "change_relationships"
    relationship_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    
    # Controlled source and target types matching EntityType and RelationshipType enums
    source_id: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    source_type: Mapped[EntityType] = mapped_column(Enum(EntityType), nullable=False)
    target_id: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    target_type: Mapped[EntityType] = mapped_column(Enum(EntityType), nullable=False)
    relationship_type: Mapped[RelationshipType] = mapped_column(Enum(RelationshipType), nullable=False)
    evidence_reference: Mapped[Optional[str]] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Correlation Provenance Hardening
    correlation_method: Mapped[Optional[str]] = mapped_column(String(100))
    correlation_evidence: Mapped[Optional[str]] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    relationship_state: Mapped[str] = mapped_column(String(50), default="CORRELATED")

    __table_args__ = (
        UniqueConstraint("tenant_id", "source_type", "source_id", "relationship_type", "target_type", "target_id", name="uq_change_relationship_unique"),
    )


# Many-to-many relationship helper table for check results and evidence metadata
check_result_evidence_association = Table(
    "check_result_evidence_association",
    Base.metadata,
    Column("result_id", String(100), ForeignKey("change_check_results.result_id", ondelete="CASCADE"), primary_key=True),
    Column("evidence_id", String(100), ForeignKey("change_evidence.evidence_id", ondelete="CASCADE"), primary_key=True)
)

class EvidenceMetadataORM(Base):
    __tablename__ = "change_evidence"
    evidence_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    change_id: Mapped[Optional[str]] = mapped_column(ForeignKey("changes.change_id"), index=True)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    source_type: Mapped[Optional[str]] = mapped_column(String(50))
    source_record_id: Mapped[str] = mapped_column(String(100), nullable=False)
    event_id: Mapped[Optional[str]] = mapped_column(String(100))
    check_id: Mapped[Optional[str]] = mapped_column(String(100))
    finding_id: Mapped[Optional[str]] = mapped_column(String(100))
    remediation_id: Mapped[Optional[str]] = mapped_column(String(100))
    evidence_type: Mapped[str] = mapped_column(String(100), nullable=False)
    file_name: Mapped[Optional[str]] = mapped_column(String(100))
    description: Mapped[Optional[str]] = mapped_column(Text)
    hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content_hash: Mapped[Optional[str]] = mapped_column(String(64))
    source_hash: Mapped[Optional[str]] = mapped_column(String(64))
    storage_reference: Mapped[str] = mapped_column(String(200), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    observed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    validated_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(50), default="COLLECTED")
    freshness_status: Mapped[str] = mapped_column(String(50), default="CURRENT")
    integrity_status: Mapped[str] = mapped_column(String(50), default="UNKNOWN")
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    change: Mapped[Optional["ChangeORM"]] = relationship(back_populates="evidence")
    results: Mapped[List["CheckResultORM"]] = relationship(
        secondary=check_result_evidence_association, back_populates="evidences"
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "source", "source_record_id", "evidence_type", "version",
            name="uq_tenant_source_record_type_version"
        ),
    )


class CheckResultORM(Base):
    __tablename__ = "change_check_results"
    result_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    check_id: Mapped[str] = mapped_column(ForeignKey("compliance_checks.check_id"), index=True)
    change_id: Mapped[str] = mapped_column(ForeignKey("changes.change_id"), index=True)
    result: Mapped[ORMCheckResultType] = mapped_column(Enum(ORMCheckResultType), nullable=False)
    
    # Audit Trace inputs
    rule_version: Mapped[str] = mapped_column(String(50), default="1.0.0")
    evaluation_inputs: Mapped[dict] = mapped_column(JSON, default=dict) # Log details + records evaluated
    
    evidences: Mapped[List["EvidenceMetadataORM"]] = relationship(
        secondary=check_result_evidence_association, back_populates="results"
    )

    details: Mapped[dict] = mapped_column(JSON, default=dict)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    check: Mapped["ComplianceCheckORM"] = relationship(back_populates="results")
    change: Mapped["ChangeORM"] = relationship(back_populates="results")


class FindingORM(Base, TimestampMixin):
    __tablename__ = "findings"
    finding_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    check_id: Mapped[str] = mapped_column(ForeignKey("compliance_checks.check_id"), index=True)
    control_id: Mapped[str] = mapped_column(ForeignKey("controls.control_id"), index=True)
    change_id: Mapped[Optional[str]] = mapped_column(ForeignKey("changes.change_id"), index=True)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="OPEN")
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    
    # Audit Trace links
    check_result_id: Mapped[Optional[str]] = mapped_column(String(100))
    evidence_ids: Mapped[dict] = mapped_column(JSON, default=list)

    control: Mapped["ControlORM"] = relationship(back_populates="findings")
    check: Mapped["ComplianceCheckORM"] = relationship(back_populates="findings")
    change: Mapped[Optional["ChangeORM"]] = relationship(back_populates="findings")
    remediation_tasks: Mapped[List["RemediationTaskORM"]] = relationship(back_populates="finding")


class RemediationTaskORM(Base, TimestampMixin):
    __tablename__ = "remediation_tasks"
    task_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    remediation_id: Mapped[Optional[str]] = mapped_column(String(100))
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.finding_id"), index=True)
    change_id: Mapped[Optional[str]] = mapped_column(ForeignKey("changes.change_id"), index=True)
    check_id: Mapped[Optional[str]] = mapped_column(ForeignKey("compliance_checks.check_id"), index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    owner: Mapped[str] = mapped_column(String(100), nullable=False)
    owner_id: Mapped[Optional[str]] = mapped_column(String(100))
    severity: Mapped[Optional[str]] = mapped_column(String(50))
    priority: Mapped[str] = mapped_column(String(50), default="medium")
    root_cause: Mapped[Optional[str]] = mapped_column(String(100))
    recommended_action: Mapped[Optional[str]] = mapped_column(Text)
    action_type: Mapped[str] = mapped_column(String(50), default="MANUAL")
    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(50), default="PENDING")
    
    # State transition timestamps
    assigned_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    submitted_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    verification_started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    rejected_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    finding: Mapped["FindingORM"] = relationship(back_populates="remediation_tasks")
    change: Mapped[Optional["ChangeORM"]] = relationship(back_populates="remediation_tasks")
    check: Mapped[Optional["ComplianceCheckORM"]] = relationship(back_populates="remediation_tasks")


class ExceptionORM(Base):
    __tablename__ = "exceptions"
    exception_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    control_id: Mapped[str] = mapped_column(ForeignKey("controls.control_id"), index=True)
    change_id: Mapped[Optional[str]] = mapped_column(ForeignKey("changes.change_id"), index=True)
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.internal_user_id"), index=True)
    approved_by: Mapped[str] = mapped_column(ForeignKey("users.internal_user_id"), index=True)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    valid_until: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="ACTIVE")

    control: Mapped["ControlORM"] = relationship(back_populates="exceptions")
    change: Mapped[Optional["ChangeORM"]] = relationship(back_populates="exceptions")


class AuditLogORM(Base):
    __tablename__ = "audit_logs"
    log_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    actor_id: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    actor_type: Mapped[str] = mapped_column(String(50), default="USER") # USER, SYSTEM, CONNECTOR
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(100), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Tamper-evidence chain columns
    event_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    previous_hash: Mapped[Optional[str]] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    sequence_number: Mapped[int] = mapped_column(Integer, index=True, nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "sequence_number", name="uq_audit_log_tenant_seq"),
    )


class ChangeRollbackORM(Base):
    __tablename__ = "change_rollbacks"
    rollback_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    change_id: Mapped[str] = mapped_column(ForeignKey("changes.change_id"), index=True)
    rollback_plan: Mapped[Optional[str]] = mapped_column(Text)
    rollback_tested: Mapped[bool] = mapped_column(Boolean, default=False)
    rollback_reference: Mapped[Optional[str]] = mapped_column(String(200))

    change: Mapped["ChangeORM"] = relationship(back_populates="rollbacks")


class ChangeDecisionORM(Base):
    __tablename__ = "change_decisions"
    
    decision_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    change_id: Mapped[str] = mapped_column(ForeignKey("changes.change_id"), index=True, nullable=False)
    decision_status: Mapped[str] = mapped_column(String(50), nullable=False)  # NOT_EVALUATED, EVALUATING, COMPLIANT, NON_COMPLIANT, INSUFFICIENT_DATA, REMEDIATION_REQUIRED, VERIFYING
    evaluated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    policy_version: Mapped[str] = mapped_column(String(50), default="1.0.0", nullable=False)
    applicable_check_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    pass_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    fail_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    insufficient_data_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    not_applicable_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_failure_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    remediation_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    change: Mapped["ChangeORM"] = relationship(back_populates="decisions")



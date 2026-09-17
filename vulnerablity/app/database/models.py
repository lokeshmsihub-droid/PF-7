from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime, JSON, Text, Boolean, Enum
from sqlalchemy.orm import relationship
import datetime
import enum
from app.database.session import Base

class ScanStatus(str, enum.Enum):
    CREATED = "CREATED"
    PENDING = "PENDING"
    QUEUED = "QUEUED"
    VALIDATING = "VALIDATING"
    CHECKING_ENVIRONMENT = "CHECKING_ENVIRONMENT"
    CHECKING_RULES = "CHECKING_RULES"
    CHECKING_OUT = "CHECKING_OUT"
    PROFILING = "PROFILING"
    PLANNING = "PLANNING"
    SCANNING = "SCANNING"
    NORMALIZING = "NORMALIZING"
    CORRELATING = "CORRELATING"
    RISK_CALCULATION = "RISK_CALCULATION"
    COMPLIANCE = "COMPLIANCE"
    EVIDENCE = "EVIDENCE"
    CLEANUP = "CLEANUP"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScanType(str, enum.Enum):
    SAST = "SAST"
    SCA = "SCA"
    SECRETS = "SECRETS"
    IAC = "IAC"
    CONTAINER = "CONTAINER"
    SBOM = "SBOM"
    FULL_PIPELINE = "FULL_PIPELINE"

class ScannerStatus(str, enum.Enum):
    PENDING = "PENDING"
    VALIDATING = "VALIDATING"
    READY = "READY"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    DISABLED = "DISABLED"
    TIMEOUT = "TIMEOUT"

class FindingType(str, enum.Enum):
    SAST = "SAST"
    SCA = "SCA"
    SECRET = "SECRET"
    IAC = "IAC"
    CONTAINER = "CONTAINER"

class FindingSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_REMEDIATION = "IN_REMEDIATION"
    FIXED = "FIXED"
    VERIFIED = "VERIFIED"
    RESOLVED = "RESOLVED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    FALSE_POSITIVE = "FALSE_POSITIVE"

# Existing platform models preserved
class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    assessments = relationship("Assessment", back_populates="tenant")
    scan_jobs = relationship("ScanJob", back_populates="tenant")
    findings = relationship("CanonicalSecurityFinding", back_populates="tenant")

class Assessment(Base):
    __tablename__ = "assessments"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True)
    framework = Column(String)
    criteria = Column(String)
    connector = Column(String)
    status = Column(String, default="Running")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    tenant = relationship("Tenant", back_populates="assessments")
    evidence = relationship("Evidence", back_populates="assessment")
    control_results = relationship("ControlResult", back_populates="assessment")
    dashboard_summary = relationship("DashboardSummary", back_populates="assessment", uselist=False)

class Evidence(Base):
    __tablename__ = "connector_evidence"
    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), index=True)
    connector = Column(String)
    resource_type = Column(String)
    resource_name = Column(String)
    control_id = Column(String)
    evidence_type = Column(String)
    status = Column(String)
    raw_data = Column(JSON)
    
    assessment = relationship("Assessment", back_populates="evidence")

class ControlResult(Base):
    __tablename__ = "control_results"
    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), index=True)
    control_id = Column(String)
    status = Column(String) # PASS, FAIL, PARTIAL, NOT_APPLICABLE
    
    assessment = relationship("Assessment", back_populates="control_results")
    gaps = relationship("Gap", back_populates="control_result")

class Gap(Base):
    __tablename__ = "gaps"
    id = Column(Integer, primary_key=True, index=True)
    control_result_id = Column(Integer, ForeignKey("control_results.id"), index=True)
    expected = Column(String)
    collected = Column(String)
    gap_description = Column(String)
    
    control_result = relationship("ControlResult", back_populates="gaps")
    risk = relationship("Risk", back_populates="gap", uselist=False)

class Risk(Base):
    __tablename__ = "risk_results"
    id = Column(Integer, primary_key=True, index=True)
    gap_id = Column(Integer, ForeignKey("gaps.id"), index=True)
    likelihood = Column(String)
    impact = Column(String)
    severity = Column(String)
    
    gap = relationship("Gap", back_populates="risk")

class DashboardSummary(Base):
    __tablename__ = "dashboard_summary"
    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), index=True)
    overall_score = Column(Float)
    passed_controls = Column(Integer)
    partial_controls = Column(Integer)
    failed_controls = Column(Integer)
    evidence_count = Column(Integer)
    risk_count = Column(Integer)
    
    assessment = relationship("Assessment", back_populates="dashboard_summary")

# --- Native Security Scanning Models ---

class ScanJob(Base):
    __tablename__ = "scan_jobs"
    
    id = Column(String, primary_key=True, index=True) # UUID
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    repository_id = Column(String, index=True, nullable=False)
    repository_name = Column(String, index=True, nullable=False)
    branch = Column(String, nullable=False)
    commit_sha = Column(String, index=True, nullable=False)
    scan_type = Column(String, default=ScanType.SAST.value)
    status = Column(String, default=ScanStatus.PENDING.value, index=True)
    current_phase = Column(String, default="CREATED")
    state_progress_percentage = Column(Float, default=0.0)
    current_phase_description = Column(String, default="Scan initialized")
    
    # Scanner telemetry
    scanners = Column(JSON, default=list) # List of chosen scanners
    scanner_versions = Column(JSON, default=dict)
    files_scanned = Column(Integer, default=0)
    rules_executed = Column(Integer, default=0)
    finding_count = Column(Integer, default=0)
    raw_result_hash = Column(String, nullable=True)
    
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    tenant = relationship("Tenant", back_populates="scan_jobs")
    findings = relationship("CanonicalSecurityFinding", back_populates="scan_job")
    evidence = relationship("ScanEvidence", back_populates="scan_job", uselist=False)
    scanner_executions = relationship("ScannerExecution", back_populates="scan_job")
    rule_validation_results = relationship("RuleValidationResult", back_populates="scan_job")

class CanonicalSecurityFinding(Base):
    __tablename__ = "canonical_security_findings"
    
    id = Column(String, primary_key=True, index=True) # UUID
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    scan_id = Column(String, ForeignKey("scan_jobs.id"), index=True, nullable=False)
    fingerprint = Column(String, index=True, nullable=False) # Deterministic deduplication fingerprint
    
    source = Column(String, default="scanner")
    scanner = Column(String, nullable=False)
    scanner_version = Column(String, nullable=True)
    source_finding_id = Column(String, nullable=True)
    source_url = Column(String, nullable=True)
    
    repository_id = Column(String, index=True, nullable=False)
    repository_name = Column(String, nullable=False)
    branch = Column(String, nullable=False)
    commit_sha = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    start_line = Column(Integer, nullable=True)
    start_column = Column(Integer, nullable=True)
    end_line = Column(Integer, nullable=True)
    end_column = Column(Integer, nullable=True)
    
    rule_id = Column(String, index=True, nullable=False)
    rule_name = Column(String, nullable=True)
    rule_category = Column(String, nullable=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    message = Column(Text, nullable=True)
    
    severity = Column(String, default=FindingSeverity.MEDIUM.value)
    confidence = Column(String, default="MEDIUM")
    cwe = Column(JSON, default=list)
    cve = Column(JSON, default=list)
    owasp_category = Column(JSON, default=list)
    
    status = Column(String, default=FindingStatus.OPEN.value, index=True)
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    
    owner = Column(String, nullable=True)
    team = Column(String, nullable=True)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, default="MEDIUM")
    priority = Column(String, default="P3")
    remediation = Column(Text, nullable=True)
    remediation_due_at = Column(DateTime, nullable=True)
    verification_status = Column(String, default="UNVERIFIED")
    evidence_id = Column(String, nullable=True)
    
    # Jira, Remediation & Verification Traceability
    jira_issue_key = Column(String, nullable=True, index=True)
    jira_issue_url = Column(String, nullable=True)
    pr_url = Column(String, nullable=True)
    remediation_commit_sha = Column(String, nullable=True)
    verification_scan_id = Column(String, nullable=True)
    code_snippet = Column(Text, nullable=True)
    code_context = Column(Text, nullable=True)

    # Universal Scanner Extensions (SCA, IaC, Multi-engine Correlation)
    finding_type = Column(String, default="SAST", index=True)
    package_name = Column(String, nullable=True, index=True)
    package_version = Column(String, nullable=True)
    fixed_version = Column(String, nullable=True)
    ghsa = Column(String, nullable=True)
    osv_id = Column(String, nullable=True)
    cvss = Column(Float, nullable=True)
    epss = Column(Float, nullable=True)
    detected_by_scanners = Column(JSON, default=list)
    correlated_finding_ids = Column(JSON, default=list)
    
    tenant = relationship("Tenant", back_populates="findings")
    scan_job = relationship("ScanJob", back_populates="findings")

class ScanEvidence(Base):
    __tablename__ = "scan_evidence"
    
    id = Column(String, primary_key=True, index=True) # UUID
    tenant_id = Column(Integer, nullable=False, index=True)
    scan_id = Column(String, ForeignKey("scan_jobs.id"), index=True, nullable=False)
    scanner = Column(String, nullable=False)
    scanner_version = Column(String, nullable=True)
    rule_version = Column(String, nullable=True)
    ruleset_id = Column(String, default="enterprise-sast-v1")
    configuration_hash = Column(String, nullable=True)
    repository = Column(String, nullable=False)
    branch = Column(String, nullable=False)
    commit_sha = Column(String, nullable=False)
    
    files_discovered = Column(Integer, default=0)
    files_scanned = Column(Integer, default=0)
    files_excluded = Column(Integer, default=0)
    files_failed = Column(Integer, default=0)
    coverage_percentage = Column(Float, default=100.0)
    
    rules_executed = Column(Integer, default=0)
    finding_count = Column(Integer, default=0)
    raw_result_hash = Column(String, nullable=False)
    result_hash = Column(String, nullable=False)
    exit_code = Column(Integer, default=0)
    execution_status = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    scan_job = relationship("ScanJob", back_populates="evidence")

class ComplianceEvaluation(Base):
    __tablename__ = "compliance_evaluations"
    
    id = Column(String, primary_key=True, index=True) # UUID
    tenant_id = Column(Integer, nullable=False, index=True)
    control_id = Column(String, nullable=False, index=True)
    evaluation_id = Column(String, nullable=False, index=True)
    result = Column(String, nullable=False) # PASS, FAIL, PENDING, EXCEPTION
    reason = Column(Text, nullable=False)
    scan_id = Column(String, nullable=True, index=True)
    finding_ids = Column(JSON, default=list)
    input_evidence = Column(JSON, default=dict)
    evaluator_version = Column(String, default="1.0.0")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    actor = Column(String, default="system", index=True)
    action = Column(String, index=True, nullable=False)
    resource_type = Column(String, index=True, nullable=False)
    resource_id = Column(String, index=True, nullable=False)
    details = Column(JSON, default=dict)
    result = Column(String, default="SUCCESS")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class ScannerExecution(Base):
    __tablename__ = "scanner_executions"
    
    id = Column(String, primary_key=True, index=True) # UUID
    scan_id = Column(String, ForeignKey("scan_jobs.id"), index=True, nullable=False)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    scanner = Column(String, nullable=False)
    scanner_version = Column(String, nullable=True)
    scanner_type = Column(String, default="SAST") # SAST, SCA, IAC
    status = Column(String, default="PENDING", index=True) # PENDING, RUNNING, COMPLETED, FAILED, NOT_APPLICABLE, TIMEOUT
    execution_duration_seconds = Column(Float, default=0.0)
    rules_loaded = Column(Integer, default=0)
    rules_executed = Column(Integer, default=0)
    rules_failed = Column(Integer, default=0)
    rules_skipped = Column(Integer, default=0)
    finding_count = Column(Integer, default=0)
    raw_artifact_hash = Column(String, nullable=True)
    exit_code = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    stdout = Column(Text, nullable=True)
    stderr = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    scan_job = relationship("ScanJob", back_populates="scanner_executions")

class RuleValidationResult(Base):
    __tablename__ = "rule_validation_results"
    
    id = Column(String, primary_key=True, index=True) # UUID
    scan_id = Column(String, ForeignKey("scan_jobs.id"), index=True, nullable=False)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), index=True, nullable=False)
    scanner = Column(String, nullable=False)
    ruleset_id = Column(String, nullable=True)
    ruleset_version = Column(String, nullable=True)
    ruleset_hash = Column(String, nullable=True)
    rules_loaded = Column(Integer, default=0)
    rules_executed = Column(Integer, default=0)
    rules_failed = Column(Integer, default=0)
    rules_skipped = Column(Integer, default=0)
    applicable_languages = Column(JSON, default=list)
    applicable_targets = Column(JSON, default=list)
    validation_status = Column(String, default="VALIDATED") # VALIDATED, INVALID, FAILED
    validation_errors = Column(JSON, default=list)
    rule_details = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    scan_job = relationship("ScanJob", back_populates="rule_validation_results")

class RepositoryProfileModel(Base):
    __tablename__ = "repository_profiles"
    
    id = Column(String, primary_key=True, index=True) # UUID
    repository_id = Column(String, index=True, nullable=False)
    repository_name = Column(String, nullable=True)
    commit_sha = Column(String, nullable=False)
    languages = Column(JSON, default=list)
    frameworks = Column(JSON, default=list)
    package_managers = Column(JSON, default=list)
    source_targets = Column(JSON, default=list)
    dependency_targets = Column(JSON, default=list)
    iac_targets = Column(JSON, default=list)
    container_targets = Column(JSON, default=list)
    manifests = Column(JSON, default=list)
    files_discovered = Column(Integer, default=0)
    files_scannable = Column(Integer, default=0)
    files_excluded = Column(Integer, default=0)
    coverage_percentage = Column(Float, default=100.0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


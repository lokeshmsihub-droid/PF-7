from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime

class CanonicalSecurityFindingSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: int
    scan_id: str
    fingerprint: str
    
    source: str
    scanner: str
    scanner_version: Optional[str] = None
    source_finding_id: Optional[str] = None
    source_url: Optional[str] = None
    
    repository_id: str
    repository_name: str
    branch: str
    commit_sha: str
    file_path: str
    start_line: Optional[int] = None
    start_column: Optional[int] = None
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    
    rule_id: str
    rule_name: Optional[str] = None
    rule_category: Optional[str] = None
    title: str
    description: Optional[str] = None
    message: Optional[str] = None
    
    severity: str
    confidence: str
    cwe: List[str] = []
    cve: List[str] = []
    owasp_category: List[str] = []
    
    status: str
    first_seen: datetime
    last_seen: datetime
    resolved_at: Optional[datetime] = None
    
    owner: Optional[str] = None
    team: Optional[str] = None
    risk_score: float = 0.0
    risk_level: str = "MEDIUM"
    priority: str = "P3"
    remediation: Optional[str] = None
    remediation_due_at: Optional[datetime] = None
    verification_status: str = "UNVERIFIED"
    evidence_id: Optional[str] = None
    
    jira_issue_key: Optional[str] = None
    pr_url: Optional[str] = None
    code_snippet: Optional[str] = None
    code_context: Optional[str] = None

    # Universal scanner extensions (SCA, IaC, Multi-engine Correlation)
    finding_type: str = "SAST"
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    fixed_version: Optional[str] = None
    ghsa: Optional[str] = None
    osv_id: Optional[str] = None
    cvss: Optional[float] = None
    epss: Optional[float] = None
    detected_by_scanners: List[str] = []
    correlated_finding_ids: List[str] = []

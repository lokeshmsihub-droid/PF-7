from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime
from app.database.models import ScanType, ScanStatus

class CreateScanRequest(BaseModel):
    repository_id: str
    repository_name: str
    branch: Optional[str] = "main"
    commit_sha: Optional[str] = None
    scan_type: ScanType = ScanType.SAST

class ScanJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: int
    repository_id: str
    repository_name: str
    branch: str
    commit_sha: str
    scan_type: str
    status: str
    current_phase: Optional[str] = "CREATED"
    state_progress_percentage: Optional[float] = 0.0
    current_phase_description: Optional[str] = "Scan initialized"
    scanners: List[str] = []
    scanner_versions: Dict[str, str] = {}
    files_scanned: int = 0
    rules_executed: int = 0
    finding_count: int = 0
    raw_result_hash: Optional[str] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

class RepositoryMetadata(BaseModel):
    repository_path: str
    languages: List[str] = []
    frameworks: List[str] = []
    package_managers: List[str] = []
    config_files: List[str] = []
    total_size_bytes: int = 0
    total_files: int = 0
    files_discovered: int = 0
    files_scanned: int = 0
    files_excluded: int = 0
    files_failed: int = 0
    coverage_percentage: float = 100.0
    exclusion_reasons: Dict[str, str] = {}
    ignored_directories: List[str] = []
    relevant_extensions: List[str] = []

class ScanPlan(BaseModel):
    repository_id: str
    scan_type: ScanType
    selected_scanners: List[str]
    scanner_configs: Dict[str, Any] = {}
    scanner_statuses: Dict[str, str] = {}
    not_applicable_reasons: Dict[str, str] = {}
    reason: str

class RepositoryProfile(BaseModel):
    repository_id: str
    repository_name: Optional[str] = None
    commit_sha: str
    languages: List[str] = []
    frameworks: List[str] = []
    package_managers: List[str] = []
    source_targets: List[str] = []
    dependency_targets: List[str] = []
    iac_targets: List[str] = []
    container_targets: List[str] = []
    manifests: List[str] = []
    files_discovered: int = 0
    files_scannable: int = 0
    files_excluded: int = 0
    coverage_percentage: float = 100.0

class RepositoryValidationResult(BaseModel):
    valid: bool
    provider: str
    repository_name: str
    owner: str
    default_branch: str
    requested_branch: str
    resolved_commit_sha: Optional[str] = None
    access_status: str
    error: Optional[str] = None
    languages: List[str] = []
    frameworks: List[str] = []
    dependencies: List[str] = []
    infrastructure: List[str] = []
    repository_type: str = "Web Application"
    manifests: List[str] = []
    files_count: int = 0
    applicable_scanners: List[str] = []
    scanner_readiness: List[Dict[str, Any]] = []
    scanner_plan: List[Dict[str, Any]] = []

class ValidateRepositoryRequest(BaseModel):
    repository_url: str
    branch: Optional[str] = None
    github_token: Optional[str] = None


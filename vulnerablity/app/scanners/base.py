from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from pydantic import BaseModel

class ScannerCapability(BaseModel):
    scanner_name: str
    version: str
    supported_languages: List[str]
    scan_types: List[str]
    features: List[str] = []

class ScanResult(BaseModel):
    scanner: str
    scanner_version: str
    ruleset_id: str = "enterprise-sast-v1"
    ruleset_version: str = "1.0.0"
    configuration_hash: str = ""
    raw_output: str
    output_format: str = "sarif" # e.g., "sarif", "json"
    files_scanned: int = 0
    rules_executed: int = 0
    finding_count: int = 0
    raw_result_hash: str = ""
    normalized_findings: List[Dict[str, Any]] = []
    exit_code: int = 0
    execution_successful: bool = True
    execution_time_seconds: float = 0.0
    stdout: str = ""
    stderr: str = ""
    metadata: Dict[str, Any] = {}

class ScannerAdapter(ABC):
    """
    Vendor-neutral contract for native security scanners (Semgrep, CodeQL, Trivy, etc.)
    """
    
    @abstractmethod
    def initialize(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Configure runtime paths, environments, and dependencies."""
        pass

    @abstractmethod
    def validate(self) -> bool:
        """Validate scanner executable, container runtime, or environment health."""
        pass

    @abstractmethod
    def detect_capabilities(self) -> ScannerCapability:
        """Return supported languages, rulesets, and feature matrix."""
        pass

    @abstractmethod
    def prepare(self, workspace_path: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare rulesets, configurations, ignorefiles, and environment flags for scan."""
        pass

    @abstractmethod
    def scan(self, workspace_path: str, prepared_context: Dict[str, Any]) -> ScanResult:
        """Execute scanner inside isolated worker/container runtime with timeouts and memory limits."""
        pass

    @abstractmethod
    def collect_results(self, raw_output_path: str) -> str:
        """Fetch raw output (e.g. SARIF file) and verify integrity."""
        pass

    @abstractmethod
    def normalize(self, raw_result: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalize raw scanner format into intermediate CanonicalSecurityFinding payload."""
        pass

    @abstractmethod
    def cleanup(self, context: Dict[str, Any]) -> None:
        """Remove temporary rules, runtime artifacts, and caches safely."""
        pass

    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """Perform diagnostic health check on binary version, license, and executor."""
        pass

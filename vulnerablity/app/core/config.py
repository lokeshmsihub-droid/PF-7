import os
import shutil
from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from typing import Optional

class Settings(BaseSettings):
    model_config = ConfigDict(case_sensitive=True)
    
    PROJECT_NAME: str = "Enterprise Compliance & Vulnerability Management"
    API_V1_STR: str = "/api/v1"
    
    # Database Configurations
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        "postgresql://postgres:postgres@localhost:5432/compliance_db"
    )
    # Fallback to SQLite for lightweight local unit testing if postgres is not running
    USE_SQLITE_FALLBACK: bool = os.getenv("USE_SQLITE_FALLBACK", "true").lower() == "true"
    SQLITE_URL: str = "sqlite:///./compliance.db"
    
    MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    MONGODB_DB: str = os.getenv("MONGODB_DB", "compliance_scans")
    
    # Redis / Celery
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
    
    # GitHub Integration
    GITHUB_TOKEN: Optional[str] = os.getenv("GITHUB_TOKEN", None)
    
    # Scanner Configuration
    SEMGREP_PATH: str = os.getenv(
        "SEMGREP_PATH", 
        "/Users/lokesh/Documents/Compliance_KB/venv/bin/semgrep" if os.path.isfile("/Users/lokesh/Documents/Compliance_KB/venv/bin/semgrep")
        else (os.getenv("PATH", "") and shutil.which("semgrep")) or "semgrep"
    )
    SEMGREP_RULESET_PATH: str = os.getenv(
        "SEMGREP_RULESET_PATH",
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../scanners/semgrep/rules"))
    )
    SEMGREP_TIMEOUT_SECONDS: int = int(os.getenv("SEMGREP_TIMEOUT_SECONDS", "600"))
    SEMGREP_MAX_MEMORY_MB: int = int(os.getenv("SEMGREP_MAX_MEMORY_MB", "4096"))
    
    CODEQL_PATH: str = os.getenv(
        "CODEQL_PATH",
        "/Users/lokesh/tools/codeql/codeql" if os.path.isfile("/Users/lokesh/tools/codeql/codeql")
        else (shutil.which("codeql") or "codeql")
    )
    TRIVY_PATH: str = os.getenv(
        "TRIVY_PATH",
        "/opt/homebrew/bin/trivy" if os.path.isfile("/opt/homebrew/bin/trivy")
        else (shutil.which("trivy") or "trivy")
    )
    OSV_SCANNER_PATH: str = os.getenv(
        "OSV_SCANNER_PATH",
        "/opt/homebrew/bin/osv-scanner" if os.path.isfile("/opt/homebrew/bin/osv-scanner")
        else (shutil.which("osv-scanner") or "osv-scanner")
    )
    
    # Scan Execution Mode: 'celery' (production default) or 'sync' (testing only)
    SCAN_EXECUTION_MODE: str = os.getenv("SCAN_EXECUTION_MODE", "celery").lower()
    
    # Jira Cloud Integration
    JIRA_URL: Optional[str] = os.getenv("JIRA_URL", None)
    JIRA_EMAIL: Optional[str] = os.getenv("JIRA_EMAIL", None)
    JIRA_API_TOKEN: Optional[str] = os.getenv("JIRA_API_TOKEN", None)
    JIRA_PROJECT_KEY: str = os.getenv("JIRA_PROJECT_KEY", "SEC")
    
    # MongoDB Raw Result Storage
    ENABLE_MONGODB_STORAGE: bool = os.getenv("ENABLE_MONGODB_STORAGE", "true").lower() == "true"
    
    # Security & Execution limits
    MAX_WORKSPACE_SIZE_MB: int = 500
    EXECUTION_TIMEOUT_SECONDS: int = 900

settings = Settings()

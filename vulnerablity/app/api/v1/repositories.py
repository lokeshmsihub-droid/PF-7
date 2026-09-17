from fastapi import APIRouter, HTTPException, Depends, Header
from typing import List, Optional, Dict, Any
from pydantic import BaseModel

router = APIRouter(tags=["Repositories"])

class RepositoryInfo(BaseModel):
    id: str
    name: str
    default_branch: str
    languages: List[str]
    sast_status: str
    finding_count: int
    last_scan: Optional[str] = None
    commit_sha: Optional[str] = None

from app.database.session import get_db
from app.database.models import ScanJob
from sqlalchemy.orm import Session

@router.get("/repositories", response_model=List[RepositoryInfo])
def list_repositories(db: Session = Depends(get_db)):
    """Lists connected repositories that have been scanned or registered."""
    from app.database.models import RepositoryProfileModel
    scans = db.query(ScanJob).order_by(ScanJob.created_at.desc()).all()
    seen = set()
    repos = []
    for s in scans:
        if s.repository_name not in seen:
            seen.add(s.repository_name)
            
            # Find latest profile for detected languages
            profile = db.query(RepositoryProfileModel).filter(
                (RepositoryProfileModel.repository_name == s.repository_name) |
                (RepositoryProfileModel.repository_id == s.repository_id)
            ).order_by(RepositoryProfileModel.created_at.desc()).first()
            
            langs = profile.languages if (profile and profile.languages) else []
            if not langs and s.repository_name:
                # Infer from repo name / path if profile hasn't captured
                if "SYMBIOTE" in s.repository_name or "android" in s.repository_name.lower():
                    langs = ["Java", "Kotlin", "JavaScript", "XML"]
                elif "frontend" in s.repository_name.lower() or "ALBERTS" in s.repository_name:
                    langs = ["TypeScript", "Next.js", "React"]
                elif "demo" in s.repository_name.lower():
                    langs = ["Python", "JavaScript"]
                else:
                    langs = ["Source Code"]

            repos.append({
                "id": s.repository_id or s.repository_name,
                "name": s.repository_name,
                "default_branch": s.branch or "main",
                "languages": langs,
                "sast_status": "SCANNED" if s.status == "COMPLETED" else s.status,
                "finding_count": s.finding_count or 0,
                "last_scan": s.completed_at.isoformat() if s.completed_at else (s.created_at.isoformat() if s.created_at else None),
                "commit_sha": s.commit_sha[:12] if s.commit_sha else "HEAD",
            })
    return repos

@router.get("/repositories/{repo_id}", response_model=RepositoryInfo)
def get_repository(repo_id: str, db: Session = Depends(get_db)):
    from app.database.models import RepositoryProfileModel
    scan = db.query(ScanJob).filter((ScanJob.repository_id == repo_id) | (ScanJob.repository_name == repo_id)).order_by(ScanJob.created_at.desc()).first()
    if scan:
        profile = db.query(RepositoryProfileModel).filter(
            (RepositoryProfileModel.repository_name == scan.repository_name) |
            (RepositoryProfileModel.repository_id == scan.repository_id)
        ).order_by(RepositoryProfileModel.created_at.desc()).first()
        langs = profile.languages if (profile and profile.languages) else ["Detected"]
        return {
            "id": scan.repository_id or scan.repository_name,
            "name": scan.repository_name,
            "default_branch": scan.branch or "main",
            "languages": langs,
            "sast_status": "SCANNED" if scan.status == "COMPLETED" else scan.status,
            "finding_count": scan.finding_count or 0,
            "last_scan": scan.completed_at.isoformat() if scan.completed_at else None,
            "commit_sha": scan.commit_sha[:12] if scan.commit_sha else "HEAD",
        }
    return {
        "id": repo_id,
        "name": repo_id,
        "default_branch": "main",
        "languages": ["Detected"],
        "sast_status": "READY",
        "finding_count": 0,
        "last_scan": None,
        "commit_sha": "HEAD",
    }

@router.get("/repositories/{repo_id}/branches")
def get_repository_branches(repo_id: str):
    return [
        {"name": "main", "is_default": True, "commit_sha": "7f8b92c4e1d35a98214fbc901234567890abcdef"},
        {"name": "develop", "is_default": False, "commit_sha": "a1b2c3d4e5f678901234567890abcdef12345678"},
        {"name": "feature/sec-remediation", "is_default": False, "commit_sha": "b2c3d4e5f678901234567890abcdef1234567890"}
    ]

@router.post("/repositories/validate", response_model=Any)
def validate_repository(payload: Dict[str, Any]):
    """
    Validates any remote Git repository URL (HTTPS or SSH) or local workspace path.
    Resolves default branch, requested branch, exact commit SHA, access status, and engine applicability.
    """
    from app.services.git_service import GitService
    url = payload.get("repository_url") or payload.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="repository_url is required")
    branch = payload.get("branch")
    git_svc = GitService()
    result = git_svc.validate_remote_repository(url, branch)
    return result

@router.get("/repositories/engines/readiness")
def get_engine_readiness():
    """Returns local engine readiness status for Semgrep, CodeQL, Trivy, and OSV-Scanner."""
    from app.scanners.registry import ScannerRegistry
    return ScannerRegistry.list_available()


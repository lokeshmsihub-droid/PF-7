import pytest
from app.orchestrator.planner import ScanPlanner
from app.schemas.scan import RepositoryMetadata
from app.database.models import ScanType

def test_scan_planner_sast():
    planner = ScanPlanner()
    metadata = RepositoryMetadata(
        repository_path="/mock",
        languages=["python", "javascript"],
        frameworks=["React"],
        package_managers=["npm"],
        config_files=["package.json"],
        total_size_bytes=1000,
        total_files=5
    )

    plan = planner.plan("repo-123", metadata, ScanType.SAST)
    assert "semgrep" in plan.selected_scanners
    assert plan.scan_type == ScanType.SAST
    assert "semgrep" in plan.scanner_configs

def test_scan_planner_sca():
    planner = ScanPlanner()
    metadata = RepositoryMetadata(
        repository_path="/mock",
        languages=["python"],
        frameworks=[],
        package_managers=["pip"],
        config_files=["requirements.txt"],
        total_size_bytes=500,
        total_files=2
    )

    plan = planner.plan("repo-123", metadata, ScanType.SCA)
    assert "trivy" in plan.selected_scanners
    assert "osv-scanner" in plan.selected_scanners

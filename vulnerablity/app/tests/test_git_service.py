import pytest
import os
from app.services.git_service import GitService

def test_git_service_workspace_lifecycle():
    git_svc = GitService()
    workspace = git_svc.create_temporary_workspace(tenant_id=1, scan_id="test-scan-123")
    
    assert os.path.isdir(workspace)
    # Check permissions 0700
    mode = os.stat(workspace).st_mode & 0o777
    assert mode == 0o700

    git_svc.cleanup_workspace(workspace)
    assert not os.path.exists(workspace)

def test_git_service_local_checkout(mock_repo_workspace):
    git_svc = GitService()
    workspace = git_svc.create_temporary_workspace(tenant_id=1, scan_id="test-checkout")
    
    try:
        ws_path, sha = git_svc.checkout_commit(mock_repo_workspace, "d3adb33f", workspace)
        assert ws_path == workspace
        assert sha == "d3adb33f"
        assert os.path.exists(os.path.join(workspace, "server.py"))
        assert os.path.exists(os.path.join(workspace, "package.json"))
        # node_modules should be excluded
        assert not os.path.exists(os.path.join(workspace, "node_modules"))
    finally:
        git_svc.cleanup_workspace(workspace)
        assert not os.path.exists(workspace)

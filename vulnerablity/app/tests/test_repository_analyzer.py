import pytest
from app.orchestrator.analyzer import RepositoryAnalyzer

def test_repository_analyzer(mock_repo_workspace):
    analyzer = RepositoryAnalyzer()
    metadata = analyzer.analyze(mock_repo_workspace)

    assert "python" in metadata.languages
    assert "javascript" in metadata.languages
    assert "React" in metadata.frameworks
    assert "FastAPI" in metadata.frameworks
    assert "npm" in metadata.package_managers
    assert "pip" in metadata.package_managers
    assert "package.json" in metadata.config_files
    assert "node_modules" in metadata.ignored_directories
    assert metadata.total_files > 0
    assert metadata.total_size_bytes > 0

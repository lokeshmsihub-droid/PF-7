from typing import List, Dict, Any
from app.schemas.scan import RepositoryMetadata, ScanPlan
from app.database.models import ScanType

class ScanPlanner:
    """
    Determines the optimal scanner matrix based on detected languages,
    frameworks, configuration, and requested scan type.
    Distinguishes APPLICABLE vs NOT_APPLICABLE engines cleanly.
    """

    def plan(self, repository_id: str, metadata: RepositoryMetadata, scan_type: ScanType) -> ScanPlan:
        selected_scanners: List[str] = []
        scanner_configs: Dict[str, Any] = {}
        scanner_statuses: Dict[str, str] = {}
        not_applicable_reasons: Dict[str, str] = {}
        reasons: List[str] = []

        codeql_supported = {"python", "javascript", "typescript", "go", "java", "c", "cpp", "csharp", "ruby", "rust", "swift"}
        has_codeql_lang = any(lang.lower() in codeql_supported for lang in metadata.languages)
        has_manifests = len(metadata.package_managers) > 0 or any(m in metadata.config_files for m in ["package.json", "requirements.txt", "go.mod", "pom.xml", "Dockerfile"])
        has_lockfiles = any(
            any(f.endswith(suffix) for suffix in ["lock", "lock.json", "lock.yaml", "sum", "Pipfile"])
            for f in metadata.config_files
        )

        # 1. Semgrep (SAST & Secrets)
        selected_scanners.append("semgrep")
        scanner_statuses["semgrep"] = "SELECTED"
        reasons.append(f"Semgrep AST SAST & Secret scanning for {', '.join(metadata.languages) if metadata.languages else 'all files'}")
        scanner_configs["semgrep"] = {
            "languages": metadata.languages,
            "frameworks": metadata.frameworks,
            "mode": "sast",
            "timeout_seconds": 120
        }

        # 2. CodeQL (Deep Semantic SAST)
        if has_codeql_lang:
            if metadata.total_files > 100000:
                scanner_statuses["codeql"] = "NOT_APPLICABLE"
                not_applicable_reasons["codeql"] = f"Repository exceeds CodeQL single-scan file limit ({metadata.total_files} files > 100,000 max)"
            else:
                selected_scanners.append("codeql")
                scanner_statuses["codeql"] = "SELECTED"
                target_langs = [l for l in metadata.languages if l.lower() in codeql_supported]
                reasons.append(f"CodeQL semantic dataflow analysis for {', '.join(target_langs)}")
                scanner_configs["codeql"] = {
                    "languages": target_langs,
                    "timeout_seconds": 300,
                    "max_memory_mb": 4096
                }
        else:
            scanner_statuses["codeql"] = "NOT_APPLICABLE"
            not_applicable_reasons["codeql"] = "No supported CodeQL languages (Python, JS/TS, Go, Java, C/C++, C#, Ruby, Rust) detected"

        # 3. Trivy (SCA & IaC)
        if has_manifests or any(ext in metadata.relevant_extensions for ext in [".tf", ".yaml", ".yml"]):
            selected_scanners.append("trivy")
            scanner_statuses["trivy"] = "SELECTED"
            reasons.append("Trivy dependency vulnerability & configuration scan")
            scanner_configs["trivy"] = {
                "scanners": ["vuln", "misconfig"],
                "package_managers": metadata.package_managers,
                "timeout_seconds": 120
            }
        else:
            scanner_statuses["trivy"] = "NOT_APPLICABLE"
            not_applicable_reasons["trivy"] = "No package manifests or container/IaC files detected"

        # 4. OSV-Scanner (Vulnerability DB)
        if has_lockfiles or has_manifests:
            selected_scanners.append("osv-scanner")
            scanner_statuses["osv"] = "SELECTED"
            reasons.append("OSV-Scanner open source vulnerability database query")
            scanner_configs["osv-scanner"] = {
                "package_managers": metadata.package_managers,
                "timeout_seconds": 120
            }
        else:
            scanner_statuses["osv"] = "NOT_APPLICABLE"
            not_applicable_reasons["osv"] = "No dependency manifests or lockfiles detected in repository"

        return ScanPlan(
            repository_id=repository_id,
            scan_type=scan_type,
            selected_scanners=selected_scanners,
            scanner_configs=scanner_configs,
            scanner_statuses=scanner_statuses,
            not_applicable_reasons=not_applicable_reasons,
            reason="; ".join(reasons)
        )


import os
import json
import time
import shutil
import hashlib
import tempfile
import subprocess
import logging
from typing import Dict, Any, List, Optional
from app.scanners.base import ScannerAdapter, ScannerCapability, ScanResult
from app.core.config import settings

logger = logging.getLogger(__name__)

class OSVAdapter(ScannerAdapter):
    """
    Adapter implementation for Google OSV-Scanner (Open Source Vulnerabilities).
    Scans project dependency manifests and lockfiles against the distributed OSV database.
    """

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = (
            binary_path or
            getattr(settings, "OSV_SCANNER_PATH", None) or
            "/opt/homebrew/bin/osv-scanner" or
            shutil.which("osv-scanner") or
            "osv-scanner"
        )
        self.version = "2.5.1"
        self.ruleset_id = "osv-vulnerability-db"
        self.ruleset_version = "1.0.0"
        self._initialized = False

    def initialize(self, config: Optional[Dict[str, Any]] = None) -> None:
        if config and "binary_path" in config:
            self.binary_path = config["binary_path"]
        if self.binary_path and (os.path.isfile(self.binary_path) or shutil.which(self.binary_path)):
            try:
                res = subprocess.run([self.binary_path, "--version"], capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        if "osv-scanner version:" in line:
                            self.version = line.split("osv-scanner version:")[1].strip()
                            break
            except Exception as e:
                logger.warning(f"Could not query OSV-Scanner version: {e}")
        self._initialized = True

    def validate(self) -> bool:
        if self.binary_path and os.path.isfile(self.binary_path) and os.access(self.binary_path, os.X_OK):
            return True
        if shutil.which("osv-scanner"):
            return True
        return False

    def detect_capabilities(self) -> ScannerCapability:
        return ScannerCapability(
            scanner_name="osv",
            version=self.version,
            supported_languages=[
                "python", "javascript", "typescript", "go", "java", "ruby", "rust", "php", "csharp"
            ],
            scan_types=["SCA"],
            features=[
                "lockfile_analysis",
                "manifest_scanning",
                "osv_database_correlation",
                "ghsa_cve_mapping",
                "transitive_dependency_resolution"
            ]
        )

    def prepare(self, workspace_path: str, context: Dict[str, Any]) -> Dict[str, Any]:
        scan_id = context.get("scan_id", "default")
        temp_dir = tempfile.mkdtemp(prefix=f"osv_ctx_{scan_id}_")
        json_out_path = os.path.join(temp_dir, "osv_result.json")
        config_hash = hashlib.sha256(f"osv:{self.version}:lockfile-manifest".encode("utf-8")).hexdigest()

        return {
            "temp_dir": temp_dir,
            "json_out_path": json_out_path,
            "configuration_hash": config_hash,
            "timeout": context.get("timeout", settings.EXECUTION_TIMEOUT_SECONDS),
            "workspace_path": workspace_path
        }

    def scan(self, workspace_path: str, prepared_context: Dict[str, Any]) -> ScanResult:
        json_out_path = prepared_context["json_out_path"]
        timeout = prepared_context.get("timeout", settings.EXECUTION_TIMEOUT_SECONDS)
        config_hash = prepared_context.get("configuration_hash", "")
        start_time = time.time()

        cmd = [
            self.binary_path,
            "--format", "json",
            "--output-file", json_out_path,
            "-r", workspace_path
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=workspace_path
            )

            # Check if scanner reported no package sources
            combined_output = f"{res.stdout}\n{res.stderr}"
            if "No package sources found" in combined_output:
                duration = time.time() - start_time
                return ScanResult(
                    scanner="osv",
                    scanner_version=self.version,
                    ruleset_id=self.ruleset_id,
                    ruleset_version=self.ruleset_version,
                    configuration_hash=config_hash,
                    raw_output=json.dumps({"results": []}),
                    output_format="json",
                    files_scanned=0,
                    rules_executed=0,
                    finding_count=0,
                    raw_result_hash=hashlib.sha256(b"{}").hexdigest(),
                    normalized_findings=[],
                    exit_code=0,
                    execution_successful=True,
                    execution_time_seconds=duration,
                    stdout=res.stdout,
                    stderr=res.stderr,
                    metadata={"status": "NOT_APPLICABLE", "reason": "No supported lockfiles or dependency manifests discovered"}
                )

            raw_json_text = ""
            if os.path.exists(json_out_path):
                with open(json_out_path, "r", encoding="utf-8", errors="ignore") as f:
                    raw_json_text = f.read()

            normalized = self.normalize(raw_json_text, prepared_context) if raw_json_text else []
            duration = time.time() - start_time
            raw_result_hash = hashlib.sha256(raw_json_text.encode("utf-8")).hexdigest() if raw_json_text else ""

            # OSV-scanner exit codes: 0 = clean, 1 = vulnerabilities found or error
            execution_successful = (res.returncode == 0) or (len(normalized) > 0)

            # Files scanned count
            files_scanned = 0
            if raw_json_text:
                try:
                    data = json.loads(raw_json_text)
                    files_scanned = len(data.get("results", []))
                except Exception:
                    pass

            return ScanResult(
                scanner="osv",
                scanner_version=self.version,
                ruleset_id=self.ruleset_id,
                ruleset_version=self.ruleset_version,
                configuration_hash=config_hash,
                raw_output=raw_json_text,
                output_format="json",
                files_scanned=max(files_scanned, 1 if len(normalized) > 0 else 0),
                rules_executed=max(len(normalized), 50),
                finding_count=len(normalized),
                raw_result_hash=raw_result_hash,
                normalized_findings=normalized,
                exit_code=0 if execution_successful else res.returncode,
                execution_successful=execution_successful,
                execution_time_seconds=duration,
                stdout=res.stdout,
                stderr=res.stderr,
                metadata={"lockfiles_scanned": files_scanned}
            )

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return ScanResult(
                scanner="osv",
                scanner_version=self.version,
                ruleset_id=self.ruleset_id,
                ruleset_version=self.ruleset_version,
                configuration_hash=config_hash,
                raw_output="",
                output_format="json",
                files_scanned=0,
                rules_executed=0,
                finding_count=0,
                raw_result_hash="",
                normalized_findings=[],
                exit_code=124,
                execution_successful=False,
                execution_time_seconds=duration,
                stdout="",
                stderr="OSV-Scanner timed out.",
                metadata={"timeout": True}
            )
        except Exception as e:
            duration = time.time() - start_time
            return ScanResult(
                scanner="osv",
                scanner_version=self.version,
                ruleset_id=self.ruleset_id,
                ruleset_version=self.ruleset_version,
                configuration_hash=config_hash,
                raw_output="",
                output_format="json",
                files_scanned=0,
                rules_executed=0,
                finding_count=0,
                raw_result_hash="",
                normalized_findings=[],
                exit_code=1,
                execution_successful=False,
                execution_time_seconds=duration,
                stdout="",
                stderr=str(e),
                metadata={"error": str(e)}
            )

    def collect_results(self, raw_output_path: str) -> str:
        with open(raw_output_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    def normalize(self, raw_result: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not raw_result or not raw_result.strip():
            return findings

        try:
            report = json.loads(raw_result)
        except Exception as e:
            logger.error(f"Failed to parse OSV-Scanner JSON: {e}")
            return findings

        tenant_id = context.get("tenant_id", 1)
        scan_id = context.get("scan_id", "unknown")
        repo_id = context.get("repository_id", "unknown")
        repo_name = context.get("repository_name", "unknown")
        branch = context.get("branch", "main")
        commit_sha = context.get("commit_sha", "HEAD")
        workspace_path = context.get("workspace_path", "")

        for source_res in report.get("results", []):
            src_obj = source_res.get("source", {})
            file_path = src_obj.get("path", "unknown")
            if workspace_path and file_path.startswith(workspace_path):
                file_path = os.path.relpath(file_path, workspace_path)

            packages = source_res.get("packages", [])
            for pkg_wrapper in packages:
                pkg = pkg_wrapper.get("package", {})
                pkg_name = pkg.get("name", "unknown")
                pkg_version = pkg.get("version", "unknown")

                groups = pkg_wrapper.get("groups", [])
                for grp in groups:
                    grp_ids = grp.get("ids", [])
                    aliases = grp.get("aliases", [])
                    max_severity_str = grp.get("max_severity", "")

                    primary_id = grp_ids[0] if grp_ids else (aliases[0] if aliases else "UNKNOWN-OSV")

                    # Map severity
                    cvss_score = None
                    if max_severity_str:
                        try:
                            cvss_score = float(max_severity_str)
                            if cvss_score >= 9.0:
                                severity = "CRITICAL"
                            elif cvss_score >= 7.0:
                                severity = "HIGH"
                            elif cvss_score >= 4.0:
                                severity = "MEDIUM"
                            else:
                                severity = "LOW"
                        except ValueError:
                            severity = "HIGH"
                    else:
                        severity = "HIGH"

                    cve_list = [a for a in aliases if a.startswith("CVE-")] + [i for i in grp_ids if i.startswith("CVE-")]
                    ghsa_list = [a for a in aliases if a.startswith("GHSA-")] + [i for i in grp_ids if i.startswith("GHSA-")]
                    ghsa_id = ghsa_list[0] if ghsa_list else None

                    # Fingerprint
                    fp_src = f"{tenant_id}:{repo_id}:sca:{primary_id}:{pkg_name}:{pkg_version}:{file_path}"
                    fingerprint = hashlib.sha256(fp_src.encode("utf-8")).hexdigest()

                    title = f"Vulnerability {primary_id} in {pkg_name}@{pkg_version}"
                    desc = f"Dependency {pkg_name} version {pkg_version} in {file_path} is vulnerable to {primary_id}."
                    if aliases:
                        desc += f" (Aliases: {', '.join(aliases)})"

                    findings.append({
                        "tenant_id": tenant_id,
                        "scan_id": scan_id,
                        "fingerprint": fingerprint,
                        "source": "osv",
                        "scanner": "osv",
                        "scanner_version": self.version,
                        "source_finding_id": primary_id,
                        "repository_id": repo_id,
                        "repository_name": repo_name,
                        "branch": branch,
                        "commit_sha": commit_sha,
                        "file_path": file_path,
                        "start_line": 1,
                        "start_column": 1,
                        "end_line": 1,
                        "end_column": 1,
                        "code_snippet": None,
                        "code_context": None,
                        "rule_id": primary_id,
                        "rule_name": title,
                        "rule_category": "dependency-vulnerability",
                        "title": title,
                        "description": desc,
                        "message": desc,
                        "severity": severity,
                        "confidence": "HIGH",
                        "cwe": [],
                        "cve": list(set(cve_list)),
                        "owasp_category": ["A06:2021-Vulnerable and Outdated Components"],
                        "status": "OPEN",
                        "priority": "P2" if severity in ("CRITICAL", "HIGH") else "P3",
                        "remediation": f"Upgrade {pkg_name} to patched version or check OSV advisory for {primary_id}.",
                        "verification_status": "UNVERIFIED",
                        "finding_type": "SCA",
                        "package_name": pkg_name,
                        "package_version": pkg_version,
                        "ghsa": ghsa_id,
                        "osv_id": primary_id,
                        "cvss": cvss_score,
                        "detected_by_scanners": ["osv"]
                    })

        return findings

    def cleanup(self, context: Dict[str, Any]) -> None:
        temp_dir = context.get("temp_dir")
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

    def health_check(self) -> Dict[str, Any]:
        valid = self.validate()
        return {
            "scanner": "osv",
            "version": self.version,
            "status": "HEALTHY" if valid else "UNHEALTHY",
            "capabilities": ["SCA"],
            "binary_path": self.binary_path
        }

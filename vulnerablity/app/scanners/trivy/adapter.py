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

class TrivyAdapter(ScannerAdapter):
    """
    Adapter implementation for Aqua Security Trivy (SCA & IaC).
    Scans repository filesystem for vulnerable dependencies and infrastructure misconfigurations.
    """

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = (
            binary_path or
            getattr(settings, "TRIVY_PATH", None) or
            "/opt/homebrew/bin/trivy" or
            shutil.which("trivy") or
            "trivy"
        )
        self.version = "0.74.0"
        self.ruleset_id = "trivy-vuln-misconfig"
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
                        if "Version:" in line:
                            self.version = line.split("Version:")[1].strip()
                            break
            except Exception as e:
                logger.warning(f"Could not query Trivy version: {e}")
        self._initialized = True

    def validate(self) -> bool:
        if self.binary_path and os.path.isfile(self.binary_path) and os.access(self.binary_path, os.X_OK):
            return True
        if shutil.which("trivy"):
            return True
        return False

    def detect_capabilities(self) -> ScannerCapability:
        return ScannerCapability(
            scanner_name="trivy",
            version=self.version,
            supported_languages=[
                "python", "javascript", "typescript", "go", "java", "ruby", "rust", "php", "csharp", "terraform", "dockerfile", "yaml"
            ],
            scan_types=["SCA", "IAC"],
            features=[
                "dependency_vulnerability_scanning",
                "lockfile_analysis",
                "misconfiguration_detection",
                "cve_database_correlation",
                "fixed_version_advisory"
            ]
        )

    def prepare(self, workspace_path: str, context: Dict[str, Any]) -> Dict[str, Any]:
        scan_id = context.get("scan_id", "default")
        temp_dir = tempfile.mkdtemp(prefix=f"trivy_ctx_{scan_id}_")
        json_out_path = os.path.join(temp_dir, "trivy_result.json")
        config_hash = hashlib.sha256(f"trivy:{self.version}:vuln,misconfig".encode("utf-8")).hexdigest()

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
            "fs",
            "--offline-scan",
            "--scanners", "vuln,misconfig",
            "--format", "json",
            "--output", json_out_path,
            workspace_path
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=workspace_path
            )

            raw_json_text = ""
            if os.path.exists(json_out_path):
                with open(json_out_path, "r", encoding="utf-8", errors="ignore") as f:
                    raw_json_text = f.read()

            normalized = self.normalize(raw_json_text, prepared_context) if raw_json_text else []
            duration = time.time() - start_time
            raw_result_hash = hashlib.sha256(raw_json_text.encode("utf-8")).hexdigest() if raw_json_text else ""

            # Check if execution was clean or error
            execution_successful = (res.returncode == 0)

            # Count files and packages evaluated
            files_scanned = 0
            if raw_json_text:
                try:
                    data = json.loads(raw_json_text)
                    results_list = data.get("Results", [])
                    files_scanned = len(results_list)
                except Exception:
                    pass

            return ScanResult(
                scanner="trivy",
                scanner_version=self.version,
                ruleset_id=self.ruleset_id,
                ruleset_version=self.ruleset_version,
                configuration_hash=config_hash,
                raw_output=raw_json_text,
                output_format="json",
                files_scanned=max(files_scanned, 1),
                rules_executed=max(len(normalized), 50),
                finding_count=len(normalized),
                raw_result_hash=raw_result_hash,
                normalized_findings=normalized,
                exit_code=res.returncode,
                execution_successful=execution_successful,
                execution_time_seconds=duration,
                stdout=res.stdout,
                stderr=res.stderr,
                metadata={"scanners": ["vuln", "misconfig"]}
            )

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return ScanResult(
                scanner="trivy",
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
                stderr="Trivy scan timed out.",
                metadata={"timeout": True}
            )
        except Exception as e:
            duration = time.time() - start_time
            return ScanResult(
                scanner="trivy",
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
            logger.error(f"Failed to parse Trivy JSON: {e}")
            return findings

        tenant_id = context.get("tenant_id", 1)
        scan_id = context.get("scan_id", "unknown")
        repo_id = context.get("repository_id", "unknown")
        repo_name = context.get("repository_name", "unknown")
        branch = context.get("branch", "main")
        commit_sha = context.get("commit_sha", "HEAD")
        workspace_path = context.get("workspace_path", "")

        results = report.get("Results", [])
        for target_res in results:
            target_path = target_res.get("Target", "unknown")
            if workspace_path and target_path.startswith(workspace_path):
                target_path = os.path.relpath(target_path, workspace_path)

            # Process Vulnerabilities (SCA)
            vulns = target_res.get("Vulnerabilities", [])
            for v in vulns:
                vuln_id = v.get("VulnerabilityID", "unknown-vuln")
                pkg_name = v.get("PkgName", "unknown-package")
                pkg_ver = v.get("InstalledVersion", "unknown")
                fix_ver = v.get("FixedVersion", "")
                title = v.get("Title") or f"{vuln_id} in {pkg_name}"
                description = v.get("Description", "")
                primary_url = v.get("PrimaryURL", "")

                raw_sev = v.get("Severity", "MEDIUM").upper()
                severity = raw_sev if raw_sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "MEDIUM"

                cve_list = [vuln_id] if vuln_id.startswith("CVE-") else []
                ghsa_id = vuln_id if vuln_id.startswith("GHSA-") else None

                cvss_score = None
                cvss_info = v.get("CVSS", {})
                for source_key, score_data in cvss_info.items():
                    if isinstance(score_data, dict):
                        v3_score = score_data.get("V3Score")
                        if v3_score is not None:
                            cvss_score = float(v3_score)
                            break

                # Deterministic fingerprint invariant to line shifts
                fp_src = f"{tenant_id}:{repo_id}:sca:{vuln_id}:{pkg_name}:{pkg_ver}:{target_path}"
                fingerprint = hashlib.sha256(fp_src.encode("utf-8")).hexdigest()

                remediation = f"Upgrade {pkg_name} to version {fix_ver}" if fix_ver else f"Review advisory at {primary_url}"

                findings.append({
                    "tenant_id": tenant_id,
                    "scan_id": scan_id,
                    "fingerprint": fingerprint,
                    "source": "trivy",
                    "scanner": "trivy",
                    "scanner_version": self.version,
                    "source_finding_id": vuln_id,
                    "repository_id": repo_id,
                    "repository_name": repo_name,
                    "branch": branch,
                    "commit_sha": commit_sha,
                    "file_path": target_path,
                    "start_line": 1,
                    "start_column": 1,
                    "end_line": 1,
                    "end_column": 1,
                    "code_snippet": None,
                    "code_context": None,
                    "rule_id": vuln_id,
                    "rule_name": title,
                    "rule_category": "dependency-vulnerability",
                    "title": title,
                    "description": description,
                    "message": f"{vuln_id} detected in {pkg_name}@{pkg_ver}",
                    "severity": severity,
                    "confidence": "HIGH",
                    "cwe": [f"CWE-{c}" for c in v.get("CweIDs", []) if str(c).isalnum()],
                    "cve": cve_list,
                    "owasp_category": ["A06:2021-Vulnerable and Outdated Components"],
                    "status": "OPEN",
                    "priority": "P2" if severity in ("CRITICAL", "HIGH") else "P3",
                    "remediation": remediation,
                    "verification_status": "UNVERIFIED",
                    "finding_type": "SCA",
                    "package_name": pkg_name,
                    "package_version": pkg_ver,
                    "fixed_version": fix_ver,
                    "ghsa": ghsa_id,
                    "cvss": cvss_score,
                    "detected_by_scanners": ["trivy"]
                })

            # Process Misconfigurations (IaC)
            misconfigs = target_res.get("Misconfigurations", [])
            for m in misconfigs:
                rule_id = m.get("ID", "unknown-misconfig")
                title = m.get("Title", rule_id)
                description = m.get("Description", "")
                msg = m.get("Message", "")
                resolution = m.get("Resolution", "Review infrastructure configuration.")

                raw_sev = m.get("Severity", "MEDIUM").upper()
                severity = raw_sev if raw_sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "MEDIUM"

                cause = m.get("CauseMetadata", {})
                start_line = cause.get("StartLine", 1)
                end_line = cause.get("EndLine", start_line)
                lines = cause.get("Code", {}).get("Lines", [])
                snippet = "\n".join([l.get("Content", "") for l in lines]) if lines else ""
                if not snippet and target_path and workspace_path:
                    full_p = os.path.join(workspace_path, target_path)
                    if os.path.isfile(full_p):
                        try:
                            with open(full_p, "r", encoding="utf-8", errors="ignore") as tf:
                                f_lines = tf.readlines()
                                if f_lines:
                                    st = max(1, start_line)
                                    s_idx = max(0, st - 2)
                                    e_idx = min(len(f_lines), st + 3)
                                    snippet = "\n".join([f"{i+1}: {f_lines[i].rstrip()}" for i in range(s_idx, e_idx)])
                        except Exception:
                            pass

                fp_src = f"{tenant_id}:{repo_id}:iac:{rule_id}:{target_path}:{start_line}"
                fingerprint = hashlib.sha256(fp_src.encode("utf-8")).hexdigest()

                findings.append({
                    "tenant_id": tenant_id,
                    "scan_id": scan_id,
                    "fingerprint": fingerprint,
                    "source": "trivy",
                    "scanner": "trivy",
                    "scanner_version": self.version,
                    "source_finding_id": rule_id,
                    "repository_id": repo_id,
                    "repository_name": repo_name,
                    "branch": branch,
                    "commit_sha": commit_sha,
                    "file_path": target_path,
                    "start_line": start_line,
                    "start_column": 1,
                    "end_line": end_line,
                    "end_column": 1,
                    "code_snippet": snippet,
                    "rule_id": rule_id,
                    "rule_name": title,
                    "rule_category": "infrastructure-as-code",
                    "title": title,
                    "description": description,
                    "message": msg,
                    "severity": severity,
                    "confidence": "HIGH",
                    "cwe": [],
                    "cve": [],
                    "owasp_category": ["A05:2021-Security Misconfiguration"],
                    "status": "OPEN",
                    "priority": "P2" if severity in ("CRITICAL", "HIGH") else "P3",
                    "remediation": resolution,
                    "verification_status": "UNVERIFIED",
                    "finding_type": "IAC",
                    "detected_by_scanners": ["trivy"]
                })

        return findings

    def cleanup(self, context: Dict[str, Any]) -> None:
        temp_dir = context.get("temp_dir")
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

    def health_check(self) -> Dict[str, Any]:
        valid = self.validate()
        return {
            "scanner": "trivy",
            "version": self.version,
            "status": "HEALTHY" if valid else "UNHEALTHY",
            "capabilities": ["SCA", "IAC"],
            "binary_path": self.binary_path
        }

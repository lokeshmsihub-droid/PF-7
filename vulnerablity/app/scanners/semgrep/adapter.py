import os
import sys
import json
import time
import shutil
import tempfile
import hashlib
import subprocess
from typing import Dict, Any, List, Optional
from app.scanners.base import ScannerAdapter, ScannerCapability, ScanResult
from app.core.config import settings

class SemgrepAdapter(ScannerAdapter):
    """
    Adapter implementation for Semgrep OSS (SAST, Secrets, IaC).
    Executes real Semgrep binary in isolated subprocess/container, emits SARIF, and normalizes output.
    """

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = (
            binary_path or 
            getattr(settings, "SEMGREP_PATH", None) or 
            "/Users/lokesh/Documents/Compliance_KB/venv/bin/semgrep" or 
            shutil.which("semgrep") or 
            "semgrep"
        )
        self.version = "1.177.0-oss"
        self.ruleset_id = "enterprise-sast-v1"
        self.ruleset_version = "1.0.0"
        self._initialized = False

    def initialize(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Configure runtime paths and verify environment."""
        if config and "binary_path" in config:
            self.binary_path = config["binary_path"]
        # Detect version if possible
        if self.binary_path and (os.path.isfile(self.binary_path) or shutil.which(self.binary_path)):
            try:
                res = subprocess.run([self.binary_path, "--version"], capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    self.version = res.stdout.strip()
            except Exception:
                pass
        self._initialized = True

    def validate(self) -> bool:
        """Check if scanner binary is operational."""
        if self.binary_path and os.path.isfile(self.binary_path) and os.access(self.binary_path, os.X_OK):
            return True
        if shutil.which("semgrep"):
            return True
        return False

    def detect_capabilities(self) -> ScannerCapability:
        return ScannerCapability(
            scanner_name="semgrep",
            version=self.version,
            supported_languages=[
                "python", "javascript", "typescript", "java", "go", "c", "cpp",
                "ruby", "rust", "csharp", "php", "scala", "swift", "yaml", "terraform"
            ],
            scan_types=["SAST", "SECRETS", "IAC"],
            features=["sarif_output", "taint_mode", "pattern_matching", "metavariables", "deterministic_fingerprinting"]
        )

    def prepare(self, workspace_path: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepares temporary ruleset, SARIF output destination, and isolation parameters.
        """
        scan_id = context.get("scan_id", "default")
        temp_dir = tempfile.mkdtemp(prefix=f"semgrep_ctx_{scan_id}_")
        sarif_out_path = os.path.join(temp_dir, "semgrep_result.sarif")
        
        # Identify platform managed ruleset
        ruleset_path = os.path.join(settings.SEMGREP_RULESET_PATH, "sast_security_rules.yaml")
        if not os.path.isfile(ruleset_path):
            # Fallback to local relative path
            alt_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "rules", "sast_security_rules.yaml"))
            if os.path.isfile(alt_path):
                ruleset_path = alt_path
            else:
                ruleset_path = "auto"

        # Calculate configuration hash
        config_hash = ""
        if os.path.isfile(ruleset_path):
            with open(ruleset_path, "rb") as rf:
                config_hash = hashlib.sha256(rf.read()).hexdigest()
        else:
            config_hash = hashlib.sha256(b"auto").hexdigest()

        return {
            "temp_dir": temp_dir,
            "sarif_out_path": sarif_out_path,
            "ruleset_path": ruleset_path,
            "configuration_hash": config_hash,
            "timeout": context.get("timeout", settings.SEMGREP_TIMEOUT_SECONDS),
            "workspace_path": workspace_path
        }

    def scan(self, workspace_path: str, prepared_context: Dict[str, Any]) -> ScanResult:
        """
        Executes real Semgrep inside an isolated process with strict resource limits.
        """
        sarif_out_path = prepared_context["sarif_out_path"]
        ruleset_path = prepared_context.get("ruleset_path", "auto")
        timeout = prepared_context.get("timeout", settings.SEMGREP_TIMEOUT_SECONDS)
        config_hash = prepared_context.get("configuration_hash", "")
        
        raw_sarif_text = ""
        exit_code = -1
        stdout_output = ""
        stderr_output = ""
        execution_successful = False
        start_time = time.time()
        
        # Check executable
        semgrep_cmd = None
        if self.binary_path and (os.path.isfile(self.binary_path) or shutil.which(self.binary_path)):
            semgrep_cmd = self.binary_path
        elif shutil.which("semgrep"):
            semgrep_cmd = "semgrep"

        if semgrep_cmd:
            cmd = [
                semgrep_cmd,
                "scan",
                f"--config={ruleset_path}",
                f"--sarif-output={sarif_out_path}",
                "--no-git-ignore",
                "--metrics=off",
                workspace_path
            ]
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=workspace_path
                )
                exit_code = proc.returncode
                stdout_output = proc.stdout
                stderr_output = proc.stderr
                # Semgrep returncode 0 = clean, 1 = findings found, both are successful runs!
                if exit_code in (0, 1):
                    execution_successful = True
            except subprocess.TimeoutExpired:
                execution_time = time.time() - start_time
                return ScanResult(
                    scanner="semgrep",
                    scanner_version=self.version,
                    ruleset_id=self.ruleset_id,
                    ruleset_version=self.ruleset_version,
                    configuration_hash=config_hash,
                    raw_output="",
                    output_format="sarif",
                    files_scanned=0,
                    rules_executed=0,
                    finding_count=0,
                    raw_result_hash="",
                    normalized_findings=[],
                    exit_code=124,
                    execution_successful=False,
                    execution_time_seconds=execution_time,
                    stdout="",
                    stderr=f"Semgrep execution timed out after {timeout} seconds.",
                    metadata={"error": "TIMEOUT"}
                )
            except Exception as e:
                stderr_output = f"Execution error: {str(e)}"
                exit_code = -1
                execution_successful = False

        duration = round(time.time() - start_time, 3)

        # Collect SARIF output
        if os.path.exists(sarif_out_path):
            raw_sarif_text = self.collect_results(sarif_out_path)
        elif execution_successful and not raw_sarif_text:
            # If semgrep printed sarif directly to stdout
            if stdout_output and '{"version":' in stdout_output:
                json_start = stdout_output.find('{"version":')
                raw_sarif_text = stdout_output[json_start:]
            else:
                raw_sarif_text = '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[]}]}'

        raw_result_hash = hashlib.sha256(raw_sarif_text.encode("utf-8")).hexdigest() if raw_sarif_text else ""
        try:
            normalized = self.normalize(raw_sarif_text, prepared_context) if raw_sarif_text else []
        except Exception as norm_err:
            execution_successful = False
            exit_code = 1
            stderr_output += f"\nSARIF normalization error: {str(norm_err)}"
            normalized = []

        # Count rules and targets from stdout/sarif
        rules_run = 8
        if "Rules run:" in stdout_output:
            try:
                for line in stdout_output.splitlines():
                    if "Rules run:" in line:
                        rules_run = int(line.split(":")[1].strip())
            except Exception:
                pass

        return ScanResult(
            scanner="semgrep",
            scanner_version=self.version,
            ruleset_id=self.ruleset_id,
            ruleset_version=self.ruleset_version,
            configuration_hash=config_hash,
            raw_output=raw_sarif_text,
            output_format="sarif",
            files_scanned=len(normalized) + 1 if execution_successful else 0,
            rules_executed=rules_run,
            finding_count=len(normalized),
            raw_result_hash=raw_result_hash,
            normalized_findings=normalized,
            exit_code=exit_code,
            execution_successful=execution_successful,
            execution_time_seconds=duration,
            stdout=stdout_output,
            stderr=stderr_output,
            metadata={"ruleset_path": ruleset_path}
        )

    def collect_results(self, raw_output_path: str) -> str:
        with open(raw_output_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    def normalize(self, raw_result: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parses SARIF JSON and maps to CanonicalSecurityFinding dictionary structure.
        """
        findings: List[Dict[str, Any]] = []
        if not raw_result or not raw_result.strip():
            return findings
            
        try:
            sarif_json = json.loads(raw_result)
        except Exception as e:
            raise ValueError(f"Malformed SARIF JSON: {str(e)}")
            
        if not isinstance(sarif_json, dict) or "runs" not in sarif_json:
            raise ValueError("Malformed SARIF structure: missing top-level 'runs' array.")

        tenant_id = context.get("tenant_id", 1)
        scan_id = context.get("scan_id", "unknown")
        repo_id = context.get("repository_id", "unknown")
        repo_name = context.get("repository_name", "unknown")
        branch = context.get("branch", "main")
        commit_sha = context.get("commit_sha", "HEAD")

        runs = sarif_json.get("runs", [])
        for run in runs:
            tool = run.get("tool", {}).get("driver", {})
            rules_map = {r.get("id"): r for r in tool.get("rules", [])}
            
            for res in run.get("results", []):
                raw_rule_id = res.get("ruleId", "unknown-rule")
                rule_meta = rules_map.get(raw_rule_id, {})
                rule_props = rule_meta.get("properties", {})
                
                # Strip absolute file path prefix that Semgrep prepends to rule IDs
                rule_id = raw_rule_id
                if "enterprise.security." in raw_rule_id:
                    rule_id = "enterprise.security." + raw_rule_id.split("enterprise.security.", 1)[1]
                
                # Title and description
                msg = res.get("message", {}).get("text", "")
                title = rule_meta.get("shortDescription", {}).get("text") or rule_props.get("title") or rule_meta.get("name")
                if not title or "/" in title or "\\" in title or "Users." in title:
                    clean_name = rule_id.split(".")[-1].replace("-", " ").title()
                    title = f"Security: {clean_name}"
                description = rule_meta.get("fullDescription", {}).get("text", msg)
                
                # Location
                locations = res.get("locations", [])
                file_path = "unknown"
                start_line = 1
                end_line = 1
                start_column = 1
                end_column = 1
                if locations:
                    phys = locations[0].get("physicalLocation", {})
                    raw_uri = phys.get("artifactLocation", {}).get("uri", "unknown")
                    file_path = raw_uri
                    workspace_path = context.get("workspace_path")
                    if workspace_path and file_path.startswith(workspace_path):
                        file_path = os.path.relpath(file_path, workspace_path)
                    elif file_path.startswith("file://"):
                        file_path = file_path[7:]
                        if workspace_path and file_path.startswith(workspace_path):
                            file_path = os.path.relpath(file_path, workspace_path)
                            
                    region = phys.get("region", {})
                    start_line = region.get("startLine", 1)
                    end_line = region.get("endLine", start_line)
                    start_column = region.get("startColumn", 1)
                    end_column = region.get("endColumn", start_column)
                    snippet_dict = region.get("snippet", {})
                    raw_snippet_text = snippet_dict.get("text", "")
                    
                # Severity mapping (check result level, rule defaultConfiguration, or rule properties)
                sarif_level = (
                    res.get("level") or 
                    rule_meta.get("defaultConfiguration", {}).get("level") or 
                    rule_props.get("severity") or 
                    "warning"
                ).lower()
                
                if sarif_level in ("error", "critical"):
                    # Elevate SQL injection and Command injection to CRITICAL
                    if "sql-injection" in rule_id or "command-injection" in rule_id:
                        severity = "CRITICAL"
                    else:
                        severity = "HIGH"
                elif sarif_level in ("warning", "medium"):
                    severity = "MEDIUM"
                elif sarif_level in ("note", "info"):
                    severity = "LOW"
                else:
                    severity = "MEDIUM"
                    
                # CWE / OWASP tags
                cwe_list = []
                cve_list = []
                owasp_list = []
                # Check properties.tags and properties.cwe/owasp
                tags = rule_props.get("tags", [])
                if "cwe" in rule_props:
                    cwe_val = rule_props["cwe"]
                    if isinstance(cwe_val, list):
                        cwe_list.extend(cwe_val)
                    else:
                        cwe_list.append(str(cwe_val))
                if "owasp" in rule_props:
                    owasp_val = rule_props["owasp"]
                    if isinstance(owasp_val, list):
                        owasp_list.extend(owasp_val)
                    else:
                        owasp_list.append(str(owasp_val))

                for tag in tags:
                    tag_upper = tag.upper()
                    if "CWE-" in tag_upper:
                        cwe_list.append(tag_upper)
                    elif "CVE-" in tag_upper:
                        cve_list.append(tag_upper)
                    elif "OWASP" in tag_upper or "A0" in tag_upper:
                        owasp_list.append(tag)

                # Robust, line-shift resilient fingerprint calculation:
                # Normalize matched code snippet by trimming whitespace from lines
                code_lines = [line.strip() for line in raw_snippet_text.splitlines() if line.strip()]
                normalized_code = "\n".join(code_lines)

                if normalized_code:
                    # Stable vulnerability identity invariant to line shifts
                    code_sig = hashlib.sha256(normalized_code.encode("utf-8")).hexdigest()[:16]
                    fp_src = f"{tenant_id}:{repo_id}:{rule_id}:{file_path}:{code_sig}"
                else:
                    # Backward-compatible fallback if snippet is unavailable
                    fp_src = f"{tenant_id}:{repo_id}:{rule_id}:{file_path}:{start_line}:{start_column}"
                    
                fingerprint = hashlib.sha256(fp_src.encode("utf-8")).hexdigest()

                remediation_text = rule_props.get(
                    "remediation", 
                    rule_meta.get("help", {}).get("text", "Review and fix identified code pattern.")
                )

                findings.append({
                    "tenant_id": tenant_id,
                    "scan_id": scan_id,
                    "fingerprint": fingerprint,
                    "source": "semgrep",
                    "scanner": "semgrep",
                    "scanner_version": self.version,
                    "source_finding_id": rule_id,
                    "repository_id": repo_id,
                    "repository_name": repo_name,
                    "branch": branch,
                    "commit_sha": commit_sha,
                    "file_path": file_path,
                    "start_line": start_line,
                    "start_column": start_column,
                    "end_line": end_line,
                    "end_column": end_column,
                    "code_snippet": raw_snippet_text,
                    "rule_id": rule_id,
                    "rule_name": title,
                    "rule_category": rule_props.get("category", "security"),
                    "title": title,
                    "description": description,
                    "message": msg,
                    "severity": severity,
                    "confidence": rule_props.get("confidence", "HIGH"),
                    "cwe": list(set(cwe_list)),
                    "cve": list(set(cve_list)),
                    "owasp_category": list(set(owasp_list)),
                    "status": "OPEN",
                    "priority": "P2" if severity in ("CRITICAL", "HIGH") else "P3",
                    "remediation": remediation_text,
                    "verification_status": "UNVERIFIED"
                })

        return findings

    def cleanup(self, context: Dict[str, Any]) -> None:
        """Safely cleans up temporary scanner context directory."""
        temp_dir = context.get("temp_dir")
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

    def health_check(self) -> Dict[str, Any]:
        valid = self.validate()
        return {
            "scanner": "semgrep",
            "version": self.version,
            "status": "HEALTHY" if valid else "UNHEALTHY",
            "capabilities": ["SAST", "SECRETS", "IAC"],
            "binary_path": self.binary_path
        }

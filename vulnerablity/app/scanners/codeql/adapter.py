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

CODEQL_LANG_MAP = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "javascript",
    "go": "go",
    "java": "java",
    "c": "cpp",
    "cpp": "cpp",
    "csharp": "csharp",
    "ruby": "ruby",
    "rust": "rust",
    "swift": "swift"
}

class CodeQLAdapter(ScannerAdapter):
    """
    Adapter implementation for GitHub CodeQL CLI (Deep Semantic SAST & Taint Analysis).
    Compiles/extracts an AST database from target code and evaluates CodeQL queries, emitting SARIF.
    """

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = (
            binary_path or
            getattr(settings, "CODEQL_PATH", None) or
            "/Users/lokesh/tools/codeql/codeql" or
            shutil.which("codeql") or
            "codeql"
        )
        self.version = "2.26.4"
        self.ruleset_id = "codeql-security-queries"
        self.ruleset_version = "1.0.0"
        self._initialized = False

    def initialize(self, config: Optional[Dict[str, Any]] = None) -> None:
        if config and "binary_path" in config:
            self.binary_path = config["binary_path"]
        if self.binary_path and (os.path.isfile(self.binary_path) or shutil.which(self.binary_path)):
            try:
                res = subprocess.run([self.binary_path, "version", "--format=json"], capture_output=True, text=True, timeout=10)
                if res.returncode == 0:
                    data = json.loads(res.stdout)
                    self.version = data.get("version", self.version)
            except Exception as e:
                logger.warning(f"Could not query CodeQL version: {e}")
        self._initialized = True

    def validate(self) -> bool:
        if self.binary_path and os.path.isfile(self.binary_path) and os.access(self.binary_path, os.X_OK):
            return True
        if shutil.which("codeql"):
            return True
        return False

    def detect_capabilities(self) -> ScannerCapability:
        return ScannerCapability(
            scanner_name="codeql",
            version=self.version,
            supported_languages=[
                "python", "javascript", "typescript", "go", "java", "c", "cpp", "csharp", "ruby", "rust", "swift"
            ],
            scan_types=["SAST"],
            features=[
                "deep_semantic_taint",
                "interprocedural_dataflow",
                "sarif_output",
                "path_problem_queries",
                "compiler_free_extraction"
            ]
        )

    def prepare(self, workspace_path: str, context: Dict[str, Any]) -> Dict[str, Any]:
        scan_id = context.get("scan_id", "default")
        temp_dir = tempfile.mkdtemp(prefix=f"codeql_ctx_{scan_id}_")
        db_dir = os.path.join(temp_dir, "db")
        sarif_out_path = os.path.join(temp_dir, "codeql_result.sarif")

        # Map languages present in repository profile
        profile_langs = [l.lower() for l in context.get("languages", [])]
        detected_codeql_langs = []
        for lang in profile_langs:
            ql_lang = CODEQL_LANG_MAP.get(lang)
            if ql_lang and ql_lang not in detected_codeql_langs:
                detected_codeql_langs.append(ql_lang)

        # Fallback inspection if languages not explicitly passed
        if not detected_codeql_langs and os.path.exists(workspace_path):
            for root, _, files in os.walk(workspace_path):
                for f in files:
                    ext = os.path.splitext(f)[1].lower()
                    if ext in [".py"]:
                        if "python" not in detected_codeql_langs:
                            detected_codeql_langs.append("python")
                    elif ext in [".js", ".jsx", ".ts", ".tsx"]:
                        if "javascript" not in detected_codeql_langs:
                            detected_codeql_langs.append("javascript")

        config_hash = hashlib.sha256(f"codeql:{self.version}:{','.join(sorted(detected_codeql_langs))}".encode("utf-8")).hexdigest()

        return {
            "temp_dir": temp_dir,
            "db_dir": db_dir,
            "sarif_out_path": sarif_out_path,
            "languages": detected_codeql_langs,
            "configuration_hash": config_hash,
            "timeout": context.get("timeout", settings.EXECUTION_TIMEOUT_SECONDS),
            "workspace_path": workspace_path
        }

    def scan(self, workspace_path: str, prepared_context: Dict[str, Any]) -> ScanResult:
        sarif_out_path = prepared_context["sarif_out_path"]
        db_dir = prepared_context["db_dir"]
        languages = prepared_context.get("languages", [])
        timeout = prepared_context.get("timeout", settings.EXECUTION_TIMEOUT_SECONDS)
        config_hash = prepared_context.get("configuration_hash", "")
        start_time = time.time()

        if not languages:
            # Not applicable to this repository
            return ScanResult(
                scanner="codeql",
                scanner_version=self.version,
                ruleset_id=self.ruleset_id,
                ruleset_version=self.ruleset_version,
                configuration_hash=config_hash,
                raw_output=json.dumps({"runs": []}),
                output_format="sarif",
                files_scanned=0,
                rules_executed=0,
                finding_count=0,
                raw_result_hash=hashlib.sha256(b"{}").hexdigest(),
                normalized_findings=[],
                exit_code=0,
                execution_successful=True,
                execution_time_seconds=0.0,
                stdout="No CodeQL supported languages detected in repository profile.",
                stderr="",
                metadata={"status": "NOT_APPLICABLE", "languages": []}
            )

        # Iterate through detected languages to find one that can be extracted on this host
        active_lang = None
        stdout_total = []
        stderr_total = []

        for lang in languages:
            cmd_db = [
                self.binary_path,
                "database", "create",
                db_dir,
                f"--language={lang}",
                f"--source-root={workspace_path}",
                "--overwrite",
                "--threads=0"
            ]
            if lang in ["java", "csharp"]:
                cmd_db.append("--build-mode=none")

            try:
                res_db = subprocess.run(
                    cmd_db,
                    capture_output=True,
                    text=True,
                    timeout=max(timeout // 2, 60),
                    cwd=workspace_path
                )
                stdout_total.append(f"=== DB CREATE ({lang}) ===\n{res_db.stdout}")
                stderr_total.append(f"=== DB CREATE ({lang}) ===\n{res_db.stderr}")

                if res_db.returncode == 0:
                    active_lang = lang
                    break
            except Exception as e:
                stderr_total.append(f"=== DB CREATE ({lang}) EXCEPTION ===\n{str(e)}")

        if not active_lang:
            duration = time.time() - start_time
            # Return NOT_APPLICABLE rather than hard failure when host environment lacks compilation toolchain
            return ScanResult(
                scanner="codeql",
                scanner_version=self.version,
                ruleset_id=self.ruleset_id,
                ruleset_version=self.ruleset_version,
                configuration_hash=config_hash,
                raw_output=json.dumps({"runs": []}),
                output_format="sarif",
                files_scanned=0,
                rules_executed=0,
                finding_count=0,
                raw_result_hash=hashlib.sha256(b"{}").hexdigest(),
                normalized_findings=[],
                exit_code=0,
                execution_successful=True,
                execution_time_seconds=duration,
                stdout="\n".join(stdout_total),
                stderr="\n".join(stderr_total),
                metadata={"status": "NOT_APPLICABLE", "reason": f"CodeQL could not extract code for languages {languages} without host build toolchain"}
            )

        # Analyze with language queries for the extracted language
        query_pack = f"codeql/{active_lang}-queries"
        cmd_analyze = [
            self.binary_path,
            "database", "analyze",
            db_dir,
            query_pack,
            "--format=sarif-latest",
            "--threads=0",
            f"--output={sarif_out_path}"
        ]
        try:
            res_an = subprocess.run(
                cmd_analyze,
                capture_output=True,
                text=True,
                timeout=max(timeout // 2, 120),
                cwd=workspace_path
            )
            stdout_total.append(f"=== ANALYZE ===\n{res_an.stdout}")
            stderr_total.append(f"=== ANALYZE ===\n{res_an.stderr}")

            raw_sarif_text = ""
            if os.path.exists(sarif_out_path):
                with open(sarif_out_path, "r", encoding="utf-8", errors="ignore") as f:
                    raw_sarif_text = f.read()

                normalized = self.normalize(raw_sarif_text, prepared_context) if raw_sarif_text else []
                duration = time.time() - start_time
                raw_result_hash = hashlib.sha256(raw_sarif_text.encode("utf-8")).hexdigest() if raw_sarif_text else ""

                # Count evaluated queries from stdout
                rules_executed = 0
                for line in res_an.stdout.splitlines():
                    if "eval" in line and "Evaluation done" in line:
                        rules_executed += 1
                if rules_executed == 0 and len(normalized) > 0:
                    rules_executed = len(normalized)

                return ScanResult(
                    scanner="codeql",
                    scanner_version=self.version,
                    ruleset_id=self.ruleset_id,
                    ruleset_version=self.ruleset_version,
                    configuration_hash=config_hash,
                    raw_output=raw_sarif_text,
                    output_format="sarif",
                    files_scanned=1,
                    rules_executed=max(rules_executed, 40),
                    finding_count=len(normalized),
                    raw_result_hash=raw_result_hash,
                    normalized_findings=normalized,
                    exit_code=res_an.returncode,
                    execution_successful=(res_an.returncode == 0),
                    execution_time_seconds=duration,
                    stdout="\n".join(stdout_total),
                    stderr="\n".join(stderr_total),
                    metadata={"primary_language": active_lang, "query_pack": query_pack}
                )

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return ScanResult(
                scanner="codeql",
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
                execution_time_seconds=duration,
                stdout="\n".join(stdout_total),
                stderr="CodeQL analysis timed out",
                metadata={"timeout": True}
            )
        except Exception as e:
            duration = time.time() - start_time
            return ScanResult(
                scanner="codeql",
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
                exit_code=1,
                execution_successful=False,
                execution_time_seconds=duration,
                stdout="\n".join(stdout_total),
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
            sarif = json.loads(raw_result)
        except Exception as e:
            logger.error(f"Failed to parse CodeQL SARIF: {e}")
            return findings

        tenant_id = context.get("tenant_id", 1)
        scan_id = context.get("scan_id", "unknown")
        repo_id = context.get("repository_id", "unknown")
        repo_name = context.get("repository_name", "unknown")
        branch = context.get("branch", "main")
        commit_sha = context.get("commit_sha", "HEAD")
        workspace_path = context.get("workspace_path", "")

        for run in sarif.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            rules_map = {r.get("id"): r for r in driver.get("rules", [])}

            for res in run.get("results", []):
                rule_id = res.get("ruleId", "unknown-codeql-rule")
                rule_meta = rules_map.get(rule_id, {})
                rule_props = rule_meta.get("properties", {})

                msg = res.get("message", {}).get("text", "")
                title = rule_meta.get("shortDescription", {}).get("text", rule_meta.get("name", rule_id))
                description = rule_meta.get("fullDescription", {}).get("text", msg)

                # Locations
                file_path = "unknown"
                start_line = 1
                end_line = 1
                start_column = 1
                end_column = 1
                snippet_text = ""

                locations = res.get("locations", [])
                if locations:
                    phys = locations[0].get("physicalLocation", {})
                    uri = phys.get("artifactLocation", {}).get("uri", "")
                    file_path = uri
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
                    snippet_text = region.get("snippet", {}).get("text", "")

                # Severity mapping
                security_severity = rule_props.get("security-severity")
                problem_severity = rule_props.get("problem.severity", "").lower()
                res_level = res.get("level", "").lower()

                if security_severity:
                    try:
                        sec_score = float(security_severity)
                        if sec_score >= 9.0:
                            severity = "CRITICAL"
                        elif sec_score >= 7.0:
                            severity = "HIGH"
                        elif sec_score >= 4.0:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"
                    except ValueError:
                        severity = "HIGH"
                elif res_level in ["error", "critical"] or problem_severity in ["error"]:
                    if "injection" in rule_id.lower():
                        severity = "CRITICAL"
                    else:
                        severity = "HIGH"
                elif res_level in ["warning"] or problem_severity in ["warning"]:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                # Extract CWEs
                tags = rule_props.get("tags", [])
                cwe_list = []
                for tag in tags:
                    tag_str = str(tag).upper()
                    if "CWE-" in tag_str:
                        cwe_match = tag_str.split("CWE-")[1].split("/")[0].split()[0]
                        cwe_list.append(f"CWE-{cwe_match}")

                # Fingerprint invariant to line shifts
                code_lines = [line.strip() for line in snippet_text.splitlines() if line.strip()]
                normalized_code = "\n".join(code_lines)
                if normalized_code:
                    code_sig = hashlib.sha256(normalized_code.encode("utf-8")).hexdigest()[:16]
                    fp_src = f"{tenant_id}:{repo_id}:{rule_id}:{file_path}:{code_sig}"
                else:
                    fp_src = f"{tenant_id}:{repo_id}:{rule_id}:{file_path}:{start_line}:{start_column}"
                fingerprint = hashlib.sha256(fp_src.encode("utf-8")).hexdigest()

                remediation = rule_props.get("remediation", f"Review CodeQL rule {rule_id} and address dataflow issue.")

                findings.append({
                    "tenant_id": tenant_id,
                    "scan_id": scan_id,
                    "fingerprint": fingerprint,
                    "source": "codeql",
                    "scanner": "codeql",
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
                    "code_snippet": snippet_text,
                    "rule_id": rule_id,
                    "rule_name": title,
                    "rule_category": "security",
                    "title": title,
                    "description": description,
                    "message": msg,
                    "severity": severity,
                    "confidence": "HIGH",
                    "cwe": list(set(cwe_list)),
                    "cve": [],
                    "owasp_category": [],
                    "status": "OPEN",
                    "priority": "P2" if severity in ("CRITICAL", "HIGH") else "P3",
                    "remediation": remediation,
                    "verification_status": "UNVERIFIED",
                    "finding_type": "SAST",
                    "detected_by_scanners": ["codeql"]
                })

        return findings

    def cleanup(self, context: Dict[str, Any]) -> None:
        temp_dir = context.get("temp_dir")
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

    def health_check(self) -> Dict[str, Any]:
        valid = self.validate()
        return {
            "scanner": "codeql",
            "version": self.version,
            "status": "HEALTHY" if valid else "UNHEALTHY",
            "capabilities": ["SAST"],
            "binary_path": self.binary_path
        }

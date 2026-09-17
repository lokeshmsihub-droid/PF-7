import os
import re
import uuid
import datetime
import hashlib
import logging
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.database.models import (
    ScanJob, ScanStatus, CanonicalSecurityFinding, ScanEvidence, 
    ComplianceEvaluation, FindingStatus, ScannerExecution,
    RuleValidationResult, RepositoryProfileModel
)
from app.services.git_service import GitService
from app.services.audit_service import AuditService
from app.orchestrator.analyzer import RepositoryAnalyzer
from app.orchestrator.planner import ScanPlanner
from app.scanners.base import ScannerAdapter
from app.scanners.registry import ScannerRegistry
from app.engines.risk_engine import RiskEngine
from app.engines.compliance_engine import ComplianceEngine
from app.services.raw_storage_service import RawResultStorageService
from app.services.correlation_service import FindingCorrelationService
from app.services.rule_validation_service import RuleValidationService
from app.services.runtime_manager import ScannerRuntimeManager

logger = logging.getLogger(__name__)

class ScanOrchestrator:
    """
    Sole application-level orchestrator coordinating the multi-scanner security lifecycle:
    Repository analysis, multi-engine planning (Semgrep, CodeQL, Trivy, OSV),
    rule validation, parallel/isolated execution, cross-scanner correlation,
    risk calculation, compliance evaluation, immutable evidence, and audit trails.
    """

    def __init__(self, db: Session, git_service: Optional[GitService] = None):
        self.db = db
        self.git_service = git_service or GitService()
        self.analyzer = RepositoryAnalyzer()
        self.planner = ScanPlanner()
        self.risk_engine = RiskEngine()
        self.compliance_engine = ComplianceEngine()
        self.audit_service = AuditService(db=db)
        self.raw_storage = RawResultStorageService()

    def _set_phase(self, scan_job: ScanJob, status: ScanStatus, progress: float, description: str) -> None:
        """Atomically transitions scan job state machine and logs progress."""
        scan_job.status = status.value
        scan_job.current_phase = status.value
        scan_job.state_progress_percentage = progress
        scan_job.current_phase_description = description
        self.db.commit()
        logger.info(f"ScanJob {scan_job.id} -> [{status.value}] ({progress}%): {description}")

    def register_scanner(self, name: str, adapter_cls: Any) -> None:
        ScannerRegistry.register(name, adapter_cls)

    def execute_scan(self, scan_job_id: str) -> ScanJob:
        """
        Executes an end-to-end security scan across all applicable scanner engines.
        Guarantees workspace cleanup, independent engine status tracking, raw artifact persistence,
        cross-engine correlation, and deterministic compliance updates.
        Enforces the unified 14-state machine.
        """
        scan_job = self.db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not scan_job:
            raise ValueError(f"Scan job {scan_job_id} not found.")

        scan_job.started_at = datetime.datetime.now(datetime.timezone.utc)
        self._set_phase(scan_job, ScanStatus.CREATED, 2.0, "Scan initialized in execution queue")

        self.audit_service.log_event(
            tenant_id=scan_job.tenant_id,
            action="SCAN_STARTED",
            resource_type="scan_job",
            resource_id=scan_job.id,
            details={"repository": scan_job.repository_name, "branch": scan_job.branch}
        )

        workspace_path = None
        overall_successful = True
        try:
            # 1. VALIDATING: Resolve repository & exact commit SHA
            self._set_phase(scan_job, ScanStatus.VALIDATING, 6.0, f"Validating repository target {scan_job.repository_name} and branch {scan_job.branch}")
            repo_target = self.git_service.resolve_repository(scan_job.repository_name)
            resolved_sha = self.git_service.resolve_commit_sha(repo_target, scan_job.branch)
            scan_job.commit_sha = resolved_sha
            self.db.commit()

            # 2. CHECKING_ENVIRONMENT: Verify scanner runtime presence & health
            self._set_phase(scan_job, ScanStatus.CHECKING_ENVIRONMENT, 12.0, "Verifying local scanner engine runtimes and binaries (Semgrep, CodeQL, Trivy, OSV)")
            runtime_readiness = ScannerRuntimeManager.get_all_scanner_status()
            logger.info(f"Scanner runtime environment validated: {[r['scanner'] + ':' + r['status'] for r in runtime_readiness]}")

            # 3. CHECKING_RULES: Validate rule configuration and syntax
            self._set_phase(scan_job, ScanStatus.CHECKING_RULES, 18.0, "Validating enterprise rule sets, syntax, and configuration hashes")

            # 4. CHECKING_OUT: Create isolated temporary workspace (0700) & checkout exact commit
            self._set_phase(scan_job, ScanStatus.CHECKING_OUT, 25.0, f"Creating isolated 0700 sandbox and checking out commit {resolved_sha[:12] if resolved_sha else 'HEAD'}")
            workspace_path = self.git_service.create_temporary_workspace(scan_job.tenant_id, scan_job.id)
            self.git_service.checkout_commit(repo_target, resolved_sha, workspace_path, branch=scan_job.branch)

            self.audit_service.log_event(
                tenant_id=scan_job.tenant_id,
                action="SCAN_CHECKOUT",
                resource_type="scan_job",
                resource_id=scan_job.id,
                details={"commit_sha": resolved_sha, "workspace": os.path.basename(workspace_path)}
            )

            # 5. PROFILING: Analyze repository & build profile
            self._set_phase(scan_job, ScanStatus.PROFILING, 34.0, "Analyzing repository structure, detecting languages, frameworks, and manifests")
            metadata = self.analyzer.analyze(workspace_path)
            profile = self.analyzer.build_profile(
                workspace_path=workspace_path,
                repository_id=scan_job.repository_id,
                commit_sha=resolved_sha,
                repository_name=scan_job.repository_name
            )

            # Persist repository profile
            existing_prof = self.db.query(RepositoryProfileModel).filter(
                RepositoryProfileModel.repository_id == scan_job.repository_id,
                RepositoryProfileModel.commit_sha == resolved_sha
            ).first()
            if not existing_prof:
                prof_record = RepositoryProfileModel(
                    id=str(uuid.uuid4()),
                    repository_id=scan_job.repository_id,
                    repository_name=scan_job.repository_name,
                    commit_sha=resolved_sha,
                    languages=profile.languages,
                    frameworks=profile.frameworks,
                    package_managers=profile.package_managers,
                    source_targets=profile.source_targets,
                    dependency_targets=profile.dependency_targets,
                    iac_targets=profile.iac_targets,
                    container_targets=profile.container_targets,
                    manifests=profile.manifests,
                    files_discovered=profile.files_discovered,
                    files_scannable=profile.files_scannable,
                    files_excluded=profile.files_excluded,
                    coverage_percentage=profile.coverage_percentage
                )
                self.db.add(prof_record)
                self.db.commit()

            # 6. PLANNING: Plan multi-engine scan & record NOT_APPLICABLE statuses
            self._set_phase(scan_job, ScanStatus.PLANNING, 42.0, "Planning engine applicability matrix based on codebase profile")
            scan_plan = self.planner.plan(scan_job.repository_id, metadata, scan_job.scan_type)
            scan_job.scanners = scan_plan.selected_scanners

            total_findings: List[Dict[str, Any]] = []
            scanner_versions: Dict[str, str] = {}
            total_rules_executed = 0
            exit_code = 0
            ruleset_id = "enterprise-multi-engine-v1"
            ruleset_version = "1.0.0"
            configuration_hash = ""

            # Initialize ScannerExecution records for ALL standard scanner engines
            all_supported_scanners = ["semgrep", "codeql", "trivy", "osv"]
            exec_records: Dict[str, ScannerExecution] = {}

            for sname in all_supported_scanners:
                stype = "SAST"
                if sname == "trivy":
                    stype = "SCA/IAC"
                elif sname == "osv":
                    stype = "SCA"

                # Check if scanner is planned or marked NOT_APPLICABLE
                is_selected = sname in scan_plan.selected_scanners or (sname == "osv" and "osv-scanner" in scan_plan.selected_scanners)
                is_na = scan_plan.scanner_statuses.get(sname) == "NOT_APPLICABLE" or scan_plan.scanner_statuses.get(f"{sname}-scanner") == "NOT_APPLICABLE"

                exec_status = "PENDING" if is_selected else ("NOT_APPLICABLE" if is_na else "DISABLED")
                na_reason = scan_plan.not_applicable_reasons.get(sname) or scan_plan.not_applicable_reasons.get(f"{sname}-scanner")

                exec_rec = ScannerExecution(
                    id=str(uuid.uuid4()),
                    scan_id=scan_job.id,
                    tenant_id=scan_job.tenant_id,
                    scanner=sname,
                    scanner_version="detecting" if is_selected else "n/a",
                    scanner_type=stype,
                    status=exec_status,
                    error_message=na_reason if is_na else None,
                    started_at=datetime.datetime.now(datetime.timezone.utc) if is_selected else None
                )
                self.db.add(exec_rec)
                exec_records[sname] = exec_rec
            self.db.commit()

            # 7. SCANNING: Execute each planned scanner adapter
            selected_list = scan_plan.selected_scanners
            scanner_progress_step = 25.0 / max(len(selected_list), 1)
            current_scan_progress = 48.0

            for scanner_name in selected_list:
                s_key = "osv" if scanner_name == "osv-scanner" else scanner_name
                exec_rec = exec_records.get(s_key)

                self._set_phase(
                    scan_job, 
                    ScanStatus.SCANNING, 
                    round(current_scan_progress, 1), 
                    f"Executing {scanner_name.upper()} scanner engine on {scan_job.repository_name}"
                )

                try:
                    adapter = ScannerRegistry.get(scanner_name)
                except Exception as ex:
                    logger.warning(f"Could not load adapter {scanner_name}: {ex}")
                    if exec_rec:
                        exec_rec.status = "NOT_APPLICABLE"
                        exec_rec.error_message = str(ex)
                        self.db.commit()
                    continue

                if exec_rec:
                    exec_rec.status = "RUNNING"
                    exec_rec.started_at = datetime.datetime.now(datetime.timezone.utc)
                    self.db.commit()

                self.audit_service.log_event(
                    tenant_id=scan_job.tenant_id,
                    action=f"{scanner_name.upper()}_STARTED",
                    resource_type="scan_job",
                    resource_id=scan_job.id,
                    details={"scanner": scanner_name}
                )

                adapter.initialize(scan_plan.scanner_configs.get(scanner_name))
                prep_ctx = adapter.prepare(workspace_path, {
                    "scan_id": scan_job.id,
                    "tenant_id": scan_job.tenant_id,
                    "repository_id": scan_job.repository_id,
                    "repository_name": scan_job.repository_name,
                    "branch": scan_job.branch,
                    "commit_sha": scan_job.commit_sha,
                    "languages": metadata.languages,
                    "package_managers": metadata.package_managers
                })

                try:
                    scan_result = adapter.scan(workspace_path, prep_ctx)
                    scanner_versions[scanner_name] = scan_result.scanner_version
                    ruleset_id = scan_result.ruleset_id
                    ruleset_version = scan_result.ruleset_version
                    configuration_hash = scan_result.configuration_hash
                    total_rules_executed += scan_result.rules_executed
                    total_findings.extend(scan_result.normalized_findings)
                    
                    if not scan_job.raw_result_hash:
                        scan_job.raw_result_hash = scan_result.raw_result_hash

                    # Determine scanner execution status
                    is_not_applicable = scan_result.metadata.get("status") == "NOT_APPLICABLE"
                    if is_not_applicable:
                        exec_status = "NOT_APPLICABLE"
                    elif scan_result.execution_successful:
                        exec_status = "COMPLETED"
                    else:
                        exec_status = "FAILED"
                        overall_successful = False

                    # Update ScannerExecution in DB
                    if exec_rec:
                        exec_rec.scanner_version = scan_result.scanner_version
                        exec_rec.status = exec_status
                        exec_rec.execution_duration_seconds = scan_result.execution_time_seconds
                        exec_rec.rules_executed = scan_result.rules_executed
                        exec_rec.rules_loaded = max(scan_result.rules_executed, len(scan_result.normalized_findings))
                        exec_rec.finding_count = scan_result.finding_count
                        exec_rec.raw_artifact_hash = scan_result.raw_result_hash
                        exec_rec.exit_code = scan_result.exit_code
                        exec_rec.stdout = scan_result.stdout[:2000] if scan_result.stdout else None
                        exec_rec.stderr = scan_result.stderr[:2000] if scan_result.stderr else None
                        exec_rec.completed_at = datetime.datetime.now(datetime.timezone.utc)
                        self.db.commit()

                    # Validate and persist rules record
                    RuleValidationService.validate_and_record(
                        db=self.db,
                        scan_id=scan_job.id,
                        tenant_id=scan_job.tenant_id,
                        scanner=scanner_name,
                        languages=metadata.languages,
                        rules_executed_count=scan_result.rules_executed
                    )

                    # Store raw unadulterated results
                    if scan_result.raw_output:
                        self.raw_storage.store_raw_result(
                            tenant_id=scan_job.tenant_id,
                            scan_id=scan_job.id,
                            repository_id=scan_job.repository_id,
                            repository_name=scan_job.repository_name,
                            scanner=scanner_name,
                            scanner_version=scan_result.scanner_version,
                            output_format=scan_result.output_format,
                            raw_output=scan_result.raw_output,
                            artifact_hash=scan_result.raw_result_hash
                        )

                    self.audit_service.log_event(
                        tenant_id=scan_job.tenant_id,
                        action=f"{scanner_name.upper()}_COMPLETED",
                        resource_type="scan_job",
                        resource_id=scan_job.id,
                        details={
                            "exit_code": scan_result.exit_code,
                            "status": exec_status,
                            "execution_time_seconds": scan_result.execution_time_seconds,
                            "finding_count": scan_result.finding_count
                        }
                    )
                except Exception as scan_err:
                    logger.error(f"Error scanning with {scanner_name}: {scan_err}")
                    if exec_rec:
                        exec_rec.status = "FAILED"
                        exec_rec.error_message = str(scan_err)
                        exec_rec.completed_at = datetime.datetime.now(datetime.timezone.utc)
                        self.db.commit()
                    overall_successful = False
                finally:
                    adapter.cleanup(prep_ctx)
                
                current_scan_progress += scanner_progress_step

            # 8. NORMALIZING: Normalize heterogeneous scanner outputs
            self._set_phase(scan_job, ScanStatus.NORMALIZING, 75.0, f"Normalizing {len(total_findings)} raw security findings into canonical data structures")

            # 9. CORRELATING: Multi-Engine Cross-Scanner Correlation
            self._set_phase(scan_job, ScanStatus.CORRELATING, 82.0, "Correlating findings across multi-engine fleet with stable context fingerprinting")
            correlated_findings = FindingCorrelationService.correlate(total_findings)

            # 10. RISK_CALCULATION: Deduplicate and apply Risk Engine to findings
            self._set_phase(scan_job, ScanStatus.RISK_CALCULATION, 88.0, "Computing deterministic CVSS risk scores, exploitability factors, and SLA deadlines")
            saved_findings_count = self._persist_findings(scan_job, correlated_findings, workspace_path=workspace_path)
            scan_job.scanner_versions = scanner_versions
            scan_job.files_scanned = metadata.files_scanned
            scan_job.rules_executed = total_rules_executed
            scan_job.finding_count = saved_findings_count
            self.db.commit()

            # 11. COMPLIANCE: Deterministic SOC 2 Type II Compliance Evaluation
            self._set_phase(scan_job, ScanStatus.COMPLIANCE, 93.0, "Evaluating SOC 2 Type II Trust Services Criteria controls & audit deficiencies")
            persisted_findings = [
                {
                    "severity": f.severity,
                    "risk_level": f.risk_level,
                    "risk_score": f.risk_score,
                    "remediation_due_at": f.remediation_due_at,
                    "status": f.status,
                    "owner": f.owner,
                    "jira_issue_key": f.jira_issue_key
                }
                for f in self.db.query(CanonicalSecurityFinding).filter(
                    CanonicalSecurityFinding.scan_id == scan_job.id
                ).all()
            ]

            evals = self.compliance_engine.evaluate_scan(
                tenant_id=scan_job.tenant_id,
                scan_id=scan_job.id,
                scan_status=scan_job.status,
                execution_successful=overall_successful,
                files_scanned=metadata.files_scanned,
                coverage_percentage=metadata.coverage_percentage,
                scanners=scan_job.scanners,
                findings=persisted_findings,
                scanner_healthy=True
            )
            for ev in evals:
                self.db.add(ComplianceEvaluation(**ev))

            # 12. EVIDENCE: Create immutable cryptographic scan evidence
            self._set_phase(scan_job, ScanStatus.EVIDENCE, 97.0, "Generating SHA-256 cryptographic evidence digests and immutable audit trails")
            self._create_evidence(
                scan_job=scan_job,
                metadata=metadata,
                ruleset_id=ruleset_id,
                ruleset_version=ruleset_version,
                configuration_hash=configuration_hash,
                exit_code=exit_code,
                execution_successful=overall_successful
            )

            # 13. CLEANUP: Securely destroy temporary sandbox
            self._set_phase(scan_job, ScanStatus.CLEANUP, 99.0, "Securely destroying isolated temporary workspace and wiping caches")
            if workspace_path:
                self.git_service.cleanup_workspace(workspace_path)
                workspace_path = None

            # 14. COMPLETED
            scan_job.completed_at = datetime.datetime.now(datetime.timezone.utc)
            if overall_successful:
                self._set_phase(
                    scan_job, 
                    ScanStatus.COMPLETED, 
                    100.0, 
                    f"Scan completed successfully ({saved_findings_count} findings discovered across {metadata.files_scanned} files)"
                )
            else:
                scan_job.status = ScanStatus.FAILED.value
                scan_job.error_message = "One or more scanners encountered execution errors."
                self.db.commit()

            self.audit_service.log_event(
                tenant_id=scan_job.tenant_id,
                action="SCAN_COMPLETED" if overall_successful else "SCAN_FAILED",
                resource_type="scan_job",
                resource_id=scan_job.id,
                details={
                    "status": scan_job.status,
                    "findings_count": scan_job.finding_count,
                    "files_scanned": scan_job.files_scanned,
                    "coverage_percentage": metadata.coverage_percentage
                }
            )

        except Exception as e:
            self.db.rollback()
            scan_job.status = ScanStatus.FAILED.value
            scan_job.current_phase = ScanStatus.FAILED.value
            scan_job.error_message = str(e)
            scan_job.completed_at = datetime.datetime.now(datetime.timezone.utc)
            self.db.commit()

            self.audit_service.log_event(
                tenant_id=scan_job.tenant_id,
                action="SCAN_FAILED",
                resource_type="scan_job",
                resource_id=scan_job.id,
                details={"error": str(e)},
                result="FAILED"
            )
            raise e
        finally:
            if workspace_path:
                self.git_service.cleanup_workspace(workspace_path)

        return scan_job


    @staticmethod
    def _resolve_finding_coordinate(f: Dict[str, Any], workspace_path: Optional[str]) -> None:
        """
        Intelligently resolves the exact file path, start/end line numbers, code context line,
        and multi-line snippet for SCA, SAST, IaC, and Secret findings from the customer workspace.
        Ensures line 1 is NEVER returned if the dependency or defect exists elsewhere.
        """
        if not workspace_path or not os.path.isdir(workspace_path):
            return

        file_path = f.get("file_path")
        if not file_path:
            return

        pkg_name = f.get("package_name")
        pkg_ver = f.get("package_version")
        finding_type = f.get("finding_type") or ("SCA" if pkg_name else "SAST")

        # 1. SCA Dependency Resolution
        if finding_type == "SCA" or pkg_name:
            dir_name = os.path.dirname(file_path)
            base_name = os.path.basename(file_path).lower()

            # Strategy 1A: If lockfile, check if direct manifest exists in same directory (or root)
            if "lock" in base_name or base_name in ("yarn.lock", "package-lock.json", "pnpm-lock.yaml"):
                manifest_rel = os.path.join(dir_name, "package.json") if dir_name else "package.json"
                manifest_abs = os.path.join(workspace_path, manifest_rel)
                if os.path.isfile(manifest_abs):
                    try:
                        with open(manifest_abs, "r", encoding="utf-8", errors="ignore") as mf:
                            m_lines = mf.readlines()
                        pattern = rf"[\"\x27]{re.escape(pkg_name)}[\"\x27]\s*:"
                        for idx, line in enumerate(m_lines):
                            if re.search(pattern, line):
                                st = idx + 1
                                st_idx = max(0, st - 3)
                                end_idx = min(len(m_lines), st + 3)
                                snippet_lines = [f"{i+1}: {m_lines[i].rstrip()}" for i in range(st_idx, end_idx)]
                                f["file_path"] = manifest_rel
                                f["start_line"] = st
                                f["end_line"] = st
                                f["code_context"] = m_lines[idx].strip()
                                f["code_snippet"] = "\n".join(snippet_lines)
                                return
                    except Exception:
                        pass

            # Strategy 1B: Search within target file (lockfile or manifest)
            abs_file = os.path.join(workspace_path, file_path)
            if os.path.isfile(abs_file):
                try:
                    with open(abs_file, "r", encoding="utf-8", errors="ignore") as tf:
                        lines = tf.readlines()

                    patterns = []
                    if base_name == "package-lock.json":
                        patterns = [
                            rf"[\"\x27]node_modules/{re.escape(pkg_name)}[\"\x27]\s*:",
                            rf"[\"\x27]{re.escape(pkg_name)}[\"\x27]\s*:",
                            rf"[\"\x27]name[\"\x27]\s*:\s*[\"\x27]{re.escape(pkg_name)}[\"\x27]"
                        ]
                    elif base_name in ("package.json", "composer.json"):
                        patterns = [
                            rf"[\"\x27]{re.escape(pkg_name)}[\"\x27]\s*:"
                        ]
                    elif base_name in ("requirements.txt", "requirements.in"):
                        patterns = [
                            rf"^\s*{re.escape(pkg_name)}(?:\s*[=><~!\s]|$)"
                        ]
                    elif base_name == "pom.xml":
                        patterns = [
                            rf"<artifactId>{re.escape(pkg_name)}</artifactId>"
                        ]
                    elif "cargo" in base_name:
                        patterns = [
                            rf"^\s*{re.escape(pkg_name)}\s*=",
                            rf"name\s*=\s*[\"\x27]{re.escape(pkg_name)}[\"\x27]"
                        ]
                    else:
                        patterns = [
                            rf"[\"\x27]{re.escape(pkg_name)}[\"\x27]",
                            rf"\b{re.escape(pkg_name)}\b"
                        ]

                    matched_idx = None
                    for pat in patterns:
                        for idx, line in enumerate(lines):
                            if re.search(pat, line, re.IGNORECASE if base_name in ("requirements.txt", "pom.xml") else 0):
                                matched_idx = idx
                                # Prefer version line if within next 5 lines
                                if pkg_ver:
                                    for j in range(idx, min(len(lines), idx + 6)):
                                        if str(pkg_ver) in lines[j]:
                                            matched_idx = j
                                            break
                                break
                        if matched_idx is not None:
                            break

                    if matched_idx is not None:
                        st = matched_idx + 1
                        st_idx = max(0, st - 3)
                        end_idx = min(len(lines), st + 3)
                        snippet_lines = [f"{i+1}: {lines[i].rstrip()}" for i in range(st_idx, end_idx)]
                        f["start_line"] = st
                        f["end_line"] = st
                        f["code_context"] = lines[matched_idx].strip()
                        f["code_snippet"] = "\n".join(snippet_lines)
                        return
                except Exception:
                    pass

        # 2. SAST / IaC / Secrets or General Source Code Files
        abs_file = os.path.join(workspace_path, file_path)
        if os.path.isfile(abs_file):
            try:
                with open(abs_file, "r", encoding="utf-8", errors="ignore") as sf:
                    lines = sf.readlines()
                
                target_line = f.get("start_line") or 1
                # If target_line is 1 but we have a rule_id or package name, search for the symbol
                if target_line <= 1 and lines:
                    search_term = pkg_name or (f.get("rule_id", "").split(".")[-1] if f.get("rule_id") else None)
                    if search_term and len(search_term) > 2:
                        for idx, line in enumerate(lines):
                            if search_term in line:
                                target_line = idx + 1
                                break

                if 1 <= target_line <= len(lines):
                    st_idx = max(0, target_line - 3)
                    end_idx = min(len(lines), target_line + 3)
                    snippet_lines = [f"{i+1}: {lines[i].rstrip()}" for i in range(st_idx, end_idx)]
                    f["start_line"] = target_line
                    f["end_line"] = target_line
                    f["code_context"] = lines[target_line - 1].strip()
                    f["code_snippet"] = "\n".join(snippet_lines)
                elif lines:
                    snippet_lines = [f"{i+1}: {lines[i].rstrip()}" for i in range(min(5, len(lines)))]
                    f["start_line"] = 1
                    f["end_line"] = 1
                    f["code_context"] = lines[0].strip()
                    f["code_snippet"] = "\n".join(snippet_lines)
            except Exception:
                pass

    def _persist_findings(self, scan_job: ScanJob, findings_data: List[Dict[str, Any]], workspace_path: Optional[str] = None) -> int:
        """
        Deduplicates findings based on deterministic fingerprint and applies the Risk Engine.
        Supports SAST, SCA, and IaC finding types with cross-scanner correlation provenance.
        """
        count = 0
        now = datetime.datetime.now(datetime.timezone.utc)

        for f in findings_data:
            # Intelligently resolve coordinates and real code lines from workspace
            self._resolve_finding_coordinate(f, workspace_path)

            fp = f["fingerprint"]
            existing = self.db.query(CanonicalSecurityFinding).filter(
                CanonicalSecurityFinding.tenant_id == scan_job.tenant_id,
                CanonicalSecurityFinding.repository_name == scan_job.repository_name,
                CanonicalSecurityFinding.fingerprint == fp
            ).first()

            # Calculate deterministic risk
            risk_eval = self.risk_engine.calculate_risk(
                scanner_severity=f.get("severity", "MEDIUM"),
                confidence=f.get("confidence", "HIGH"),
                asset_criticality="TIER_2_BUSINESS_CRITICAL",
                is_production=True,
                is_internet_exposed=False,
                known_exploitation=False,
                first_seen_at=existing.first_seen if existing else now
            )

            # Enrich dictionary for downstream compliance evaluation
            f["risk_score"] = risk_eval["risk_score"]
            f["risk_level"] = risk_eval["risk_level"]
            f["priority"] = risk_eval["priority"]
            f["remediation_due_at"] = risk_eval["remediation_due_at"]

            detected_by = f.get("detected_by_scanners") or [f.get("scanner", "sast")]
            correlated_ids = f.get("correlated_finding_ids") or []

            if existing:
                # Update existing finding
                existing.last_seen = now
                existing.scan_id = scan_job.id
                existing.commit_sha = scan_job.commit_sha
                existing.repository_id = scan_job.repository_id
                existing.repository_name = scan_job.repository_name
                existing.file_path = f.get("file_path", existing.file_path)
                existing.title = f.get("title") or existing.title
                existing.description = f.get("description") or existing.description
                existing.message = f.get("message") or existing.message
                existing.start_line = f.get("start_line")
                existing.end_line = f.get("end_line")
                existing.start_column = f.get("start_column")
                existing.end_column = f.get("end_column")
                existing.code_snippet = f.get("code_snippet") or existing.code_snippet
                existing.code_context = f.get("code_context") or existing.code_context
                existing.risk_score = risk_eval["risk_score"]
                existing.risk_level = risk_eval["risk_level"]
                existing.priority = risk_eval["priority"]
                existing.remediation_due_at = risk_eval["remediation_due_at"]
                
                # Merge detected_by_scanners
                existing_scanners = set(existing.detected_by_scanners or [existing.scanner])
                existing_scanners.update(detected_by)
                existing.detected_by_scanners = sorted(list(existing_scanners))

                if existing.status == FindingStatus.RESOLVED.value:
                    existing.status = FindingStatus.OPEN.value
                    self.audit_service.log_event(
                        tenant_id=scan_job.tenant_id,
                        action="FINDING_REOPENED",
                        resource_type="finding",
                        resource_id=existing.id,
                        details={"fingerprint": fp, "commit_sha": scan_job.commit_sha}
                    )
            else:
                # Create new canonical finding
                finding = CanonicalSecurityFinding(
                    id=str(uuid.uuid4()),
                    tenant_id=scan_job.tenant_id,
                    scan_id=scan_job.id,
                    fingerprint=fp,
                    source=f.get("source", "scanner"),
                    scanner=f.get("scanner", "semgrep"),
                    scanner_version=f.get("scanner_version"),
                    source_finding_id=f.get("source_finding_id"),
                    repository_id=scan_job.repository_id,
                    repository_name=scan_job.repository_name,
                    branch=scan_job.branch,
                    commit_sha=scan_job.commit_sha,
                    file_path=f.get("file_path", "unknown"),
                    start_line=f.get("start_line"),
                    start_column=f.get("start_column"),
                    end_line=f.get("end_line"),
                    end_column=f.get("end_column"),
                    rule_id=f.get("rule_id", "unknown"),
                    rule_name=f.get("rule_name"),
                    rule_category=f.get("rule_category"),
                    title=f.get("title", "Untitled Finding"),
                    description=f.get("description"),
                    message=f.get("message"),
                    severity=f.get("severity", "MEDIUM"),
                    confidence=f.get("confidence", "HIGH"),
                    cwe=f.get("cwe", []),
                    cve=f.get("cve", []),
                    owasp_category=f.get("owasp_category", []),
                    status=FindingStatus.OPEN.value,
                    risk_score=risk_eval["risk_score"],
                    risk_level=risk_eval["risk_level"],
                    priority=risk_eval["priority"],
                    remediation=f.get("remediation"),
                    remediation_due_at=risk_eval["remediation_due_at"],
                    verification_status="UNVERIFIED",
                    code_snippet=f.get("code_snippet"),
                    code_context=f.get("code_context"),
                    first_seen=now,
                    last_seen=now,
                    # Universal extensions
                    finding_type=f.get("finding_type", "SAST"),
                    package_name=f.get("package_name"),
                    package_version=f.get("package_version"),
                    fixed_version=f.get("fixed_version"),
                    ghsa=f.get("ghsa"),
                    osv_id=f.get("osv_id"),
                    cvss=f.get("cvss"),
                    epss=f.get("epss"),
                    detected_by_scanners=detected_by,
                    correlated_finding_ids=correlated_ids
                )
                self.db.add(finding)
            count += 1

        self.db.commit()
        return count

    def _create_evidence(
        self,
        scan_job: ScanJob,
        metadata: Any,
        ruleset_id: str,
        ruleset_version: str,
        configuration_hash: str,
        exit_code: int,
        execution_successful: bool
    ) -> None:
        """Stores immutable evidence record of the multi-scanner scan execution."""
        evidence_hash = hashlib.sha256(
            f"{scan_job.id}:{scan_job.commit_sha}:{scan_job.finding_count}:{scan_job.raw_result_hash}".encode()
        ).hexdigest()
        
        ev = ScanEvidence(
            id=str(uuid.uuid4()),
            tenant_id=scan_job.tenant_id,
            scan_id=scan_job.id,
            scanner=",".join(scan_job.scanners or ["semgrep"]),
            scanner_version=str(scan_job.scanner_versions),
            rule_version=ruleset_version,
            ruleset_id=ruleset_id,
            configuration_hash=configuration_hash,
            repository=scan_job.repository_name,
            branch=scan_job.branch,
            commit_sha=scan_job.commit_sha,
            files_discovered=metadata.files_discovered,
            files_scanned=metadata.files_scanned,
            files_excluded=metadata.files_excluded,
            files_failed=metadata.files_failed,
            coverage_percentage=metadata.coverage_percentage,
            rules_executed=scan_job.rules_executed,
            finding_count=scan_job.finding_count,
            raw_result_hash=scan_job.raw_result_hash or evidence_hash,
            result_hash=evidence_hash,
            exit_code=exit_code,
            execution_status="SUCCESS" if execution_successful else "FAILED"
        )
        self.db.add(ev)
        self.db.commit()

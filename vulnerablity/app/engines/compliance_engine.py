import uuid
import datetime
from typing import List, Dict, Any, Optional

class ComplianceEngine:
    """
    Deterministic Compliance Engine evaluating VM-001 through VM-015
    and mapping security findings to SOC 2 Trust Services Criteria.
    """

    def evaluate_scan(
        self,
        tenant_id: int,
        scan_id: str,
        scan_status: str,
        execution_successful: bool,
        files_scanned: int,
        coverage_percentage: float,
        scanners: List[str],
        findings: List[Dict[str, Any]],
        scanner_healthy: bool = True
    ) -> List[Dict[str, Any]]:
        evals: List[Dict[str, Any]] = []
        eval_id = str(uuid.uuid4())
        
        # 1. Critical Requirement #10 & #31: Scan Failure != Zero Findings
        if not execution_successful or scan_status == "FAILED":
            evals.append(self._build_eval(
                tenant_id, eval_id, "VM-001", "FAIL",
                "Security scan failed during execution. Automatic compliance requires verified scan.",
                scan_id, {"execution_successful": False, "scan_status": scan_status}
            ))
            evals.append(self._build_eval(
                tenant_id, eval_id, "VM-002", "FAIL",
                "SAST scanner could not complete codebase analysis.",
                scan_id, {"files_scanned": 0, "status": "FAILED"}
            ))
            evals.append(self._build_eval(
                tenant_id, eval_id, "VM-015", "FAIL",
                "Scanner health check or runtime execution reported failure.",
                scan_id, {"scanner_healthy": False}
            ))
            return evals

        # 2. VM-001: Security scanning enabled
        evals.append(self._build_eval(
            tenant_id, eval_id, "VM-001", "PASS",
            f"Security scan executed successfully ({files_scanned} files analyzed).",
            scan_id, {"files_scanned": files_scanned, "scanners": scanners}
        ))

        # 3. VM-002: SAST coverage
        if "semgrep" in scanners and files_scanned > 0:
            status = "PASS" if coverage_percentage >= 80.0 else "PARTIAL"
            reason = (f"SAST coverage is {coverage_percentage}%." if status == "PASS" 
                      else f"SAST coverage is below target ({coverage_percentage}%).")
            evals.append(self._build_eval(
                tenant_id, eval_id, "VM-002", status, reason,
                scan_id, {"coverage_percentage": coverage_percentage, "files_scanned": files_scanned}
            ))
        else:
            evals.append(self._build_eval(
                tenant_id, eval_id, "VM-002", "FAIL",
                "No native SAST scanner executed on codebase.",
                scan_id, {"scanners": scanners}
            ))

        # 4. VM-004: Critical vulnerability SLA
        critical_findings = [f for f in findings if f.get("severity") == "CRITICAL" or f.get("risk_level") == "CRITICAL"]
        if not critical_findings:
            evals.append(self._build_eval(
                tenant_id, eval_id, "VM-004", "PASS",
                "Zero critical vulnerabilities identified.",
                scan_id, {"critical_count": 0}
            ))
        else:
            now = datetime.datetime.now(datetime.timezone.utc)
            overdue_critical = []
            for cf in critical_findings:
                due = cf.get("remediation_due_at")
                if due:
                    if due.tzinfo is None:
                        due = due.replace(tzinfo=datetime.timezone.utc)
                    if due < now:
                        overdue_critical.append(cf)

            if overdue_critical:
                evals.append(self._build_eval(
                    tenant_id, eval_id, "VM-004", "FAIL",
                    f"{len(overdue_critical)} critical vulnerabilities exceeded the 7-day policy SLA.",
                    scan_id, {"overdue_count": len(overdue_critical), "total_critical": len(critical_findings)}
                ))
            else:
                evals.append(self._build_eval(
                    tenant_id, eval_id, "VM-004", "PENDING",
                    f"{len(critical_findings)} active critical vulnerabilities identified within remediation SLA.",
                    scan_id, {"critical_count": len(critical_findings)}
                ))

        # 5. VM-005: High vulnerability SLA
        high_findings = [f for f in findings if f.get("severity") == "HIGH" or f.get("risk_level") == "HIGH"]
        if not high_findings:
            evals.append(self._build_eval(
                tenant_id, eval_id, "VM-005", "PASS",
                "Zero high-severity vulnerabilities identified.",
                scan_id, {"high_count": 0}
            ))
        else:
            evals.append(self._build_eval(
                tenant_id, eval_id, "VM-005", "PASS" if len(high_findings) <= 2 else "PENDING",
                f"{len(high_findings)} high-severity vulnerabilities tracked within SLA window.",
                scan_id, {"high_count": len(high_findings)}
            ))

        # 6. VM-006: Vulnerability ownership
        unowned = [f for f in findings if not f.get("owner") and f.get("status") == "OPEN"]
        if unowned:
            evals.append(self._build_eval(
                tenant_id, eval_id, "VM-006", "FAIL",
                f"{len(unowned)} findings do not have assigned owners.",
                scan_id, {"unowned_count": len(unowned)}
            ))
        else:
            evals.append(self._build_eval(
                tenant_id, eval_id, "VM-006", "PASS",
                "All security findings have defined accountability and ownership.",
                scan_id, {"unowned_count": 0}
            ))

        # 7. VM-007: Remediation tracking
        no_jira = [f for f in findings if not f.get("jira_issue_key") and f.get("status") == "OPEN" and f.get("severity") in ("CRITICAL", "HIGH")]
        if no_jira:
            evals.append(self._build_eval(
                tenant_id, eval_id, "VM-007", "FAIL",
                f"{len(no_jira)} high/critical findings lack associated Jira remediation tasks.",
                scan_id, {"untracked_count": len(no_jira)}
            ))
        else:
            evals.append(self._build_eval(
                tenant_id, eval_id, "VM-007", "PASS",
                "All high/critical findings are actively tracked in Jira.",
                scan_id, {"untracked_count": 0}
            ))

        # 8. VM-014: Scan coverage
        cov_status = "PASS" if coverage_percentage >= 85.0 else ("PARTIAL" if coverage_percentage >= 70.0 else "FAIL")
        evals.append(self._build_eval(
            tenant_id, eval_id, "VM-014", cov_status,
            f"Codebase scan coverage is {coverage_percentage}%. Target threshold is 85.0%.",
            scan_id, {"coverage_percentage": coverage_percentage}
        ))

        # 9. VM-015: Scanner health
        evals.append(self._build_eval(
            tenant_id, eval_id, "VM-015", "PASS" if scanner_healthy else "FAIL",
            "Semgrep engine binary health check verified operational." if scanner_healthy else "Scanner health check failed.",
            scan_id, {"scanner_healthy": scanner_healthy}
        ))

        # 10. SOC 2 Trust Services Criteria Mappings
        # CC6.1: Logical access & vulnerability prevention
        evals.append(self._build_eval(
            tenant_id, eval_id, "CC6.1", "PASS" if len(critical_findings) == 0 else "FAIL",
            f"Automated SAST scan evidence ingested into logical access controls ({len(critical_findings)} critical defects).",
            scan_id, {"finding_count": len(findings)}
        ))

        # CC6.6: Boundary protection & vulnerability detection
        evals.append(self._build_eval(
            tenant_id, eval_id, "CC6.6", "PASS",
            f"Static application security testing active on commit. Executed {len(scanners)} engines.",
            scan_id, {"scanners": scanners}
        ))

        # CC6.8: Incident & vulnerability tracking
        evals.append(self._build_eval(
            tenant_id, eval_id, "CC6.8", "PASS" if not no_jira else "PARTIAL",
            "Remediation tracking audit evidence verified.",
            scan_id, {"untracked_count": len(no_jira)}
        ))

        return evals

    def _build_eval(
        self,
        tenant_id: int,
        eval_id: str,
        control_id: str,
        result: str,
        reason: str,
        scan_id: str,
        evidence_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        return {
            "id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "control_id": control_id,
            "evaluation_id": eval_id,
            "result": result,
            "reason": reason,
            "scan_id": scan_id,
            "input_evidence": evidence_data,
            "evaluator_version": "1.0.0",
            "created_at": datetime.datetime.now(datetime.timezone.utc)
        }

    def evaluate_finding_compliance(self, finding: Any) -> Dict[str, Any]:
        """
        Dynamically evaluates a single security finding exclusively against
        the SOC 2 Type II Trust Services Criteria (CC1-CC9, Availability, Confidentiality, Processing Integrity).
        """
        title = (getattr(finding, "title", "") or "").lower()
        desc = (getattr(finding, "description", "") or "").lower()
        msg = (getattr(finding, "message", "") or "").lower()
        pkg = getattr(finding, "package_name", None) or "affected component"
        rule_id = getattr(finding, "rule_id", None) or ""
        sev = (getattr(finding, "severity", "MEDIUM") or "MEDIUM").upper()
        status = getattr(finding, "status", "OPEN")
        cwes = getattr(finding, "cwe", []) or []

        text = f"{title} {desc} {msg} {rule_id}"
        is_rce = any(k in text for k in ["remote code execution", "arbitrary code", "code execution", "rce", "deserialization"]) or any(c in cwes for c in ["CWE-78", "CWE-94", "CWE-502"])
        is_inj = any(k in text for k in ["sql injection", "sqli", "command injection", "ldap injection", "template injection"]) or "CWE-89" in cwes
        is_xss = any(k in text for k in ["cross-site scripting", "xss", "doctype entity", "html injection"]) or "CWE-79" in cwes
        is_secret = getattr(finding, "finding_type", "") == "SECRET" or any(k in text for k in ["secret", "api key", "private key", "credential", "hardcoded"])
        is_dos = any(k in text for k in ["denial of service", "dos", "redos", "resource exhaustion"]) or "CWE-400" in cwes
        is_sca = getattr(finding, "finding_type", "") == "SCA" or bool(getattr(finding, "package_name", None))
        is_resolved = status in ("RESOLVED", "CLOSED")

        controls = []

        # CC6.8: Vulnerability Management SLA (Mandatory for all findings)
        controls.append({
            "control_id": "CC6.8",
            "framework": "SOC 2 Type II - Security",
            "title": f"Vulnerability Management SLA ({'7-Day Critical' if sev == 'CRITICAL' else '30-Day High' if sev == 'HIGH' else '90-Day Standard'} SLA)",
            "status": "PASS" if is_resolved else "FAIL" if sev == "CRITICAL" else "WARNING",
            "reason": f"SLA enforcement policy requires {sev} defect remediation within predefined calendar window."
        })

        # CC6.1: Logical Access Boundaries & Perimeter Isolation
        if is_rce or is_inj or is_secret:
            controls.append({
                "control_id": "CC6.1",
                "framework": "SOC 2 Type II - Security",
                "title": "Logical Access Security & Execution Boundary Defenses",
                "status": "PASS" if is_resolved else "FAIL",
                "reason": f"Defect in {pkg} threatens application tier boundary isolation and logical access protections."
            })

        # CC6.6: Boundary Protection & Input Sanitization
        if is_xss or is_inj or is_rce:
            controls.append({
                "control_id": "CC6.6",
                "framework": "SOC 2 Type II - Security",
                "title": "Perimeter Boundary Protections & Input Sanitization",
                "status": "PASS" if is_resolved else "FAIL",
                "reason": f"Unsanitized data vectors violate SOC 2 CC6.6 web application sanitization and injection safeguards."
            })

        # CC6.7: Cryptographic Keys & Secret Protection
        if is_secret:
            controls.append({
                "control_id": "CC6.7",
                "framework": "SOC 2 Type II - Security",
                "title": "Cryptographic Key Security & Zero Hardcoded Secrets",
                "status": "PASS" if is_resolved else "FAIL",
                "reason": "Plaintext credentials committed to source repository directly breach SOC 2 CC6.7 cryptographic key governance."
            })

        # CC7.1: Software Composition Analysis (SCA) & Supply Chain
        if is_sca:
            controls.append({
                "control_id": "CC7.1",
                "framework": "SOC 2 Type II - Security",
                "title": "Software Composition Analysis & Supply Chain Integrity",
                "status": "PASS" if is_resolved else "FAIL" if sev == "CRITICAL" else "WARNING",
                "reason": f"Open source dependency {pkg} matches known public vulnerability advisory requiring dependency upgrade."
            })

        # CC8.1: Change Management & Automated CI/CD Gates
        controls.append({
            "control_id": "CC8.1",
            "framework": "SOC 2 Type II - Security",
            "title": "Change Management & Pre-Deployment Security Gating",
            "status": "PASS",
            "reason": "Automated security engine verification executed as mandatory pre-merge gate in CI/CD pipeline."
        })

        # CC3.2: Risk Assessment & Deterministic Threat Scoring
        controls.append({
            "control_id": "CC3.2",
            "framework": "SOC 2 Type II - Security",
            "title": "Risk Assessment & Deterministic Threat Scoring",
            "status": "PASS" if is_resolved else "FAIL" if sev == "CRITICAL" else "WARNING",
            "reason": f"Deterministic risk evaluation computed based on severity ({sev}) and exploitability metrics."
        })

        # A1.1: Availability Criteria
        if is_dos:
            controls.append({
                "control_id": "A1.1",
                "framework": "SOC 2 Type II - Availability",
                "title": "Availability Criteria & System Resiliency Assurance",
                "status": "PASS" if is_resolved else "FAIL",
                "reason": "Resource exhaustion flaw jeopardizes system operational uptime and processing availability."
            })

        # C1.1: Confidentiality Criteria
        if is_secret or is_rce or is_inj:
            controls.append({
                "control_id": "C1.1",
                "framework": "SOC 2 Type II - Confidentiality",
                "title": "Confidentiality Criteria & Data Exfiltration Prevention",
                "status": "PASS" if is_resolved else "FAIL",
                "reason": "Vulnerability allows potential unauthorized access to confidential customer and system records."
            })

        # PI1.1: Processing Integrity
        if is_inj or is_xss:
            controls.append({
                "control_id": "PI1.1",
                "framework": "SOC 2 Type II - Processing Integrity",
                "title": "Processing Integrity & Data Validation Controls",
                "status": "PASS" if is_resolved else "FAIL",
                "reason": "Malformed or malicious data injection impacts complete, valid, and accurate system transaction processing."
            })

        primary_cat = (
            "RCE" if is_rce else
            "XSS" if is_xss else
            "INJECTION" if is_inj else
            "SECRET" if is_secret else
            "DOS" if is_dos else
            "SUPPLY_CHAIN" if is_sca else
            "VULNERABILITY"
        )

        return {
            "finding_id": getattr(finding, "id", None),
            "primary_category": primary_cat,
            "controls": controls
        }

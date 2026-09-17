import logging
from typing import List, Dict, Any, Set

logger = logging.getLogger(__name__)

class FindingCorrelationService:
    """
    Correlates findings across multiple scanner engines (Semgrep, CodeQL, Trivy, OSV-Scanner).
    Merges overlapping vulnerabilities, unifies provenance, and enriches metadata.
    """

    @classmethod
    def correlate(cls, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not findings:
            return []

        sast_findings: List[Dict[str, Any]] = []
        sca_findings: List[Dict[str, Any]] = []
        other_findings: List[Dict[str, Any]] = []

        for f in findings:
            ftype = f.get("finding_type", "SAST").upper()
            if ftype == "SAST":
                sast_findings.append(f)
            elif ftype == "SCA":
                sca_findings.append(f)
            else:
                other_findings.append(f)

        correlated_sast = cls._correlate_sast(sast_findings)
        correlated_sca = cls._correlate_sca(sca_findings)

        return correlated_sast + correlated_sca + other_findings

    @classmethod
    def _correlate_sast(cls, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlates SAST findings (e.g. Semgrep and CodeQL) by file path and CWE / line proximity.
        """
        merged: List[Dict[str, Any]] = []
        matched_indices: Set[int] = set()

        for i in range(len(findings)):
            if i in matched_indices:
                continue

            current = dict(findings[i])
            current_scanners = set(current.get("detected_by_scanners") or [current.get("scanner", "sast")])
            correlated_fps = []

            for j in range(i + 1, len(findings)):
                if j in matched_indices:
                    continue

                candidate = findings[j]

                # Only correlate findings from DIFFERENT scanners
                cur_scanners = set(current.get("detected_by_scanners") or [current.get("scanner")])
                can_scanners = set(candidate.get("detected_by_scanners") or [candidate.get("scanner")])
                if cur_scanners.intersection(can_scanners):
                    continue

                # Compare SAST correlation: same file + (overlapping lines OR shared CWE)
                same_file = (current.get("file_path") == candidate.get("file_path")) and current.get("file_path") not in ["unknown", ""]
                
                # Check line proximity (within 5 lines)
                line_close = False
                c_start = current.get("start_line", 1)
                can_start = candidate.get("start_line", 1)
                if abs(c_start - can_start) <= 5:
                    line_close = True

                # Check shared CWEs
                shared_cwes = set(current.get("cwe") or []).intersection(set(candidate.get("cwe") or []))

                if same_file and (line_close or (len(shared_cwes) > 0 and abs(c_start - can_start) <= 15)):
                    # Correlate!
                    candidate_scanners = candidate.get("detected_by_scanners") or [candidate.get("scanner", "sast")]
                    current_scanners.update(candidate_scanners)
                    correlated_fps.append(candidate.get("fingerprint"))
                    matched_indices.add(j)

                    # Enrich CWEs
                    all_cwes = list(set((current.get("cwe") or []) + (candidate.get("cwe") or [])))
                    current["cwe"] = all_cwes

                    # Keep enterprise rule_id if candidate has it
                    if "enterprise.security." in candidate.get("rule_id", "") and "enterprise.security." not in current.get("rule_id", ""):
                        current["rule_id"] = candidate.get("rule_id")
                        current["rule_name"] = candidate.get("rule_name")
                        current["title"] = candidate.get("title")

                    # Elevate severity if candidate is higher
                    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                    if sev_rank.get(candidate.get("severity", "MEDIUM"), 0) > sev_rank.get(current.get("severity", "MEDIUM"), 0):
                        current["severity"] = candidate.get("severity")

            current["detected_by_scanners"] = sorted(list(current_scanners))
            current["correlated_finding_ids"] = correlated_fps
            merged.append(current)
            matched_indices.add(i)

        return merged

    @classmethod
    def _correlate_sca(cls, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlates SCA findings (e.g. Trivy and OSV-Scanner) by package name, version, and CVE/GHSA.
        """
        merged: List[Dict[str, Any]] = []
        matched_indices: Set[int] = set()

        for i in range(len(findings)):
            if i in matched_indices:
                continue

            current = dict(findings[i])
            current_scanners = set(current.get("detected_by_scanners") or [current.get("scanner", "sca")])
            correlated_fps = []

            cur_pkg = (current.get("package_name") or "").lower()
            cur_cves = set(current.get("cve") or [])
            cur_ghsa = current.get("ghsa")

            for j in range(i + 1, len(findings)):
                if j in matched_indices:
                    continue

                candidate = findings[j]
                
                # Only correlate findings from DIFFERENT scanners
                cur_scanners = set(current.get("detected_by_scanners") or [current.get("scanner")])
                can_scanners = set(candidate.get("detected_by_scanners") or [candidate.get("scanner")])
                if cur_scanners.intersection(can_scanners):
                    continue

                can_pkg = (candidate.get("package_name") or "").lower()
                can_cves = set(candidate.get("cve") or [])
                can_ghsa = candidate.get("ghsa")

                # Match by same package and (shared CVE, shared GHSA, or exact version match)
                same_pkg = (cur_pkg and cur_pkg == can_pkg)
                cve_match = bool(cur_cves.intersection(can_cves))
                ghsa_match = bool(cur_ghsa and can_ghsa and cur_ghsa == can_ghsa)
                version_match = (current.get("package_version") == candidate.get("package_version"))

                if same_pkg and (cve_match or ghsa_match or version_match):
                    # Correlate!
                    candidate_scanners = candidate.get("detected_by_scanners") or [candidate.get("scanner", "sca")]
                    current_scanners.update(candidate_scanners)
                    correlated_fps.append(candidate.get("fingerprint"))
                    matched_indices.add(j)

                    # Unify CVEs, GHSA, CVSS
                    all_cves = list(set(list(cur_cves) + list(can_cves)))
                    current["cve"] = all_cves
                    if not current.get("ghsa") and candidate.get("ghsa"):
                        current["ghsa"] = candidate.get("ghsa")
                    if not current.get("fixed_version") and candidate.get("fixed_version"):
                        current["fixed_version"] = candidate.get("fixed_version")
                    if candidate.get("cvss") and (not current.get("cvss") or candidate.get("cvss") > current.get("cvss")):
                        current["cvss"] = candidate.get("cvss")

                    # Highest severity
                    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                    if sev_rank.get(candidate.get("severity", "MEDIUM"), 0) > sev_rank.get(current.get("severity", "MEDIUM"), 0):
                        current["severity"] = candidate.get("severity")

            current["detected_by_scanners"] = sorted(list(current_scanners))
            current["correlated_finding_ids"] = correlated_fps
            merged.append(current)
            matched_indices.add(i)

        return merged

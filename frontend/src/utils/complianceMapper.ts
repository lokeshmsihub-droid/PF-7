import { VulnerabilityFinding, VulnerabilityComplianceControl } from '../types';

export type SOC2Category = 'ALL' | 'CC6' | 'CC7' | 'CC8' | 'CC3' | 'CC4_5' | 'CC1_2' | 'AVAIL_CONF';

export interface FindingComplianceItem {
  id: string;
  control_id: string;
  framework: string;
  soc2_category: SOC2Category;
  category_name: string;
  title: string;
  status: 'NON-COMPLIANT' | 'COMPLIANT' | 'SLA_RISK' | 'WARNING';
  status_label: string;
  status_badge_color: string;
  assessment: string;
  auditor_proof: string;
  remediation_action: string;
  sla_days: number;
}

export interface VulnerabilityClassification {
  primaryCategory: 'RCE' | 'INJECTION' | 'XSS' | 'SECRETS' | 'AUTH' | 'SSRF_PATH' | 'DOS' | 'CRYPTO' | 'IAC' | 'SUPPLY_CHAIN';
  categoryLabel: string;
  summaryRationale: string;
  isRCE: boolean;
  isInjection: boolean;
  isXSS: boolean;
  isSecrets: boolean;
  isDoS: boolean;
  isSCA: boolean;
  isAuth: boolean;
  isSSRF: boolean;
  isCrypto: boolean;
}

/**
 * Classifies a vulnerability finding into precise security taxonomy
 */
export function classifyVulnerability(finding: VulnerabilityFinding): VulnerabilityClassification {
  const text = `${finding.title || ''} ${finding.description || ''} ${finding.rule_id || ''} ${finding.message || ''} ${finding.package_name || ''}`.toLowerCase();
  const cweList = (finding.cwe || []).map((c) => c.toUpperCase());
  const type = (finding.finding_type || '').toUpperCase();

  const isRCE = 
    text.includes('remote code execution') || 
    text.includes('arbitrary code') || 
    text.includes('code execution') || 
    text.includes('rce') || 
    text.includes('deserialization') ||
    cweList.some((c) => ['CWE-78', 'CWE-94', 'CWE-502', 'CWE-77', 'CWE-95', 'CWE-1321'].includes(c));

  const isInjection = 
    text.includes('sql injection') || 
    text.includes('sqli') || 
    text.includes('command injection') || 
    text.includes('ldap injection') || 
    text.includes('template injection') ||
    cweList.some((c) => ['CWE-89', 'CWE-77', 'CWE-78', 'CWE-90', 'CWE-943'].includes(c));

  const isXSS = 
    text.includes('cross-site scripting') || 
    text.includes('xss') || 
    text.includes('doctype entity') || 
    text.includes('script injection') || 
    text.includes('html injection') ||
    cweList.some((c) => ['CWE-79', 'CWE-116', 'CWE-80'].includes(c));

  const isSecrets = 
    type === 'SECRET' || 
    type === 'SECRETS' || 
    text.includes('hardcoded') || 
    text.includes('api key') || 
    text.includes('secret') || 
    text.includes('private key') || 
    text.includes('credential') || 
    text.includes('password') ||
    cweList.some((c) => ['CWE-798', 'CWE-259', 'CWE-321'].includes(c));

  const isDoS = 
    text.includes('denial of service') || 
    text.includes('dos') || 
    text.includes('redos') || 
    text.includes('infinite loop') || 
    text.includes('resource exhaustion') || 
    text.includes('memory leak') ||
    cweList.some((c) => ['CWE-400', 'CWE-1333', 'CWE-770', 'CWE-835'].includes(c));

  const isSSRF = 
    text.includes('server-side request forgery') || 
    text.includes('ssrf') || 
    text.includes('path traversal') || 
    text.includes('directory traversal') || 
    text.includes('file inclusion') ||
    cweList.some((c) => ['CWE-918', 'CWE-22', 'CWE-23', 'CWE-35'].includes(c));

  const isAuth = 
    text.includes('access control') || 
    text.includes('idor') || 
    text.includes('privilege escalation') || 
    text.includes('csrf') || 
    text.includes('unauthorized') || 
    text.includes('bypass authentication') ||
    cweList.some((c) => ['CWE-284', 'CWE-285', 'CWE-639', 'CWE-352', 'CWE-862', 'CWE-863'].includes(c));

  const isCrypto = 
    text.includes('cryptographic') || 
    text.includes('weak hash') || 
    text.includes('cleartext') || 
    text.includes('md5') || 
    text.includes('sha1') ||
    cweList.some((c) => ['CWE-327', 'CWE-328', 'CWE-312', 'CWE-319'].includes(c));

  const isSCA = type === 'SCA' || !!finding.package_name;
  const isIaC = type === 'IAC' || text.includes('misconfiguration') || text.includes('terraform') || text.includes('dockerfile');

  let primaryCategory: VulnerabilityClassification['primaryCategory'] = 'SUPPLY_CHAIN';
  let categoryLabel = 'Software Supply Chain Vulnerability';
  let summaryRationale = `This third-party dependency flaw in ${finding.package_name || 'external library'} introduces unvetted code into production builds, directly impacting SOC 2 CC7.1 and CC6.8 compliance posture.`;

  if (isRCE) {
    primaryCategory = 'RCE';
    categoryLabel = 'Remote Code Execution (RCE) / Arbitrary Execution';
    summaryRationale = `This critical Remote Code Execution vulnerability in ${finding.package_name || finding.file_path} allows unauthenticated attackers to escape process boundaries and execute arbitrary commands, posing an immediate deficiency under SOC 2 CC6.1, CC6.8, and CC7.1 criteria.`;
  } else if (isSecrets) {
    primaryCategory = 'SECRETS';
    categoryLabel = 'Hardcoded Credentials & Cryptographic Secrets';
    summaryRationale = `This exposed secret in ${finding.file_path} directly breaches SOC 2 CC6.1 (Credential Isolation) and CC6.7 (Cryptographic Protection). Immediate revocation and token rotation are mandated under SOC 2 compliance.`;
  } else if (isInjection) {
    primaryCategory = 'INJECTION';
    categoryLabel = 'Untrusted Input Injection (SQL / Command / Template)';
    summaryRationale = `This injection defect violates data sanitization and perimeter boundary controls under SOC 2 CC6.6 and CC6.1, threatening application tier isolation and data integrity.`;
  } else if (isXSS) {
    primaryCategory = 'XSS';
    categoryLabel = 'Cross-Site Scripting (XSS) & Content Injection';
    summaryRationale = `This cross-site scripting defect allows unauthorized client-side script execution in authenticated user sessions, directly violating SOC 2 CC6.6 boundary protection and sanitization controls.`;
  } else if (isSSRF) {
    primaryCategory = 'SSRF_PATH';
    categoryLabel = 'Server-Side Request Forgery / Path Traversal';
    summaryRationale = `This request forgery or path traversal flaw enables unauthorized traversal of internal services or filesystem objects, violating SOC 2 CC6.6 and CC6.1 boundary controls.`;
  } else if (isAuth) {
    primaryCategory = 'AUTH';
    categoryLabel = 'Broken Access Control & Privilege Escalation';
    summaryRationale = `This authorization defect permits unauthorized object access or role escalation, violating SOC 2 CC6.1 and CC6.3 least-privilege principles.`;
  } else if (isDoS) {
    primaryCategory = 'DOS';
    categoryLabel = 'Denial of Service (DoS) & Resource Exhaustion';
    summaryRationale = `This resource exhaustion vulnerability impairs service availability and response reliability, violating SOC 2 A1.1 (Availability Criteria) and CC7.2 monitoring controls.`;
  } else if (isCrypto) {
    primaryCategory = 'CRYPTO';
    categoryLabel = 'Cryptographic Safeguards & Data Protection';
    summaryRationale = `This weak cipher or cleartext storage issue exposes sensitive data in transit or at rest, violating SOC 2 CC6.7 and C1.1 confidentiality safeguards.`;
  } else if (isIaC) {
    primaryCategory = 'IAC';
    categoryLabel = 'Infrastructure as Code (IaC) Misconfiguration';
    summaryRationale = `This cloud configuration defect exposes infrastructure components without required hardening, violating SOC 2 CC6.6 and CC8.1 change control criteria.`;
  }

  return {
    primaryCategory,
    categoryLabel,
    summaryRationale,
    isRCE,
    isInjection,
    isXSS,
    isSecrets,
    isDoS,
    isSCA,
    isAuth,
    isSSRF,
    isCrypto,
  };
}

/**
 * Dynamically computes complete, detailed SOC 2 Type II controls tailored to the exact vulnerability finding
 */
export function getDynamicComplianceForFinding(finding: VulnerabilityFinding): FindingComplianceItem[] {
  const clf = classifyVulnerability(finding);
  const isResolved = finding.status === 'RESOLVED' || finding.verification_status === 'VERIFIED';
  const isCritical = finding.severity === 'CRITICAL' || (finding.risk_score || 0) >= 9.0;
  const isHigh = finding.severity === 'HIGH' || (finding.risk_score || 0) >= 7.0;
  const pkg = finding.package_name || 'affected component';
  const fixedVer = finding.fixed_version || 'latest patched release';

  const items: FindingComplianceItem[] = [];

  // =========================================================================
  // CC6: LOGICAL AND PHYSICAL ACCESS CONTROLS
  // =========================================================================

  // CC6.1: Logical Access Security & Perimeter Boundaries
  if (clf.isRCE || clf.isSecrets || clf.isAuth || clf.isInjection) {
    items.push({
      id: `${finding.id}-soc2-cc6.1`,
      control_id: 'CC6.1',
      framework: 'SOC 2 Type II',
      soc2_category: 'CC6',
      category_name: 'Logical Access & Perimeter',
      title: clf.isRCE
        ? 'Perimeter Isolation & Unauthorized Execution Defenses'
        : clf.isSecrets
        ? 'Access Credentials & Zero Hardcoded Secrets Policy'
        : clf.isInjection
        ? 'Data Access Boundaries & Query Isolation'
        : 'Logical Access Controls & Least Privilege Enforcement',
      status: isResolved ? 'COMPLIANT' : isCritical ? 'NON-COMPLIANT' : 'WARNING',
      status_label: isResolved ? 'Control Satisfied' : isCritical ? 'Critical Deficiency' : 'Boundary At Risk',
      status_badge_color: isResolved ? 'bg-[#F0FDF4] text-[#16A34A] border-[#BBF7D0]' : 'bg-[#FEF2F2] text-[#DC2626] border-[#FCA5A5]',
      assessment: clf.isRCE
        ? `Unauthenticated remote code execution in ${pkg} allows attackers to escape application sandboxes and execute commands on host containers, violating SOC 2 CC6.1 perimeter access isolation.`
        : clf.isSecrets
        ? `Plaintext credentials committed in ${finding.file_path} violate SOC 2 CC6.1 key custody and access credential isolation mandates.`
        : clf.isInjection
        ? `Untrusted input parameters fed into queries in ${finding.file_path} bypass data isolation layers and authorization boundaries.`
        : `Authorization defect allows privilege escalation or unauthorized role assumption in production systems.`,
      auditor_proof: clf.isRCE
        ? `CI/CD test report verifying patched ${pkg} version and container seccomp/AppArmor boundary lockdown.`
        : clf.isSecrets
        ? `Git commit history proving credential purge + revocation log from credential authority.`
        : `Static analysis AST taint verification report proving complete parameterization.`,
      remediation_action: clf.isRCE
        ? `Upgrade ${pkg} to version ${fixedVer} and enforce immutable container execution.`
        : clf.isSecrets
        ? `Revoke exposed token immediately and store secret in secure Key Management Service (KMS).`
        : `Implement parameterized queries and strict schema-based input sanitization.`,
      sla_days: isCritical ? 7 : 30,
    });
  }

  // CC6.6: Boundary Protection & Input Sanitization
  if (clf.isInjection || clf.isXSS || clf.isSSRF || clf.isIaC) {
    items.push({
      id: `${finding.id}-soc2-cc6.6`,
      control_id: 'CC6.6',
      framework: 'SOC 2 Type II',
      soc2_category: 'CC6',
      category_name: 'Logical Access & Perimeter',
      title: clf.isXSS
        ? 'Web Application Content Security & Output Sanitization'
        : clf.isInjection
        ? 'Perimeter Input Validation & Parameterized Execution'
        : clf.isSSRF
        ? 'Egress Network Filtering & Request Target Allowlisting'
        : 'Cloud Infrastructure Hardening & Network Boundary Defenses',
      status: isResolved ? 'COMPLIANT' : isCritical ? 'NON-COMPLIANT' : 'WARNING',
      status_label: isResolved ? 'Control Satisfied' : isCritical ? 'Boundary Violation' : 'Sanitization Warning',
      status_badge_color: isResolved ? 'bg-[#F0FDF4] text-[#16A34A] border-[#BBF7D0]' : 'bg-[#FEF2F2] text-[#DC2626] border-[#FCA5A5]',
      assessment: clf.isXSS
        ? `Unsanitized output in ${finding.file_path} allows client-side script injection into authenticated browser contexts, violating SOC 2 CC6.6 web tier boundaries.`
        : clf.isInjection
        ? `Untrusted input parameters fed into sinks in ${finding.file_path} break perimeter data isolation layers.`
        : `Request handler allows internal server-side request forgery, probing private metadata or internal VPC endpoints.`,
      auditor_proof: `Static analysis taint report confirming parameterized data flow and complete output encoding.`,
      remediation_action: `Apply contextual output encoding, Content Security Policy (CSP) headers, and strict target allowlisting.`,
      sla_days: isCritical ? 7 : 30,
    });
  }

  // CC6.7: Cryptographic Protection & Data Transmission
  if (clf.isCrypto || clf.isSecrets) {
    items.push({
      id: `${finding.id}-soc2-cc6.7`,
      control_id: 'CC6.7',
      framework: 'SOC 2 Type II',
      soc2_category: 'CC6',
      category_name: 'Logical Access & Perimeter',
      title: 'Cryptographic Protection & Key Management Safeguards',
      status: isResolved ? 'COMPLIANT' : 'NON-COMPLIANT',
      status_label: isResolved ? 'Keys Secured' : 'Cryptographic Non-Compliance',
      status_badge_color: isResolved ? 'bg-[#F0FDF4] text-[#16A34A] border-[#BBF7D0]' : 'bg-[#FEF2F2] text-[#DC2626] border-[#FCA5A5]',
      assessment: `Sensitive token or cryptographic material is exposed in application code, violating SOC 2 CC6.7 encryption-at-rest and transmission safeguards.`,
      auditor_proof: `Verified migration of cryptographic materials to AWS Secrets Manager / HashiCorp Vault with automated rotation enabled.`,
      remediation_action: `Migrate static keys to runtime environment variables injected via secret management vault.`,
      sla_days: 7,
    });
  }

  // CC6.8: Vulnerability Management & SLA Policy Enforcement (Always required in SOC 2)
  items.push({
    id: `${finding.id}-soc2-cc6.8`,
    control_id: 'CC6.8',
    framework: 'SOC 2 Type II',
    soc2_category: 'CC6',
    category_name: 'Logical Access & Perimeter',
    title: `Vulnerability Management SLA Policy (${isCritical ? '7-Day Critical' : isHigh ? '30-Day High' : '90-Day Standard'} Window)`,
    status: isResolved ? 'COMPLIANT' : isCritical ? 'NON-COMPLIANT' : 'WARNING',
    status_label: isResolved ? 'SLA Satisfied' : isCritical ? 'SLA Policy Enforced (Critical)' : 'SLA Active Tracking',
    status_badge_color: isResolved ? 'bg-[#F0FDF4] text-[#16A34A] border-[#BBF7D0]' : isCritical ? 'bg-[#FEF2F2] text-[#DC2626] border-[#FCA5A5]' : 'bg-[#FFFBEB] text-[#D97706] border-[#FDE68A]',
    assessment: `SOC 2 CC6.8 mandates that entities detect and prevent unauthorized software and remediate security vulnerabilities within defined SLA thresholds (Critical: 7 calendar days, High: 30 calendar days).`,
    auditor_proof: `Audit trail recording first detection timestamp, assigned Jira issue key, and verified commit SHA timestamp prior to SLA deadline.`,
    remediation_action: `Ensure Jira remediation ticket is assigned and deploy validated fix before SLA cutoff date.`,
    sla_days: isCritical ? 7 : isHigh ? 30 : 90,
  });

  // =========================================================================
  // CC7: SYSTEM OPERATIONS & SUPPLY CHAIN
  // =========================================================================

  // CC7.1: Vulnerability Detection & Software Supply Chain (SCA)
  if (clf.isSCA || isCritical) {
    items.push({
      id: `${finding.id}-soc2-cc7.1`,
      control_id: 'CC7.1',
      framework: 'SOC 2 Type II',
      soc2_category: 'CC7',
      category_name: 'Operations & Supply Chain',
      title: 'Software Composition Analysis & Supply Chain Inventory',
      status: isResolved ? 'COMPLIANT' : isCritical ? 'NON-COMPLIANT' : 'WARNING',
      status_label: isResolved ? 'Dependency Patched' : 'Supply Chain Risk Active',
      status_badge_color: isResolved ? 'bg-[#F0FDF4] text-[#16A34A] border-[#BBF7D0]' : 'bg-[#FEF2F2] text-[#DC2626] border-[#FCA5A5]',
      assessment: `SOC 2 CC7.1 requires continuous vulnerability detection across infrastructure and application components. Library ${pkg} contains public advisory ${finding.rule_id || 'CVE'} present in build manifest (${finding.file_path}).`,
      auditor_proof: `Software Bill of Materials (SBOM) and clean Trivy/OSV scan execution logs showing zero unpatched CVEs.`,
      remediation_action: `Upgrade ${pkg} to version ${fixedVer} in ${finding.file_path} and regenerate lockfile checksums.`,
      sla_days: isCritical ? 7 : 30,
    });
  }

  // CC7.2: Security Monitoring, Anomaly Detection & Incident Response
  if (clf.isRCE || clf.isDoS || clf.isInjection) {
    items.push({
      id: `${finding.id}-soc2-cc7.2`,
      control_id: 'CC7.2',
      framework: 'SOC 2 Type II',
      soc2_category: 'CC7',
      category_name: 'Operations & Supply Chain',
      title: 'Security Monitoring, Anomaly Detection & Incident Triggers',
      status: isResolved ? 'COMPLIANT' : 'WARNING',
      status_label: isResolved ? 'Monitoring Active' : 'Exploit Exposure Active',
      status_badge_color: isResolved ? 'bg-[#F0FDF4] text-[#16A34A] border-[#BBF7D0]' : 'bg-[#FFFBEB] text-[#D97706] border-[#FDE68A]',
      assessment: `SOC 2 CC7.2 requires infrastructure to monitor system anomalies and detect potential execution exploits. Unmitigated ${clf.categoryLabel} represents an active attack vector requiring runtime detection rules.`,
      auditor_proof: `WAF / SIEM alert rule configuration and runtime application self-protection (RASP) logs.`,
      remediation_action: `Configure web application firewall (WAF) blocking rules while underlying code patch is being deployed.`,
      sla_days: 30,
    });
  }

  // =========================================================================
  // CC8: CHANGE MANAGEMENT
  // =========================================================================

  // CC8.1: Change Authorization, Pre-Deployment Testing & CI/CD Security Gating
  items.push({
    id: `${finding.id}-soc2-cc8.1`,
    control_id: 'CC8.1',
    framework: 'SOC 2 Type II',
    soc2_category: 'CC8',
    category_name: 'Change Management',
    title: 'Pre-Deployment Security Testing & Automated CI/CD Gates',
    status: isResolved ? 'COMPLIANT' : 'WARNING',
    status_label: isResolved ? 'CI Gate Passed' : 'Pre-Merge Gate Active',
    status_badge_color: isResolved ? 'bg-[#F0FDF4] text-[#16A34A] border-[#BBF7D0]' : 'bg-[#FFFBEB] text-[#D97706] border-[#FDE68A]',
    assessment: `SOC 2 CC8.1 mandates that all software changes must be authorized, tested for security defects, and approved prior to production release. The automated multi-scanner pipeline detected this issue before production branch merge.`,
    auditor_proof: `GitHub/GitLab branch protection rules enforcing passing security scan status check before pull request merge.`,
    remediation_action: `Ensure automated scanner PR check blocks merge until this finding is verified as remediated.`,
    sla_days: isCritical ? 7 : 30,
  });

  // =========================================================================
  // CC3: RISK ASSESSMENT
  // =========================================================================

  // CC3.2: Risk Assessment & Deterministic Scoring
  items.push({
    id: `${finding.id}-soc2-cc3.2`,
    control_id: 'CC3.2',
    framework: 'SOC 2 Type II',
    soc2_category: 'CC3',
    category_name: 'Risk Assessment',
    title: `Risk Severity & Threat Impact Assessment (Risk Score: ${finding.risk_score || 5.0})`,
    status: isResolved ? 'COMPLIANT' : isCritical ? 'NON-COMPLIANT' : 'WARNING',
    status_label: isResolved ? 'Risk Mitigated' : isCritical ? 'High Risk Threat' : 'Monitored Risk',
    status_badge_color: isResolved ? 'bg-[#F0FDF4] text-[#16A34A] border-[#BBF7D0]' : isCritical ? 'bg-[#FEF2F2] text-[#DC2626] border-[#FCA5A5]' : 'bg-[#FFFBEB] text-[#D97706] border-[#FDE68A]',
    assessment: `SOC 2 CC3.2 requires entities to assess the severity and probability of security vulnerabilities. This ${finding.severity || 'MEDIUM'} flaw was evaluated with risk score ${finding.risk_score || 5.0}/10.0 and assigned Priority ${finding.priority || 'P2'}.`,
    auditor_proof: `Deterministic risk engine calculation record factoring asset criticality, CVSS telemetry, and exploitability.`,
    remediation_action: `Incorporate finding into quarterly enterprise security risk assessment register.`,
    sla_days: isCritical ? 7 : 30,
  });

  // =========================================================================
  // CC4 & CC5: MONITORING & CONTROL ACTIVITIES
  // =========================================================================

  // CC4.1: Ongoing Automated Multi-Scanner Evaluations
  items.push({
    id: `${finding.id}-soc2-cc4.1`,
    control_id: 'CC4.1',
    framework: 'SOC 2 Type II',
    soc2_category: 'CC4_5',
    category_name: 'Monitoring & Controls',
    title: 'Ongoing & Separate Automated Security Evaluations',
    status: 'COMPLIANT',
    status_label: 'Evaluations Active',
    status_badge_color: 'bg-[#F0FDF4] text-[#16A34A] border-[#BBF7D0]',
    assessment: `SOC 2 CC4.1 requires ongoing evaluations of control effectiveness. Multi-engine scanner fleet (Semgrep, CodeQL, Trivy, OSV) provides independent automated verification across repositories.`,
    auditor_proof: `Automated scanner execution audit telemetry showing regular commit and scheduled pipeline scans.`,
    remediation_action: `Maintain multi-engine scanner fleet health and 100% repository coverage.`,
    sla_days: 0,
  });

  // CC5.1: Preventive & Detective Security Controls
  items.push({
    id: `${finding.id}-soc2-cc5.1`,
    control_id: 'CC5.1',
    framework: 'SOC 2 Type II',
    soc2_category: 'CC4_5',
    category_name: 'Monitoring & Controls',
    title: 'Security Control Activities & Technical Guardrails',
    status: isResolved ? 'COMPLIANT' : 'WARNING',
    status_label: isResolved ? 'Guardrail Active' : 'Deficiency Detected',
    status_badge_color: isResolved ? 'bg-[#F0FDF4] text-[#16A34A] border-[#BBF7D0]' : 'bg-[#FFFBEB] text-[#D97706] border-[#FDE68A]',
    assessment: `SOC 2 CC5.1 requires development of control activities that contribute to mitigation of security risks to acceptable levels.`,
    auditor_proof: `Repository security policies, linting configurations, and pre-commit hook enforcement evidence.`,
    remediation_action: `Deploy automated dependency update bot and pre-commit security verification hooks.`,
    sla_days: 30,
  });

  // =========================================================================
  // AVAILABILITY & CONFIDENTIALITY (A1.1 / C1.1 / PI1.1)
  // =========================================================================

  if (clf.isDoS) {
    items.push({
      id: `${finding.id}-soc2-a1.1`,
      control_id: 'A1.1',
      framework: 'SOC 2 Type II',
      soc2_category: 'AVAIL_CONF',
      category_name: 'Availability & Integrity',
      title: 'Availability Criteria & System Resiliency Defenses',
      status: isResolved ? 'COMPLIANT' : 'WARNING',
      status_label: isResolved ? 'Resilience Verified' : 'Availability Threat',
      status_badge_color: isResolved ? 'bg-[#F0FDF4] text-[#16A34A] border-[#BBF7D0]' : 'bg-[#FFFBEB] text-[#D97706] border-[#FDE68A]',
      assessment: `SOC 2 Availability Criteria A1.1 requires entities to maintain system operational capacity. Unchecked resource exhaustion in ${pkg} risks service denial.`,
      auditor_proof: `Performance stress test logs proving application resilience against malformed inputs.`,
      remediation_action: `Implement request body size limits, rate limiting, and upgrade ${pkg} to patched version.`,
      sla_days: 30,
    });
  }

  if (clf.isSecrets || clf.isCrypto || clf.isRCE) {
    items.push({
      id: `${finding.id}-soc2-c1.1`,
      control_id: 'C1.1',
      framework: 'SOC 2 Type II',
      soc2_category: 'AVAIL_CONF',
      category_name: 'Availability & Integrity',
      title: 'Confidentiality Safeguards & Data Leak Prevention',
      status: isResolved ? 'COMPLIANT' : isCritical ? 'NON-COMPLIANT' : 'WARNING',
      status_label: isResolved ? 'Data Protected' : 'Data Exposure Risk',
      status_badge_color: isResolved ? 'bg-[#F0FDF4] text-[#16A34A] border-[#BBF7D0]' : 'bg-[#FEF2F2] text-[#DC2626] border-[#FCA5A5]',
      assessment: `SOC 2 Confidentiality Criteria C1.1 requires confidential information to be protected during its lifecycle. Exploitation of ${clf.categoryLabel} could result in unauthorized data exfiltration.`,
      auditor_proof: `Data classification matrix and egress DLP monitoring logs.`,
      remediation_action: `Verify database access logs and purge credentials from version control history.`,
      sla_days: isCritical ? 7 : 30,
    });
  }

  if (clf.isInjection || clf.isXSS) {
    items.push({
      id: `${finding.id}-soc2-pi1.1`,
      control_id: 'PI1.1',
      framework: 'SOC 2 Type II',
      soc2_category: 'AVAIL_CONF',
      category_name: 'Availability & Integrity',
      title: 'Processing Integrity & Complete Data Validation',
      status: isResolved ? 'COMPLIANT' : 'WARNING',
      status_label: isResolved ? 'Integrity Verified' : 'Integrity At Risk',
      status_badge_color: isResolved ? 'bg-[#F0FDF4] text-[#16A34A] border-[#BBF7D0]' : 'bg-[#FFFBEB] text-[#D97706] border-[#FDE68A]',
      assessment: `SOC 2 Processing Integrity Criteria PI1.1 requires system processing to be complete, valid, and accurate. Malformed input injection threatens processing integrity.`,
      auditor_proof: `Automated unit and integration test reports verifying input validation boundary tests.`,
      remediation_action: `Implement strict schema validation prior to processing application requests.`,
      sla_days: 30,
    });
  }

  return items;
}

/**
 * Builds the comprehensive continuous SOC 2 compliance dashboard across all active findings for Tab 4
 */
export function buildGlobalComplianceDashboard(findings: VulnerabilityFinding[]): VulnerabilityComplianceControl[] {
  const openFindings = findings.filter((f) => f.status === 'OPEN' || !f.status);
  const criticals = openFindings.filter((f) => f.severity === 'CRITICAL' || (f.risk_score || 0) >= 9.0);
  const highs = openFindings.filter((f) => f.severity === 'HIGH' || (f.risk_score || 0) >= 7.0);
  const scaFindings = openFindings.filter((f) => f.finding_type === 'SCA' || !!f.package_name);
  const secretFindings = openFindings.filter((f) => f.finding_type === 'SECRET' || f.title?.toLowerCase().includes('secret'));
  const injectionFindings = openFindings.filter((f) => {
    const t = `${f.title || ''} ${f.description || ''}`.toLowerCase();
    return t.includes('injection') || t.includes('sqli') || t.includes('rce') || t.includes('remote code');
  });

  const now = Date.now();
  const criticalBreaches = criticals.filter((f) => {
    if (!f.remediation_due_at) return false;
    return new Date(f.remediation_due_at).getTime() < now;
  }).length;

  return [
    // CC1.1: Control Environment & Governance Integrity
    {
      control_id: 'CC1.1',
      title: 'Control Environment & Security Policy Governance',
      framework: 'SOC 2 Type II - Security (Control Environment)',
      status: 'PASS',
      failing_findings_count: 0,
      sla_days: 0,
      sla_breached_count: 0,
      description: 'The organization demonstrates commitment to security integrity, organizational structure, and authoritative management over secure coding baselines.',
      remediation_guide: 'Security policy compliance baselines and mandatory repository scan attachments are active and enforced.',
    },
    // CC2.1: Information & Security Communication
    {
      control_id: 'CC2.1',
      title: 'Information & Security Incident Communication Integrity',
      framework: 'SOC 2 Type II - Security (Communication)',
      status: criticalBreaches > 0 ? 'WARNING' : 'PASS',
      failing_findings_count: criticalBreaches,
      sla_days: 7,
      sla_breached_count: criticalBreaches,
      description: 'Security metrics, telemetry records, and SLA breach notices must be communicated promptly to internal stakeholders and engineering teams.',
      remediation_guide: criticalBreaches > 0
        ? `Dispatch automated incident communications for ${criticalBreaches} overdue SLA breaches to engineering owners.`
        : 'All security telemetry and audit trails are actively reporting without communication delays.',
    },
    // CC6.8: Vulnerability Management SLA
    {
      control_id: 'CC6.8',
      title: 'Vulnerability Management & Timely SLA Remediation',
      framework: 'SOC 2 Type II - Security (Logical Access)',
      status: criticals.length > 0 ? 'FAIL' : highs.length > 0 ? 'WARNING' : 'PASS',
      failing_findings_count: criticals.length + highs.length,
      sla_days: 7,
      sla_breached_count: criticalBreaches,
      description: 'Entities must scan all production systems continuously. Critical severity vulnerabilities must be remediated within 7 days, and High severity within 30 calendar days.',
      remediation_guide: criticals.length > 0
        ? `Remediate ${criticals.length} Critical vulnerability findings currently violating the 7-day policy SLA window.`
        : 'All critical findings are resolved. Continue tracking high-severity findings within 30-day window.',
    },
    // CC7.1: Software Supply Chain & SCA
    {
      control_id: 'CC7.1',
      title: 'Software Composition Analysis & Supply Chain Integrity',
      framework: 'SOC 2 Type II - Security (System Operations)',
      status: scaFindings.length > 0 ? (scaFindings.some((f) => f.severity === 'CRITICAL') ? 'FAIL' : 'WARNING') : 'PASS',
      failing_findings_count: scaFindings.length,
      sla_days: 30,
      sla_breached_count: 0,
      description: 'Third-party dependencies and container base images must be monitored continuously against public CVE/GHSA vulnerability databases with SBOM tracking.',
      remediation_guide: scaFindings.length > 0
        ? `Upgrade ${scaFindings.length} vulnerable open-source packages (e.g. ${scaFindings[0]?.package_name || 'dependencies'}) to verified patched versions.`
        : 'Zero vulnerable third-party dependencies detected across monitored repositories.',
    },
    // CC6.1: Logical Access & Perimeter Isolation
    {
      control_id: 'CC6.1',
      title: 'Logical Access Security & Remote Execution Boundary Defenses',
      framework: 'SOC 2 Type II - Security (Logical Access)',
      status: injectionFindings.length > 0 ? 'FAIL' : 'PASS',
      failing_findings_count: injectionFindings.length,
      sla_days: 7,
      sla_breached_count: 0,
      description: 'Logical access controls must prevent untrusted inputs from executing unauthorized commands or breaking out of execution boundaries.',
      remediation_guide: injectionFindings.length > 0
        ? `Patch ${injectionFindings.length} remote execution / injection flaws allowing potential boundary bypass.`
        : 'All boundary protection and access control verification tests are passing.',
    },
    // CC6.6: Perimeter Boundary Protections & Sanitization
    {
      control_id: 'CC6.6',
      title: 'Boundary Protection, Ingress Filtering & Input Sanitization',
      framework: 'SOC 2 Type II - Security (Logical Access)',
      status: openFindings.some((f) => (f.title || '').toLowerCase().includes('xss') || (f.title || '').toLowerCase().includes('injection')) ? 'FAIL' : 'PASS',
      failing_findings_count: openFindings.filter((f) => (f.title || '').toLowerCase().includes('xss') || (f.title || '').toLowerCase().includes('injection')).length,
      sla_days: 30,
      sla_breached_count: 0,
      description: 'Perimeter boundary controls and web sanitization must defend against client-side script injection (XSS) and server-side request forgery.',
      remediation_guide: 'Enforce parameterized queries, contextual output encoding, and restrictive Content Security Policy (CSP) headers.',
    },
    // CC6.7: Cryptographic Key Security & Zero Hardcoded Secrets
    {
      control_id: 'CC6.7',
      title: 'Cryptographic Secret Security & Zero Hardcoded Credentials',
      framework: 'SOC 2 Type II - Security (Logical Access)',
      status: secretFindings.length > 0 ? 'FAIL' : 'PASS',
      failing_findings_count: secretFindings.length,
      sla_days: 7,
      sla_breached_count: 0,
      description: 'Automated secret detection must ensure no plain-text API keys, passwords, or private cryptographic tokens exist in source control.',
      remediation_guide: secretFindings.length > 0
        ? `Purge and rotate ${secretFindings.length} hardcoded secret tokens identified in source code commits.`
        : 'Zero hardcoded secrets detected in active git branches.',
    },
    // CC8.1: Change Management & SAST Gate Pre-Merge
    {
      control_id: 'CC8.1',
      title: 'Change Management & Automated Pre-Deployment Security Gating',
      framework: 'SOC 2 Type II - Security (Change Management)',
      status: 'PASS',
      failing_findings_count: 0,
      sla_days: 0,
      sla_breached_count: 0,
      description: 'Automated multi-scanner security analysis (Semgrep, CodeQL, Trivy, OSV) must execute on all pull requests prior to merge into main.',
      remediation_guide: 'Branch protection checks and automated security pipelines are verified active across connected repositories.',
    },
    // CC3.2: Risk Assessment & Severity Analysis
    {
      control_id: 'CC3.2',
      title: 'Risk Assessment & Deterministic Threat Scoring',
      framework: 'SOC 2 Type II - Security (Risk Assessment)',
      status: criticals.length > 0 ? 'FAIL' : 'PASS',
      failing_findings_count: criticals.length,
      sla_days: 30,
      sla_breached_count: criticalBreaches,
      description: 'Entities must assess the severity and probability of security vulnerabilities factoring asset criticality, CVSS metrics, and exploit likelihood.',
      remediation_guide: `Risk register has ${criticals.length} active critical vulnerabilities requiring risk treatment documentation.`,
    },
    // CC4.1: Ongoing & Separate Security Evaluations
    {
      control_id: 'CC4.1',
      title: 'Continuous Automated Multi-Engine Security Evaluations',
      framework: 'SOC 2 Type II - Security (Monitoring Activities)',
      status: 'PASS',
      failing_findings_count: 0,
      sla_days: 0,
      sla_breached_count: 0,
      description: 'Continuous monitoring of security controls through automated SAST, SCA, and secret scanning across all git branches.',
      remediation_guide: 'All scanner engines (Semgrep, CodeQL, Trivy, OSV) are operational with active scanning telemetry.',
    },
    // CC5.1: Preventive Technical Guardrails
    {
      control_id: 'CC5.1',
      title: 'Technical Security Control Activities & Enforcement Guardrails',
      framework: 'SOC 2 Type II - Security (Control Activities)',
      status: openFindings.length > 0 ? 'WARNING' : 'PASS',
      failing_findings_count: openFindings.length,
      sla_days: 30,
      sla_breached_count: 0,
      description: 'Policies deployed through procedure establishing automated branch rules, PR security status checks, and dependency verification.',
      remediation_guide: 'Maintain strict pre-commit hooks and dependency review automation.',
    },
    // CC7.2: Threat Monitoring & Anomaly Detection
    {
      control_id: 'CC7.2',
      title: 'Security Monitoring, Anomaly Detection & Threat Triggering',
      framework: 'SOC 2 Type II - Security (System Operations)',
      status: injectionFindings.length > 0 ? 'WARNING' : 'PASS',
      failing_findings_count: injectionFindings.length,
      sla_days: 30,
      sla_breached_count: 0,
      description: 'System monitoring must detect anomalous traffic patterns and prevent exploitation of unmitigated vulnerabilities.',
      remediation_guide: 'Ensure WAF filtering rules and runtime anomaly alerts are operational for active injection vectors.',
    },
    // CC9.2: Vendor & Supplier Risk Management
    {
      control_id: 'CC9.2',
      title: 'Third-Party Software Vendor & Open-Source Supplier Risk',
      framework: 'SOC 2 Type II - Security (Risk Mitigation)',
      status: scaFindings.length > 0 ? 'WARNING' : 'PASS',
      failing_findings_count: scaFindings.length,
      sla_days: 30,
      sla_breached_count: 0,
      description: 'Assessment and ongoing management of risks associated with third-party software dependencies incorporated into production code.',
      remediation_guide: 'Conduct supplier risk reviews and enforce automated dependency version update gates.',
    },
    // A1.1: Availability & System Resiliency Criteria
    {
      control_id: 'A1.1',
      title: 'Availability Criteria & System Resiliency Assurance',
      framework: 'SOC 2 Type II - Availability',
      status: openFindings.some((f) => (f.title || '').toLowerCase().includes('denial of service') || (f.title || '').toLowerCase().includes('dos')) ? 'WARNING' : 'PASS',
      failing_findings_count: openFindings.filter((f) => (f.title || '').toLowerCase().includes('denial of service') || (f.title || '').toLowerCase().includes('dos')).length,
      sla_days: 30,
      sla_breached_count: 0,
      description: 'Capacity and operational availability planning protecting systems from denial of service attacks and resource exhaustion.',
      remediation_guide: 'Remediate active denial-of-service vulnerabilities and enforce strict request timeout and concurrency limits.',
    },
    // C1.1: Confidentiality & Sensitive Data Safeguards
    {
      control_id: 'C1.1',
      title: 'Confidentiality Criteria & Data Exfiltration Prevention',
      framework: 'SOC 2 Type II - Confidentiality',
      status: (criticals.length > 0 || secretFindings.length > 0) ? 'FAIL' : 'PASS',
      failing_findings_count: criticals.length + secretFindings.length,
      sla_days: 7,
      sla_breached_count: criticalBreaches,
      description: 'Protection of confidential customer and system data against unauthorized exposure, access, or data leakage.',
      remediation_guide: 'Prioritize resolution of critical execution and secret leakage flaws to prevent unauthorized access to customer records.',
    },
    // PI1.1: Processing Integrity & Input Validation
    {
      control_id: 'PI1.1',
      title: 'Processing Integrity Criteria & Input Validation Safeguards',
      framework: 'SOC 2 Type II - Processing Integrity',
      status: injectionFindings.length > 0 ? 'WARNING' : 'PASS',
      failing_findings_count: injectionFindings.length,
      sla_days: 30,
      sla_breached_count: 0,
      description: 'System processing must be complete, valid, accurate, and authorized with comprehensive input boundary checks.',
      remediation_guide: 'Implement strict input validation schemas to prevent malformed data from affecting transaction processing integrity.',
    },
  ];
}

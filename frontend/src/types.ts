export type ProviderType = 'github' | 'gitlab' | 'bitbucket' | 'jira';

export type SystemCategory = 'all' | 'repo' | 'ticketing';

export type ConnectionStatus =
  | 'connected'
  | 'connecting'
  | 'syncing'
  | 'monitoring'
  | 'paused'
  | 'warning'
  | 'error';

export type MonitoringStatus = 'active' | 'paused' | 'degraded' | 'error';

export type ControlStatus = 'PASS' | 'FAIL' | 'INSUFFICIENT_DATA' | 'NOT_APPLICABLE';

export interface System {
  id: string;
  name: string;
  provider: ProviderType;
  category: SystemCategory;
  owner: string;
  orgOrWorkspace: string;
  repoCount: number;
  pullRequestCount: number;
  pendingTaskCount: number;
  failingTaskCount: number;
  criticalTaskCount: number;
  dueTaskCount: number;
  connectionStatus: ConnectionStatus;
  monitoringStatus: MonitoringStatus;
  lastSyncTime: string;
  nextSyncTime: string;
  tokenPreview: string;
  isContinuousMonitoring: boolean;
  monitorPRs: boolean;
  monitorReviews: boolean;
  monitorCICD: boolean;
  monitorDeployments: boolean;
  repoScope: 'all' | 'selected';
  selectedReposList?: string[];
  projectsCount?: number;
  changeRequestsCount?: number;
  approvalsCount?: number;
  siteUrl?: string;
  createdAt: string;
  updatedAt: string;
}

export interface Repository {
  id: string;
  systemId: string;
  name: string;
  defaultBranch: string;
  changesCount: number;
  pullRequestsCount: number;
  lastActivity: string;
  status: 'active' | 'warning' | 'error';
  branchProtectionEnforced: boolean;
  requireReviewersCount: number;
  requireStatusChecks: boolean;
  allowAdminBypass: boolean;
}

export interface Reviewer {
  name: string;
  avatar?: string;
  approved: boolean;
}

export interface PullRequest {
  id: string;
  systemId: string;
  repoId: string;
  repoName: string;
  prNumber: string;
  title: string;
  author: string;
  authorAvatar?: string;
  reviewers: Reviewer[];
  approvalStatus: 'Approved' | 'Pending Review' | 'Changes Requested' | 'Checks Failing';
  ciStatus: 'PASS' | 'FAIL' | 'RUNNING' | 'PENDING';
  branch: string;
  targetBranch: string;
  updatedTime: string;
  linkedJiraIssue?: string;
}

export interface Pipeline {
  id: string;
  systemId: string;
  repoId: string;
  repoName: string;
  pipelineId: string;
  commitSha: string;
  commitMessage: string;
  status: 'PASS' | 'FAIL' | 'RUNNING' | 'CANCELLED';
  testsSummary: string;
  startedTime: string;
  completedTime: string;
  deploymentEnv: 'Production' | 'Staging' | 'QA' | 'None';
  trigger: string;
  author: string;
  htmlUrl?: string;
}

export interface ControlEvidence {
  type: string;
  title: string;
  status: 'verified' | 'failed' | 'missing';
  details: string;
}

export interface Control {
  id: string;
  systemId: string;
  controlCode: string;
  title: string;
  description: string;
  status: ControlStatus;
  pendingCount: number;
  requirementText: string;
  observedText: string;
  relatedChange: {
    changeId: string;
    title?: string;
    repoName: string;
    prNumber: string;
    commitSha: string;
    ciPipelineId: string;
    deploymentId: string;
  };
  evidenceItems: ControlEvidence[];
  findingSummary: string;
  remediation: {
    title: string;
    steps: string[];
    owner: string;
    slaDaysRemaining: number;
    slaDate: string;
  };
  lastEvaluated: string;
}

export interface MonitoringEvent {
  id: string;
  timestamp: string;
  timeString: string;
  title: string;
  category: 'pr' | 'ci' | 'evaluation' | 'decision' | 'finding' | 'remediation' | 'sync';
  status: 'success' | 'warning' | 'info' | 'error';
  description?: string;
  systemId?: string;
}

export interface MonitoringOverview {
  activeSystems: number;
  eventsProcessed: number;
  changesDetected: number;
  reEvaluations: number;
  pendingTasks: number;
  webhookStatus: 'active' | 'degraded' | 'inactive';
  periodicSyncStatus: 'active' | 'paused';
  lastSync: string;
  nextSync: string;
}

export interface ToastNotification {
  id: string;
  type: 'success' | 'info' | 'warning' | 'error';
  title?: string;
  message: string;
  duration?: number;
}

export interface EvidenceDetail {
  evidence_id: string;
  change_id: string;
  evidence_type: string;
  source: string;
  source_type: string;
  source_record_id: string;
  event_id?: string;
  check_id?: string;
  file_name: string;
  description: string;
  hash: string;
  content_hash: string;
  source_hash: string;
  storage_reference: string;
  status: string;
  freshness_status: string;
  integrity_status: string;
  version: number;
  collected_at: string;
  observed_at: string;
  validated_at: string;
  metadata_json?: Record<string, any>;
}

export interface RawEventDetail {
  event_id: string;
  event_type: string;
  source: string;
  repository: string;
  commit_sha: string;
  started_at?: string;
  completed_at?: string;
  payload: Record<string, any>;
  sha256: string;
  integrity_verified: boolean;
}

export interface EvaluationAssertion {
  name: string;
  expected: string;
  actual: string;
  passed: boolean;
}

export interface ProvenanceChainStep {
  step: string;
  label: string;
  value: string;
  status: 'verified' | 'failed' | 'pending';
}

export interface CheckExplanation {
  check_id: string;
  name: string;
  category: string;
  severity: string;
  description: string;
  result: 'PASS' | 'FAIL';
  expected: string;
  observed: string;
  assertions: EvaluationAssertion[];
  provenance_chain: ProvenanceChainStep[];
  evidence: Array<{
    evidence_id: string;
    evidence_type: string;
    source: string;
    source_record_id: string;
    status: string;
    freshness_status: string;
    integrity_status: string;
    hash: string;
    storage_reference: string;
    collected_at: string;
  }>;
}

export interface VulnerabilityFinding {
  id: string;
  scan_id?: string;
  rule_id: string;
  rule_name?: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence?: string;
  file_path: string;
  start_line: number;
  start_column?: number;
  end_line?: number;
  end_column?: number;
  cwe: string[];
  cve?: string[];
  owasp_category: string[];
  status: 'OPEN' | 'IN_REMEDIATION' | 'RESOLVED' | 'FALSE_POSITIVE' | 'MUTED';
  risk_score: number;
  risk_level: string;
  priority: string;
  remediation?: string;
  remediation_due_at?: string;
  verification_status?: 'VERIFIED' | 'UNVERIFIED' | 'PENDING' | 'FAILED';
  jira_issue_key?: string;
  pr_url?: string;
  repository_id?: string;
  repository_name: string;
  branch?: string;
  commit_sha?: string;
  scanner: string;
  scanner_version?: string;
  finding_type?: string;
  package_name?: string;
  package_version?: string;
  fixed_version?: string;
  ghsa?: string;
  osv_id?: string;
  cvss?: number;
  epss?: number;
  detected_by_scanners?: string[];
  code_snippet?: string;
  code_context?: string;
  created_at?: string;
}

export interface ScannerEngine {
  name: string;
  version: string;
  available: boolean;
  supported_languages: string[];
  scan_types: string[];
  features: string[];
}

export interface ScanJob {
  id: string;
  repository_id?: string;
  repository_name: string;
  branch: string;
  commit_sha?: string;
  scan_type: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | string;
  current_phase?: string;
  state_progress_percentage?: number;
  current_phase_description?: string;
  scanners: string[];
  scanner_versions?: Record<string, string>;
  files_scanned: number;
  rules_executed: number;
  finding_count: number;
  raw_result_hash?: string;
  error_message?: string;
  started_at?: string;
  completed_at?: string;
  created_at: string;
}

export interface VulnerabilityRepoSummary {
  id: string;
  name: string;
  default_branch: string;
  languages: string[];
  sast_status: string;
  finding_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  last_scan?: string | null;
  commit_sha?: string;
  system_id?: string;
}

export interface VulnerabilityComplianceControl {
  control_id: string;
  title: string;
  framework: string;
  status: 'PASS' | 'FAIL' | 'WARNING';
  failing_findings_count: number;
  sla_days: number;
  sla_breached_count: number;
  description: string;
  remediation_guide: string;
}

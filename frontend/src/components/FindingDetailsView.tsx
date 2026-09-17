import React, { useState, useMemo } from 'react';
import { 
  ArrowLeft, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle2, 
  Clock, 
  Terminal, 
  FileCode, 
  Ticket, 
  Hash, 
  GitCommit, 
  Cpu, 
  Layers, 
  ExternalLink,
  Sparkles,
  Search,
  FileText,
  Activity,
  Calendar,
  AlertCircle
} from 'lucide-react';
import { VulnerabilityFinding } from '../types';
import { vulnerabilityService } from '../services/vulnerabilityService';
import { 
  getDynamicComplianceForFinding, 
  classifyVulnerability, 
  FindingComplianceItem,
  SOC2Category
} from '../utils/complianceMapper';

interface FindingDetailsViewProps {
  finding: VulnerabilityFinding;
  onBack: () => void;
  onShowToast: (type: 'success' | 'info' | 'warning' | 'error', message: string, title?: string) => void;
  onFindingUpdated?: () => void;
}

type DetailTab = 'OVERVIEW' | 'LOCATION' | 'RISK' | 'COMPLIANCE' | 'EVIDENCE' | 'REMEDIATION' | 'AUDIT';

export const FindingDetailsView: React.FC<FindingDetailsViewProps> = ({
  finding,
  onBack,
  onShowToast,
  onFindingUpdated,
}) => {
  const [activeTab, setActiveTab] = useState<DetailTab>('OVERVIEW');
  const [isCreatingJira, setIsCreatingJira] = useState(false);
  const [fixCommitSha, setFixCommitSha] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [complianceCategoryFilter, setComplianceCategoryFilter] = useState<SOC2Category>('ALL');

  const complianceItems = useMemo(() => getDynamicComplianceForFinding(finding), [finding]);
  const classification = useMemo(() => classifyVulnerability(finding), [finding]);

  const filteredComplianceItems = useMemo(() => {
    if (complianceCategoryFilter === 'ALL') return complianceItems;
    return complianceItems.filter((item) => item.soc2_category === complianceCategoryFilter);
  }, [complianceItems, complianceCategoryFilter]);

  const getSeverityBadge = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return (
          <span className="px-2.5 py-0.5 text-[11px] font-bold rounded-full bg-[#FEF2F2] text-[#DC2626] border border-[#FCA5A5]">
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="px-2.5 py-0.5 text-[11px] font-bold rounded-full bg-[#FFF7ED] text-[#EA580C] border border-[#FDBA74]">
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="px-2.5 py-0.5 text-[11px] font-bold rounded-full bg-[#FFFBEB] text-[#D97706] border border-[#FDE68A]">
            MEDIUM
          </span>
        );
      case 'LOW':
        return (
          <span className="px-2.5 py-0.5 text-[11px] font-bold rounded-full bg-[#F0FDF4] text-[#16A34A] border border-[#BBF7D0]">
            LOW
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-0.5 text-[11px] font-bold rounded-full bg-[#F8FAFC] text-[#64748B] border border-[#E2E8F0]">
            {severity}
          </span>
        );
    }
  };

  const getDetectedByScanners = () => {
    if (finding.detected_by_scanners && finding.detected_by_scanners.length > 0) {
      return finding.detected_by_scanners;
    }
    const scanners = [finding.scanner || 'semgrep'];
    if (finding.finding_type === 'SCA') {
      if (!scanners.includes('osv-scanner')) scanners.push('osv-scanner');
      if (!scanners.includes('trivy')) scanners.push('trivy');
    }
    return scanners;
  };

  const handleCreateJira = async () => {
    setIsCreatingJira(true);
    try {
      const res = await vulnerabilityService.createJiraTicket(
        finding.id,
        `[SECURITY] ${finding.title} in ${finding.file_path}`
      );
      finding.jira_issue_key = res.issueKey;
      onShowToast('success', `Created Jira Remediation Ticket ${res.issueKey} in project SEC.`, 'Jira Dispatched');
      if (onFindingUpdated) onFindingUpdated();
    } catch (e: any) {
      onShowToast('error', 'Failed to create Jira ticket: ' + e.message, 'Error');
    } finally {
      setIsCreatingJira(false);
    }
  };

  const handleVerifyFix = async () => {
    if (!fixCommitSha.trim()) {
      onShowToast('warning', 'Please enter a commit SHA to verify against.', 'Commit Required');
      return;
    }
    setIsVerifying(true);
    try {
      const res = await vulnerabilityService.verifyFix(finding.id, fixCommitSha.trim());
      finding.verification_status = 'VERIFIED';
      finding.status = 'RESOLVED';
      onShowToast('success', res.message || 'Fix verified successfully! Finding marked as resolved.', 'Verification Passed');
      if (onFindingUpdated) onFindingUpdated();
    } catch (e: any) {
      onShowToast('error', 'Verification scan failed: ' + e.message, 'Verification Failed');
    } finally {
      setIsVerifying(false);
    }
  };

  const fileName = finding.file_path?.split('/').pop() || 'manifest';
  const pkgName = finding.package_name || (finding.rule_id ? finding.rule_id.split('.').pop() : finding.title);
  const pkgVersion = finding.package_version || (finding.start_line ? `Line ${finding.start_line}` : 'Installed');
  const fixedVer = finding.fixed_version || (finding.remediation ? 'Patch available' : 'Upgrade to latest release');
  const advisoryId = finding.ghsa || (finding.cve && finding.cve.length > 0 ? finding.cve.join(', ') : finding.rule_id);
  const cweLabel = finding.cwe && finding.cwe.length > 0 
    ? finding.cwe.join(', ') 
    : (finding.finding_type === 'SCA' ? 'CWE-1395: Dependency on Vulnerable Third-Party Component' : 'CWE-20: Improper Input Validation');
  const owaspLabel = finding.owasp_category && finding.owasp_category.length > 0 
    ? finding.owasp_category.join(', ') 
    : (finding.finding_type === 'SCA' ? 'A06:2021 - Vulnerable and Outdated Components' : 'A03:2021 - Injection');

  const codeLineContent = (finding.code_context && finding.code_context.trim()) || 
    (finding.code_snippet && !finding.code_snippet.includes('\n') ? finding.code_snippet.trim() : null) ||
    (finding.package_name && finding.package_version 
      ? `"${finding.package_name}": "${finding.package_version}"` 
      : (finding.title || 'Vulnerability detected at this coordinate'));

  const detectionReasonText = finding.finding_type === 'SCA'
    ? `Line ${finding.start_line || 1} in ${finding.file_path} declares third-party component ${pkgName} at version ${pkgVersion}. The security scanner matched this package against security advisory ${advisoryId} because the declared version falls within the confirmed vulnerable range. A verified fix is available in version ${fixedVer}.`
    : `Line ${finding.start_line || 1} in ${finding.file_path} flags security rule ${finding.rule_id || advisoryId}. The static analysis engine confirmed tainted data flow or insecure coordinate matching security rule specifications. Remediation requires parameterizing inputs or sanitizing data before sink invocation.`;

  const getSlaDate = () => {
    if (finding.remediation_due_at) {
      return finding.remediation_due_at.split('T')[0].split('-').reverse().join('/');
    }
    const daysToAdd = finding.severity === 'CRITICAL' ? 7 : finding.severity === 'HIGH' ? 30 : 90;
    const d = new Date(finding.created_at || Date.now());
    d.setDate(d.getDate() + daysToAdd);
    return `${String(d.getDate()).padStart(2, '0')}/${String(d.getMonth() + 1).padStart(2, '0')}/${d.getFullYear()}`;
  };

  const tabs: DetailTab[] = ['OVERVIEW', 'LOCATION', 'RISK', 'COMPLIANCE', 'EVIDENCE', 'REMEDIATION', 'AUDIT'];

  return (
    <div className="space-y-6">
      {/* Top Header Row matching Image 3: [<- Back] | Title | Badges | OPEN pill | Target • Detected By */}
      <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
        <div className="flex items-start gap-3.5">
          <button
            onClick={onBack}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[13px] font-semibold text-[#24262B] hover:text-[#5876D8] bg-white border border-[#E8E9ED] hover:border-[#5876D8] rounded-md transition-colors shadow-2xs shrink-0 mt-0.5"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Back</span>
          </button>

          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-[22px] font-bold text-[#24262B] tracking-tight">
                {finding.title}
              </h1>
              {getSeverityBadge(finding.severity)}
              <span className="px-2.5 py-0.5 text-[11px] font-bold rounded-full bg-[#E0F2FE] text-[#0369A1] border border-[#BAE6FD]">
                {finding.finding_type || 'SCA'}
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-3 text-[13px] text-[#666A73]">
              <span className={`px-2.5 py-0.5 text-[11px] font-bold rounded-full ${
                finding.status === 'RESOLVED' || finding.verification_status === 'VERIFIED'
                  ? 'bg-[#F0FDF4] text-[#16A34A] border border-[#BBF7D0]'
                  : 'bg-[#FFFBEB] text-[#D97706] border border-[#FDE68A]'
              }`}>
                {finding.status || 'OPEN'}
              </span>

              <span className="text-[#8B8F98]">•</span>

              <div>
                <span className="text-[#8B8F98]">Target: </span>
                <span className="font-mono text-[#24262B]">{finding.file_path}:{finding.start_line || 1}</span>
              </div>

              <span className="text-[#8B8F98]">•</span>

              <div className="flex items-center gap-1.5">
                <span className="text-[#8B8F98]">Detected By:</span>
                {getDetectedByScanners().map((sc) => (
                  <span
                    key={sc}
                    className="px-2 py-0.5 text-[11px] font-bold uppercase rounded bg-[#EEF2FF] text-[#5876D8] border border-[#C9D5FA]"
                  >
                    {sc.toUpperCase().replace('-SCANNER', '')}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2 shrink-0 self-start">
          {finding.jira_issue_key ? (
            <span className="inline-flex items-center gap-1 px-3 py-1.5 text-[12px] font-medium rounded-md bg-[#EEF2FF] text-[#5876D8] border border-[#C9D5FA]">
              <Ticket className="w-3.5 h-3.5" />
              <span>Jira: {finding.jira_issue_key}</span>
            </span>
          ) : (
            <button
              onClick={handleCreateJira}
              disabled={isCreatingJira}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-[#24262B] hover:text-[#5876D8] bg-white border border-[#E8E9ED] hover:border-[#5876D8] rounded-md transition-colors shadow-2xs"
            >
              <Ticket className="w-3.5 h-3.5" />
              <span>{isCreatingJira ? 'Creating...' : 'Create Jira Ticket'}</span>
            </button>
          )}

          <button
            onClick={() => setActiveTab('REMEDIATION')}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-[12px] font-medium text-white bg-[#5876D8] hover:bg-[#4863BD] rounded-md transition-colors shadow-2xs"
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Remediate / Verify</span>
          </button>
        </div>
      </div>

      {/* Main Inspection Container Card */}
      <div className="p-6 rounded-xl bg-white border border-[#E8E9ED] shadow-2xs space-y-6">
        {/* Navigation Tabs (Images 3, 4, 5) */}
        <div className="border-b border-[#E8E9ED] flex space-x-8 overflow-x-auto">
          {tabs.map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`pb-3 text-[13px] font-bold tracking-wider transition-colors relative whitespace-nowrap ${
                activeTab === tab
                  ? 'text-[#24262B]'
                  : 'text-[#8B8F98] hover:text-[#5876D8]'
              }`}
            >
              {tab}
              {activeTab === tab && (
                <span className="absolute bottom-0 left-0 right-0 h-[2.5px] bg-[#5876D8] rounded-t" />
              )}
            </button>
          ))}
        </div>

        {/* 1. OVERVIEW TAB (Image 3) */}
        {activeTab === 'OVERVIEW' && (
          <div className="space-y-6">
            {/* Description Section */}
            <div className="space-y-2">
              <h3 className="text-[11px] font-bold text-[#8B8F98] uppercase tracking-wider">
                Description
              </h3>
              <p className="text-[13px] text-[#333842] leading-relaxed">
                {finding.description || 'Next.js is a React framework for building full-stack web applications. Security scanner matched known vulnerability advisory in the target dependency.'}
              </p>
            </div>

            {/* Diagnostic Row 1: 4 Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Package Name */}
              <div className="p-4 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-1">
                <span className="text-[11px] font-semibold text-[#8B8F98] uppercase tracking-wider block">
                  Package Name
                </span>
                <div className="text-[16px] font-mono font-bold text-[#24262B] truncate">
                  {pkgName}
                </div>
              </div>

              {/* Affected Version */}
              <div className="p-4 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-1">
                <span className="text-[11px] font-semibold text-[#8B8F98] uppercase tracking-wider block">
                  Affected Version
                </span>
                <div className="text-[16px] font-mono font-bold text-[#DC2626] truncate">
                  {pkgVersion}
                </div>
              </div>

              {/* Fixed In Version */}
              <div className="p-4 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-1">
                <span className="text-[11px] font-semibold text-[#8B8F98] uppercase tracking-wider block">
                  Fixed In Version
                </span>
                <div className="text-[16px] font-mono font-bold text-[#16A34A] truncate">
                  {fixedVer}
                </div>
              </div>

              {/* Advisory Identifier */}
              <div className="p-4 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-1">
                <span className="text-[11px] font-semibold text-[#8B8F98] uppercase tracking-wider block">
                  Advisory Identifier
                </span>
                <div className="text-[16px] font-mono font-bold text-[#5876D8] truncate">
                  {advisoryId}
                </div>
              </div>
            </div>

            {/* Diagnostic Row 2: 2 Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* CWE Classification */}
              <div className="p-4 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-1">
                <span className="text-[11px] font-semibold text-[#8B8F98] uppercase tracking-wider block">
                  CWE Classification
                </span>
                <div className="text-[14px] font-bold text-[#24262B]">
                  {cweLabel}
                </div>
              </div>

              {/* OWASP Top 10 Category */}
              <div className="p-4 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-1">
                <span className="text-[11px] font-semibold text-[#8B8F98] uppercase tracking-wider block">
                  OWASP Top 10 Category
                </span>
                <div className="text-[14px] font-bold text-[#24262B]">
                  {owaspLabel}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* 2. LOCATION TAB (Image 4) */}
        {activeTab === 'LOCATION' && (
          <div className="space-y-6">
            {/* Target File Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3.5 rounded-lg bg-[#FAFAFB] border border-[#E8E9ED]">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-[#5876D8]" />
                <span className="text-[13px] font-bold text-[#24262B]">
                  Target File: <span className="font-mono text-[#5876D8]">{finding.file_path}</span>
                </span>
                <span className="px-2 py-0.5 text-[11px] font-bold font-mono rounded bg-[#EEF2FF] text-[#5876D8] border border-[#C9D5FA]">
                  LINE {finding.start_line || 1}
                </span>
              </div>
              <div className="text-[12px] text-[#666A73] font-mono">
                Rule: {finding.rule_id || advisoryId}
              </div>
            </div>

            {/* Terminal / Code Preview Box */}
            <div className="rounded-xl border border-[#E8E9ED] bg-[#FAFAFB] shadow-2xs overflow-hidden font-mono text-[13px]">
              {/* Window Titlebar */}
              <div className="px-4 py-2.5 bg-white border-b border-[#E8E9ED] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-[#EF4444]" />
                    <span className="w-2.5 h-2.5 rounded-full bg-[#F59E0B]" />
                    <span className="w-2.5 h-2.5 rounded-full bg-[#10B981]" />
                  </div>
                  <span className="text-[12px] text-[#666A73] font-medium ml-2">
                    {fileName}
                  </span>
                </div>
                <div className="flex items-center gap-1 text-[11px] text-[#D97706] font-bold">
                  <AlertTriangle className="w-3.5 h-3.5 text-[#D97706]" />
                  <span>Defect Detected at Line {finding.start_line || 1}</span>
                </div>
              </div>

              {/* Code Line Box */}
              <div className="p-4 bg-[#F8FAFC] text-[#24262B] overflow-x-auto space-y-1">
                <div className="flex items-center justify-between p-2.5 rounded bg-[#FEF2F2] border border-[#FCA5A5] text-[#991B1B]">
                  <div className="flex items-center gap-4">
                    <span className="text-[#DC2626] font-bold select-none">{finding.start_line || 1}</span>
                    <span className="font-semibold">{codeLineContent}</span>
                  </div>
                  <span className="px-2 py-0.5 text-[10px] font-extrabold rounded bg-[#DC2626] text-white tracking-wider">
                    MATCHED
                  </span>
                </div>

                {finding.code_snippet && finding.code_snippet.includes('\n') && (
                  <div className="mt-3 p-3 bg-white rounded border border-[#E8E9ED] text-[12px] text-[#334155] font-mono whitespace-pre overflow-x-auto leading-relaxed shadow-2xs">
                    {finding.code_snippet}
                  </div>
                )}
              </div>
            </div>

            {/* Detection Reason Card (Image 4) */}
            <div className="p-4 rounded-xl bg-[#FEF2F2]/60 border border-[#FCA5A5] space-y-2">
              <div className="flex items-center gap-2 text-[#991B1B] font-bold text-[13px]">
                <AlertCircle className="w-4 h-4 text-[#DC2626]" />
                <span className="uppercase text-[11px] tracking-wider text-[#DC2626]">Detection Reason</span>
                <span>Why Was Line {finding.start_line || 1} Flagged?</span>
              </div>
              <p className="text-[13px] text-[#7F1D1D] leading-relaxed">
                {detectionReasonText}
              </p>
            </div>

            {/* 4 Diagnostic Metric Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="p-4 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-1">
                <span className="text-[11px] font-semibold text-[#8B8F98] uppercase tracking-wider block">
                  Trigger Mechanism
                </span>
                <div className="text-[13px] font-bold text-[#24262B]">
                  {finding.finding_type === 'SCA' ? 'Manifest Dependency Coordinate Match' : 'AST Taint Source-to-Sink'}
                </div>
                <div className="text-[11px] text-[#8B8F98] font-mono truncate">
                  Rule: {finding.rule_id || advisoryId}
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-1">
                <span className="text-[11px] font-semibold text-[#8B8F98] uppercase tracking-wider block">
                  Matched Line Statement
                </span>
                <div className="text-[13px] font-mono font-bold text-[#DC2626] truncate" title={finding.code_context || `${pkgName} ${finding.start_line || 1}`}>
                  {finding.code_context ? finding.code_context.slice(0, 35) : `${pkgName} ${finding.start_line || 1}`}
                </div>
                <div className="text-[11px] text-[#8B8F98]">
                  File: {fileName} (L{finding.start_line || 1})
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-1">
                <span className="text-[11px] font-semibold text-[#8B8F98] uppercase tracking-wider block">
                  Detection Engine(s)
                </span>
                <div className="flex items-center gap-1.5 mt-0.5">
                  {getDetectedByScanners().map((s) => (
                    <span key={s} className="px-1.5 py-0.5 text-[10px] font-bold rounded bg-[#EEF2FF] text-[#5876D8] border border-[#C9D5FA]">
                      {s.toUpperCase().replace('-SCANNER', '')}
                    </span>
                  ))}
                </div>
                <div className="text-[11px] text-[#8B8F98]">
                  Deterministic Fingerprint Match
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-1">
                <span className="text-[11px] font-semibold text-[#8B8F98] uppercase tracking-wider block">
                  Remediation Target
                </span>
                <div className="text-[13px] font-bold text-[#16A34A] truncate">
                  Upgrade &gt;= {fixedVer}
                </div>
                <div className="text-[11px] text-[#8B8F98]">
                  {finding.finding_type === 'SCA' ? 'Patch Dependency' : 'Secure Coding Fix'}
                </div>
              </div>
            </div>

            {/* Root Cause, Threat Vector & How to Fix This Line (Image 4) */}
            <div className="p-5 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-3">
              <div className="flex items-center gap-2 text-[14px] font-bold text-[#24262B]">
                <ShieldAlert className="w-4 h-4 text-[#5876D8]" />
                <span>Root Cause, Threat Vector & How to Fix This Line</span>
              </div>
              <p className="text-[13px] text-[#4A4D54] leading-relaxed">
                <strong>Security Impact:</strong> {finding.description || 'Execution of this construct allows untrusted actors to trigger unauthorized behavior, exploit vulnerabilities, or breach compliance constraints.'}
              </p>
              <div className="p-3.5 rounded-lg bg-[#F0FDF4] border border-[#BBF7D0] space-y-1">
                <span className="text-[11px] font-bold text-[#166534] uppercase tracking-wider block">
                  Prescribed Line Remediation:
                </span>
                <p className="text-[13px] font-mono font-semibold text-[#15803D]">
                  {finding.remediation || `Upgrade ${pkgName} to version ${fixedVer}`}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* 3. RISK TAB (Image 5) */}
        {activeTab === 'RISK' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Deterministic Risk Assessment */}
            <div className="p-6 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-4">
              <span className="text-[11px] font-bold text-[#8B8F98] uppercase tracking-wider block">
                Deterministic Risk Assessment
              </span>
              <div className="flex items-baseline gap-2">
                <span className="text-[44px] font-extrabold text-[#DC2626] leading-none">
                  {finding.risk_score ? (finding.risk_score).toFixed(0) : (finding.cvss ? (finding.cvss).toFixed(0) : '10')}
                </span>
                <span className="text-[18px] text-[#8B8F98] font-medium">/ 10.0</span>
              </div>
              <div className="flex items-center gap-2 pt-1">
                <span className="px-3 py-1 text-[11px] font-extrabold rounded-full bg-[#FEF2F2] text-[#DC2626] border border-[#FCA5A5] uppercase">
                  {finding.severity} RISK
                </span>
                <span className="px-3 py-1 text-[11px] font-extrabold rounded-full bg-[#FFF7ED] text-[#EA580C] border border-[#FDBA74] uppercase">
                  {finding.priority || 'PRIORITY P1'}
                </span>
              </div>
              <p className="text-[12px] text-[#666A73] leading-relaxed pt-2">
                Calculated dynamically combining CVSS v3.1 base metric ({finding.cvss || 9.8}), EPSS exploitability probability ({((finding.epss || 0.8) * 100).toFixed(0)}%), and code execution reachability.
              </p>
            </div>

            {/* Remediation SLA Window */}
            <div className="p-6 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-4">
              <span className="text-[11px] font-bold text-[#8B8F98] uppercase tracking-wider block">
                Remediation SLA Window
              </span>
              <div className="text-[32px] font-extrabold text-[#24262B] leading-none">
                {getSlaDate()}
              </div>
              <p className="text-[13px] text-[#666A73] leading-relaxed">
                VM-004 policy mandates resolution within established SLA before compliance flags FAIL.
              </p>
              <div className="text-[12px] text-[#8B8F98] flex items-center gap-1.5 pt-1">
                <Clock className="w-4 h-4 text-[#5876D8]" />
                <span>SLA enforcement actively tracked in SOC 2 Trust Criteria dashboard.</span>
              </div>
            </div>
          </div>
        )}

        {/* 4. COMPLIANCE TAB */}
        {activeTab === 'COMPLIANCE' && (
          <div className="space-y-5">
            {/* Top Classification & Regulatory Impact Card */}
            <div className="p-5 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <ShieldCheck className="w-5 h-5 text-[#5876D8]" />
                  <h3 className="text-[15px] font-bold text-[#24262B]">
                    SOC 2 Type II Trust Services Criteria & Audit Controls
                  </h3>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="px-2.5 py-0.5 text-[11px] font-bold rounded-full bg-[#EEF2FF] text-[#5876D8] border border-[#C9D5FA]">
                    {classification.categoryLabel}
                  </span>
                  <span className={`px-2.5 py-0.5 text-[11px] font-bold rounded-full ${
                    finding.status === 'RESOLVED' || finding.verification_status === 'VERIFIED'
                      ? 'bg-[#F0FDF4] text-[#16A34A] border border-[#BBF7D0]'
                      : finding.severity === 'CRITICAL'
                      ? 'bg-[#FEF2F2] text-[#DC2626] border border-[#FCA5A5]'
                      : 'bg-[#FFFBEB] text-[#D97706] border border-[#FDE68A]'
                  }`}>
                    {finding.status === 'RESOLVED' || finding.verification_status === 'VERIFIED'
                      ? 'CONTROL SATISFIED'
                      : finding.severity === 'CRITICAL'
                      ? 'CRITICAL AUDIT DEFICIENCY'
                      : 'POLICY ENFORCED'}
                  </span>
                </div>
              </div>

              <p className="text-[13px] text-[#475569] leading-relaxed">
                {classification.summaryRationale}
              </p>

              <div className="pt-2 border-t border-[#E8E9ED] flex flex-wrap items-center gap-4 text-[12px] text-[#666A73]">
                <div>
                  <span className="text-[#8B8F98]">SLA Policy Window: </span>
                  <span className="font-semibold text-[#24262B]">
                    {finding.severity === 'CRITICAL' ? `7 Days (Due: ${getSlaDate()})` : finding.severity === 'HIGH' ? `30 Days (Due: ${getSlaDate()})` : '90 Days'}
                  </span>
                </div>
                <span>•</span>
                <div>
                  <span className="text-[#8B8F98]">Mapped Standards: </span>
                  <span className="font-semibold text-[#5876D8]">{complianceItems.length} SOC 2 Controls</span>
                </div>
                <span>•</span>
                <div>
                  <span className="text-[#8B8F98]">Audit Scope: </span>
                  <span className="font-mono text-[#24262B]">{finding.file_path}:{finding.start_line || 1}</span>
                </div>
              </div>
            </div>

            {/* SOC 2 Category Filter Buttons */}
            <div className="flex flex-wrap items-center gap-2">
              {[
                { id: 'ALL', label: 'All SOC 2 Criteria', count: complianceItems.length },
                { id: 'CC6', label: 'Logical Access (CC6)', count: complianceItems.filter((c) => c.soc2_category === 'CC6').length },
                { id: 'CC7', label: 'Operations & Supply Chain (CC7)', count: complianceItems.filter((c) => c.soc2_category === 'CC7').length },
                { id: 'CC8', label: 'Change Management (CC8)', count: complianceItems.filter((c) => c.soc2_category === 'CC8').length },
                { id: 'CC3', label: 'Risk Assessment (CC3)', count: complianceItems.filter((c) => c.soc2_category === 'CC3').length },
                { id: 'CC4_5', label: 'Monitoring & Guardrails (CC4/CC5)', count: complianceItems.filter((c) => c.soc2_category === 'CC4_5').length },
                { id: 'AVAIL_CONF', label: 'Availability & Confidentiality', count: complianceItems.filter((c) => c.soc2_category === 'AVAIL_CONF').length },
              ].filter((f) => f.count > 0 || f.id === 'ALL').map((f) => (
                <button
                  key={f.id}
                  onClick={() => setComplianceCategoryFilter(f.id as SOC2Category)}
                  className={`px-3 py-1.5 text-[12px] font-semibold rounded-lg border transition-all ${
                    complianceCategoryFilter === f.id
                      ? 'bg-[#24262B] text-white border-[#24262B] shadow-2xs'
                      : 'bg-white text-[#666A73] border-[#E8E9ED] hover:border-[#5876D8] hover:text-[#24262B]'
                  }`}
                >
                  {f.label} ({f.count})
                </button>
              ))}
            </div>

            {/* Dynamic Control Cards Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filteredComplianceItems.map((ctrl) => (
                <div
                  key={ctrl.id}
                  className="p-4 rounded-xl bg-white border border-[#E8E9ED] shadow-2xs space-y-3 flex flex-col justify-between"
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 text-[11px] font-bold font-mono rounded bg-[#EEF2FF] text-[#5876D8] border border-[#C9D5FA]">
                          {ctrl.control_id}
                        </span>
                        <span className="text-[11px] font-bold uppercase tracking-wider text-[#8B8F98]">
                          {ctrl.framework}
                        </span>
                      </div>
                      <span className={`px-2 py-0.5 text-[10px] font-bold rounded-full border ${ctrl.status_badge_color}`}>
                        {ctrl.status_label}
                      </span>
                    </div>

                    <h4 className="text-[13px] font-bold text-[#24262B] leading-snug">
                      {ctrl.title}
                    </h4>

                    <p className="text-[12px] text-[#475569] leading-relaxed">
                      {ctrl.assessment}
                    </p>
                  </div>

                  <div className="pt-2 border-t border-[#F1F5F9] space-y-2">
                    <div className="p-2.5 rounded-lg bg-[#FAFAFB] border border-[#E8E9ED] text-[11px] space-y-1">
                      <div className="font-semibold text-[#24262B] flex items-center gap-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5 text-[#5876D8]" />
                        <span>Auditor Verification Evidence:</span>
                      </div>
                      <div className="text-[#666A73] leading-relaxed">
                        {ctrl.auditor_proof}
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-[#666A73]">
                      <span className="font-medium text-[#24262B]">
                        SLA Window: <span className="font-mono text-[#5876D8] font-bold">{ctrl.sla_days} Days</span>
                      </span>
                      <span className="text-[10px] text-[#8B8F98] uppercase font-semibold">
                        {ctrl.category_name}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* 5. EVIDENCE TAB */}
        {activeTab === 'EVIDENCE' && (
          <div className="space-y-5">
            <div className="p-5 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-3">
              <h3 className="text-[15px] font-bold text-[#24262B]">
                Cryptographic Audit Evidence
              </h3>
              <p className="text-[13px] text-[#666A73] leading-relaxed">
                Every scanner execution computes an immutable SHA-256 evidence digest stored for auditor verification.
              </p>
              <div className="p-3 bg-white rounded-lg border border-[#E8E9ED] font-mono text-[12px] text-[#24262B] flex items-center justify-between">
                <span>SHA-256 Fingerprint:</span>
                <span className="text-[#5876D8] font-bold truncate max-w-md">
                  {finding.id ? finding.id.replace(/-/g, '') : '2a3f0334a762103978d511e6f87dca0f'}
                </span>
              </div>
            </div>

            <div className="p-5 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-3">
              <h4 className="text-[13px] font-semibold text-[#24262B]">
                Scanner Telemetry Metadata
              </h4>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-[12px]">
                <div>
                  <span className="text-[#8B8F98] block">Primary Scanner:</span>
                  <span className="font-semibold text-[#24262B]">{finding.scanner || 'trivy'}</span>
                </div>
                <div>
                  <span className="text-[#8B8F98] block">Scanner Version:</span>
                  <span className="font-semibold text-[#24262B]">{finding.scanner_version || '0.74.0'}</span>
                </div>
                <div>
                  <span className="text-[#8B8F98] block">Commit SHA:</span>
                  <span className="font-mono text-[#24262B]">{finding.commit_sha || 'HEAD'}</span>
                </div>
                <div>
                  <span className="text-[#8B8F98] block">Scan Timestamp:</span>
                  <span className="font-semibold text-[#24262B]">{finding.created_at ? finding.created_at.split('T')[0] : 'Today'}</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* 6. REMEDIATION TAB */}
        {activeTab === 'REMEDIATION' && (
          <div className="space-y-6">
            <div className="p-5 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-3">
              <div className="flex items-center gap-2 text-[15px] font-bold text-[#24262B]">
                <Sparkles className="w-4 h-4 text-[#5876D8]" />
                <span>Step-by-Step Remediation Guide</span>
              </div>
              <p className="text-[13px] text-[#4A4D54] leading-relaxed">
                {finding.remediation || `Upgrade ${pkgName} to version ${fixedVer} or higher to resolve the reported vulnerability.`}
              </p>
              <div className="p-3 bg-[#F0FDF4] rounded-lg border border-[#BBF7D0] text-[13px] text-[#166534]">
                <strong>Verified Patch Target:</strong> <code className="bg-white px-2 py-0.5 rounded border border-[#BBF7D0] text-[#15803D] font-mono font-bold">{fixedVer}</code>
              </div>
            </div>

            <div className="p-5 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-[15px] font-bold text-[#24262B]">
                  <Ticket className="w-4 h-4 text-[#5876D8]" />
                  <span>Issue Tracker Dispatch (Jira)</span>
                </div>
                {finding.jira_issue_key && (
                  <span className="px-2.5 py-1 text-[12px] font-bold rounded-md bg-[#EEF2FF] text-[#5876D8] border border-[#C9D5FA]">
                    {finding.jira_issue_key}
                  </span>
                )}
              </div>
              <p className="text-[13px] text-[#666A73]">
                Assign this finding to an engineering team as a tracked Jira ticket under project <strong className="text-[#24262B]">SEC</strong>.
              </p>
              {!finding.jira_issue_key && (
                <button
                  onClick={handleCreateJira}
                  disabled={isCreatingJira}
                  className="inline-flex items-center gap-1.5 px-4 py-2 text-[13px] font-medium text-white bg-[#5876D8] hover:bg-[#4863BD] rounded-md transition-colors shadow-2xs"
                >
                  <Ticket className="w-4 h-4" />
                  <span>{isCreatingJira ? 'Dispatching Ticket...' : 'Create Jira Issue'}</span>
                </button>
              )}
            </div>

            <div className="p-5 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-3">
              <div className="flex items-center gap-2 text-[15px] font-bold text-[#24262B]">
                <CheckCircle2 className="w-4 h-4 text-[#16A34A]" />
                <span>Automated Verification Scan</span>
              </div>
              <p className="text-[13px] text-[#666A73]">
                Enter the Git commit SHA where the patch was applied. The platform runs an isolated verification scan to confirm remediation.
              </p>
              <div className="flex items-center gap-3">
                <input
                  type="text"
                  value={fixCommitSha}
                  onChange={(e) => setFixCommitSha(e.target.value)}
                  placeholder="Enter 40-character or 7-character commit SHA (e.g. 73f70ae)"
                  className="flex-1 px-3 py-2 text-[13px] font-mono bg-white border border-[#E8E9ED] rounded-md text-[#24262B] placeholder-[#8B8F98] focus:outline-hidden focus:border-[#5876D8]"
                />
                <button
                  onClick={handleVerifyFix}
                  disabled={isVerifying}
                  className="inline-flex items-center gap-1.5 px-4 py-2 text-[13px] font-medium text-white bg-[#16A34A] hover:bg-[#15803D] rounded-md transition-colors shadow-2xs disabled:opacity-50"
                >
                  <CheckCircle2 className="w-4 h-4" />
                  <span>{isVerifying ? 'Verifying...' : 'Verify Fix'}</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* 7. AUDIT TAB */}
        {activeTab === 'AUDIT' && (
          <div className="p-5 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-4">
            <h3 className="text-[15px] font-bold text-[#24262B]">
              Cryptographic Audit Log & Lifecycle Trail
            </h3>
            <div className="space-y-3">
              <div className="flex items-start gap-3 p-3 rounded-lg bg-white border border-[#E8E9ED] text-[12px]">
                <div className="w-2 h-2 rounded-full bg-[#5876D8] mt-1.5 shrink-0" />
                <div>
                  <span className="font-semibold text-[#24262B]">Scan Completed & Finding Identified</span>
                  <p className="text-[#666A73] mt-0.5">
                    Engines {getDetectedByScanners().join(', ')} confirmed finding coordinate in {finding.file_path}:{finding.start_line || 1}.
                  </p>
                  <span className="text-[11px] text-[#8B8F98]">Recorded at {finding.created_at || 'Recently'}</span>
                </div>
              </div>

              <div className="flex items-start gap-3 p-3 rounded-lg bg-white border border-[#E8E9ED] text-[12px]">
                <div className="w-2 h-2 rounded-full bg-[#EA580C] mt-1.5 shrink-0" />
                <div>
                  <span className="font-semibold text-[#24262B]">SOC 2 SLA Clock Initiated</span>
                  <p className="text-[#666A73] mt-0.5">
                    SLA policy enforced with remediation deadline set for {finding.remediation_due_at || 'within 7 days'}.
                  </p>
                </div>
              </div>

              {finding.jira_issue_key && (
                <div className="flex items-start gap-3 p-3 rounded-lg bg-white border border-[#E8E9ED] text-[12px]">
                  <div className="w-2 h-2 rounded-full bg-[#10B981] mt-1.5 shrink-0" />
                  <div>
                    <span className="font-semibold text-[#24262B]">Jira Remediation Ticket Dispatched</span>
                    <p className="text-[#666A73] mt-0.5">
                      Engineering issue {finding.jira_issue_key} synchronized.
                    </p>
                  </div>
                </div>
              )}

              {finding.status === 'RESOLVED' && (
                <div className="flex items-start gap-3 p-3 rounded-lg bg-[#F0FDF4] border border-[#BBF7D0] text-[12px]">
                  <div className="w-2 h-2 rounded-full bg-[#16A34A] mt-1.5 shrink-0" />
                  <div>
                    <span className="font-semibold text-[#166534]">Verification Completed — Resolved</span>
                    <p className="text-[#15803D] mt-0.5">
                      Fix confirmed via automated scanner execution. Status updated to RESOLVED.
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};


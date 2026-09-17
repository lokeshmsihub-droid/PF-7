import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';

interface FindingData {
  id: string;
  rule_id: string;
  title: string;
  description: string;
  severity: string;
  confidence: string;
  file_path: string;
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
  cwe: string[];
  owasp_category: string[];
  status: string;
  risk_score: number;
  risk_level: string;
  priority: string;
  remediation?: string;
  remediation_due_at?: string;
  verification_status: string;
  jira_issue_key?: string;
  pr_url?: string;
  repository_name: string;
  branch: string;
  commit_sha: string;
  scanner: string;
  scanner_version: string;
  fingerprint: string;
  scan_id?: string;
  code_snippet?: string;

  // Universal extensions
  finding_type?: string;
  package_name?: string;
  package_version?: string;
  fixed_version?: string;
  ghsa?: string;
  osv_id?: string;
  cvss?: number;
  epss?: number;
  detected_by_scanners?: string[];
  correlated_finding_ids?: string[];
}

interface ComplianceEval {
  control_id: string;
  result: string;
  reason: string;
}

export const FindingDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [finding, setFinding] = useState<FindingData | null>(null);
  const [complianceEvals, setComplianceEvals] = useState<ComplianceEval[]>([]);
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [fixCommit, setFixCommit] = useState<string>('');

  const loadData = () => {
    fetch(`/security/findings/${id}`, { headers: { 'X-Tenant-ID': '1' } })
      .then((r) => r.json())
      .then((d) => setFinding(d))
      .catch(() => {});

    fetch(`/security/findings/${id}/compliance`, { headers: { 'X-Tenant-ID': '1' } })
      .then((r) => r.json())
      .then((ev) => setComplianceEvals(ev))
      .catch(() => {});
  };

  useEffect(() => {
    loadData();
  }, [id]);

  const handleCreateJira = async () => {
    if (!finding) return;
    setIsProcessing(true);
    try {
      const res = await fetch(`/security/findings/${finding.id}/remediation`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Tenant-ID': '1' },
        body: JSON.stringify({ project_key: 'SEC', summary: finding.title })
      });
      await res.json();
      loadData();
      alert('Jira remediation ticket created successfully!');
    } catch (e) {
      alert('Error creating Jira issue');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleVerifyScan = async () => {
    if (!finding || !fixCommit) {
      alert('Please enter the fix commit SHA to verify.');
      return;
    }
    setIsProcessing(true);
    try {
      const res = await fetch(`/security/findings/${finding.id}/verification`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Tenant-ID': '1' },
        body: JSON.stringify({ fix_commit_sha: fixCommit })
      });
      const data = await res.json();
      loadData();
      alert(`Verification Scan Completed: Status is now ${data.verification_status}`);
    } catch (e) {
      alert('Error running verification scan');
    } finally {
      setIsProcessing(false);
    }
  };

  if (!finding) return <div className="p-8 text-center text-gray-500 font-medium">Loading finding details...</div>;

  const isSCA = (finding.finding_type || '').toUpperCase() === 'SCA';
  const detectedScanners = finding.detected_by_scanners && finding.detected_by_scanners.length > 0 
    ? finding.detected_by_scanners 
    : [finding.scanner || 'semgrep'];

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-6">
      {/* Finding Banner */}
      <div className="bg-white dark:bg-gray-800 p-6 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-sm flex flex-col md:flex-row justify-between items-start gap-4">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <span className={`px-2.5 py-1 rounded text-xs font-black ${
              finding.severity === 'CRITICAL' ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300' :
              finding.severity === 'HIGH' ? 'bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300' : 'bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-300'
            }`}>
              {finding.severity}
            </span>
            <span className="text-xs px-2.5 py-1 bg-indigo-50 dark:bg-indigo-950 text-indigo-700 dark:text-indigo-300 rounded font-bold uppercase">
              {finding.finding_type || 'SAST'}
            </span>
            <span className="text-xs px-2.5 py-1 bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded font-semibold">
              Priority: {finding.priority}
            </span>
            <span className={`text-xs px-2.5 py-1 rounded font-semibold ${
              finding.status === 'RESOLVED' ? 'bg-emerald-100 text-emerald-800' : 'bg-blue-100 text-blue-800'
            }`}>
              Status: {finding.status}
            </span>
          </div>

          <h1 className="text-2xl font-black text-gray-900 dark:text-white mt-3 tracking-tight">{finding.title}</h1>
          <div className="text-xs text-gray-500 mt-1 font-mono flex flex-wrap items-center gap-2">
            <span>{finding.file_path}:{finding.start_line}</span>
            <span>&bull;</span>
            <span>Rule: {finding.rule_id}</span>
          </div>

          <div className="mt-3 flex items-center gap-2">
            <span className="text-xs text-gray-500 font-medium">Detected by:</span>
            {detectedScanners.map((sc) => (
              <span key={sc} className="px-2 py-0.5 bg-indigo-100 dark:bg-indigo-900/60 text-indigo-800 dark:text-indigo-300 rounded text-xs font-bold uppercase font-mono">
                ✓ {sc}
              </span>
            ))}
          </div>
        </div>

        <div className="text-left md:text-right shrink-0">
          <div className="text-xs text-gray-400 font-semibold uppercase tracking-wider">Enterprise Risk Score</div>
          <div className="text-3xl font-black text-indigo-600 mt-0.5">{finding.risk_score} / 10.0</div>
          <div className="text-[11px] text-gray-400 mt-1 font-mono">Fingerprint: {finding.fingerprint.substring(0, 12)}...</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="flex space-x-6 overflow-x-auto text-sm">
          {[
            { id: 'overview', label: 'Overview' },
            { id: 'code', label: isSCA ? 'Dependency Details' : 'Code Occurrence' },
            { id: 'risk', label: 'Risk & SLA' },
            { id: 'compliance', label: `Compliance (${complianceEvals.length})` },
            { id: 'remediation', label: 'Remediation & Jira' },
            { id: 'audit', label: 'Audit & Trace' }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`py-3 px-1 border-b-2 font-bold transition whitespace-nowrap ${
                activeTab === tab.id
                  ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400'
                  : 'border-transparent text-gray-500 hover:text-gray-800 dark:hover:text-gray-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Contents */}
      <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-sm p-6">
        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <div className="space-y-5">
            <div>
              <h3 className="font-bold text-gray-900 dark:text-white text-base">Vulnerability Description</h3>
              <p className="text-gray-700 dark:text-gray-300 text-sm leading-relaxed mt-2">{finding.description}</p>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-4 border-t border-gray-100 dark:border-gray-700 text-xs">
              <div>
                <span className="font-semibold text-gray-400 block">CWE</span>
                <span className="font-mono text-gray-900 dark:text-gray-200">{finding.cwe.join(', ') || 'N/A'}</span>
              </div>
              <div>
                <span className="font-semibold text-gray-400 block">OWASP Top 10</span>
                <span className="font-mono text-gray-900 dark:text-gray-200">{finding.owasp_category.join(', ') || 'N/A'}</span>
              </div>
              <div>
                <span className="font-semibold text-gray-400 block">Repository / Branch</span>
                <span className="font-mono text-gray-900 dark:text-gray-200">{finding.repository_name} ({finding.branch})</span>
              </div>
              <div>
                <span className="font-semibold text-gray-400 block">Exact Commit SHA</span>
                <code className="font-mono text-gray-900 dark:text-gray-200">{finding.commit_sha}</code>
              </div>
            </div>

            {/* Cross-Scanner Correlation Info */}
            <div className="p-4 bg-indigo-50/50 dark:bg-indigo-950/20 border border-indigo-100 dark:border-indigo-900/40 rounded-xl space-y-1">
              <span className="font-bold text-xs uppercase text-indigo-900 dark:text-indigo-300 tracking-wide block">
                Multi-Scanner Provenance & Correlation
              </span>
              <p className="text-xs text-gray-600 dark:text-gray-300">
                This vulnerability was independently validated and correlated across {detectedScanners.length} security engines: <strong>{detectedScanners.join(', ').toUpperCase()}</strong>.
              </p>
            </div>
          </div>
        )}

        {/* Code / Dependency Occurrence Tab */}
        {activeTab === 'code' && (
          <div className="space-y-4">
            {isSCA ? (
              <div className="space-y-4 text-xs">
                <h3 className="font-bold text-gray-900 dark:text-white text-sm">Vulnerable Third-Party Component</h3>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  <div className="p-3 bg-gray-50 dark:bg-gray-700/50 rounded-xl border">
                    <span className="text-gray-400 block">Package Name</span>
                    <span className="font-bold font-mono text-sm text-gray-900 dark:text-white">{finding.package_name || 'N/A'}</span>
                  </div>
                  <div className="p-3 bg-gray-50 dark:bg-gray-700/50 rounded-xl border">
                    <span className="text-gray-400 block">Installed Version</span>
                    <span className="font-bold font-mono text-sm text-rose-600">{finding.package_version || 'N/A'}</span>
                  </div>
                  <div className="p-3 bg-gray-50 dark:bg-gray-700/50 rounded-xl border">
                    <span className="text-gray-400 block">Fixed Version</span>
                    <span className="font-bold font-mono text-sm text-emerald-600">{finding.fixed_version || 'Advisory fix pending'}</span>
                  </div>
                  <div className="p-3 bg-gray-50 dark:bg-gray-700/50 rounded-xl border">
                    <span className="text-gray-400 block">CVSS v3 Score</span>
                    <span className="font-bold font-mono text-sm text-indigo-600">{finding.cvss || '—'}</span>
                  </div>
                </div>

                <div className="p-4 bg-gray-900 text-gray-100 rounded-xl font-mono">
                  <span className="text-gray-500 block mb-1">// Target Manifest: {finding.file_path}</span>
                  <div className="text-rose-400 font-semibold">&gt; {finding.package_name} == {finding.package_version}</div>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <h3 className="font-bold text-gray-900 dark:text-white">Source Code Snippet</h3>
                <div className="bg-gray-900 text-gray-100 p-4 rounded-xl font-mono text-xs overflow-x-auto">
                  <div className="text-gray-500 mb-2">// File: {finding.file_path} (Lines {finding.start_line} - {finding.end_line})</div>
                  {finding.code_snippet ? (
                    <pre className="text-emerald-400 leading-relaxed">{finding.code_snippet}</pre>
                  ) : (
                    <div className="text-red-400 font-semibold">&gt; Line {finding.start_line}: [Identified defect in AST pattern match]</div>
                  )}
                </div>
              </div>
            )}

            {/* Detection Reason & Trigger Mechanism */}
            <div className="p-4 bg-rose-50/40 dark:bg-rose-950/20 border border-rose-200 dark:border-rose-900/40 rounded-xl space-y-2">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wide bg-rose-100 dark:bg-rose-900/60 text-rose-700 dark:text-rose-300 px-2 py-0.5 rounded">
                  Detection Reason
                </span>
                <span className="font-bold text-sm text-gray-900 dark:text-white">
                  Why Was Line {finding.start_line || 1} Flagged?
                </span>
              </div>
              <p className="text-xs text-gray-700 dark:text-gray-300 leading-relaxed">
                {isSCA ? (
                  <>
                    Line <strong>{finding.start_line || 1}</strong> in <code>{finding.file_path}</code> declares third-party component{' '}
                    <strong><code>{finding.package_name}</code></strong> at version <strong><code>{finding.package_version}</code></strong>.{' '}
                    The security scanner matched this package against the vulnerability database advisory{' '}
                    <strong><code>{finding.rule_id}</code></strong> because the declared version falls within the confirmed vulnerable range.
                    {finding.fixed_version && (
                      <> A verified security fix is available in version <strong><code>{finding.fixed_version}</code></strong>.</>
                    )}
                  </>
                ) : (
                  <>
                    Line <strong>{finding.start_line || 1}</strong> in <code>{finding.file_path}</code> was detected by AST pattern matching and taint dataflow analysis.{' '}
                    Rule <strong><code>{finding.rule_id}</code></strong> triggered because untrusted input or an unsafe execution pattern reaches a critical sink without validation or parameterization.
                  </>
                )}
              </p>
            </div>
          </div>
        )}

        {/* Risk & SLA Tab */}
        {activeTab === 'risk' && (
          <div className="space-y-4">
            <h3 className="font-bold text-gray-900 dark:text-white">Multidimensional Risk Evaluation</h3>
            <div className="grid grid-cols-3 gap-4 text-center">
              <div className="p-4 bg-gray-50 dark:bg-gray-700/50 rounded-xl border">
                <span className="text-xs text-gray-400 block font-semibold">Risk Level</span>
                <p className="text-lg font-black text-gray-900 dark:text-white mt-1">{finding.risk_level}</p>
              </div>
              <div className="p-4 bg-gray-50 dark:bg-gray-700/50 rounded-xl border">
                <span className="text-xs text-gray-400 block font-semibold">Priority Tier</span>
                <p className="text-lg font-black text-indigo-600 mt-1">{finding.priority}</p>
              </div>
              <div className="p-4 bg-gray-50 dark:bg-gray-700/50 rounded-xl border">
                <span className="text-xs text-gray-400 block font-semibold">Remediation SLA</span>
                <p className="text-sm font-bold text-gray-900 dark:text-white mt-2">
                  {finding.remediation_due_at ? new Date(finding.remediation_due_at).toLocaleDateString() : 'Active SLA'}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Compliance Impact Tab */}
        {activeTab === 'compliance' && (
          <div className="space-y-4">
            <h3 className="font-bold text-gray-900 dark:text-white">Impacted Compliance Controls</h3>
            <p className="text-xs text-gray-500">Deterministic mapping to vulnerability management frameworks.</p>
            <div className="space-y-3 pt-2">
              {complianceEvals.map((ev, i) => (
                <div key={i} className="p-4 border rounded-xl flex justify-between items-center bg-gray-50 dark:bg-gray-900">
                  <div>
                    <span className="font-mono font-bold text-sm text-gray-900 dark:text-white">{ev.control_id}</span>
                    <p className="text-xs text-gray-500 mt-1">{ev.reason}</p>
                  </div>
                  <span className={`px-2.5 py-1 rounded text-xs font-bold ${
                    ev.result === 'PASS' ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'
                  }`}>
                    {ev.result}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Remediation & Jira Tab */}
        {activeTab === 'remediation' && (
          <div className="space-y-6">
            <div>
              <h3 className="font-bold text-gray-900 dark:text-white mb-2">Automated Remediation Advisory</h3>
              <p className="text-xs text-gray-700 dark:text-gray-300 bg-blue-50 dark:bg-blue-950/40 p-4 rounded-xl border border-blue-200 dark:border-blue-900 leading-relaxed font-mono">
                {finding.remediation || 'Upgrade vulnerable dependency or apply parameterized query sanitization.'}
              </p>
            </div>

            {/* Jira Action */}
            <div className="p-4 border rounded-xl flex justify-between items-center bg-gray-50 dark:bg-gray-900">
              <div>
                <h4 className="font-bold text-gray-900 dark:text-white text-sm">Jira Remediation Issue</h4>
                <p className="text-xs text-gray-500 mt-0.5">
                  {finding.jira_issue_key ? `Connected to ${finding.jira_issue_key}` : 'No ticket linked yet'}
                </p>
              </div>
              {finding.jira_issue_key ? (
                <span className="px-3 py-1 bg-indigo-100 text-indigo-800 font-mono text-xs font-bold rounded">
                  {finding.jira_issue_key}
                </span>
              ) : (
                <button
                  disabled={isProcessing}
                  onClick={handleCreateJira}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-bold text-xs rounded-xl shadow transition"
                >
                  {isProcessing ? 'Creating...' : 'Create Jira Ticket'}
                </button>
              )}
            </div>

            {/* Verification Scan */}
            <div className="p-4 border rounded-xl space-y-3 bg-gray-50 dark:bg-gray-900">
              <div>
                <h4 className="font-bold text-gray-900 dark:text-white text-sm">Verification Scan</h4>
                <p className="text-xs text-gray-500 mt-0.5">Verify that the fix commit resolved this finding.</p>
              </div>
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="Enter fix commit SHA"
                  value={fixCommit}
                  onChange={(e) => setFixCommit(e.target.value)}
                  className="flex-1 border rounded-xl px-3 py-1.5 text-xs font-mono bg-white dark:bg-gray-800"
                />
                <button
                  disabled={isProcessing}
                  onClick={handleVerifyScan}
                  className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs rounded-xl shadow transition"
                >
                  {isProcessing ? 'Verifying...' : 'Verify Fix'}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Audit & Trace Tab */}
        {activeTab === 'audit' && (
          <div className="space-y-4 text-xs font-mono">
            <h3 className="font-bold text-gray-900 dark:text-white text-sm font-sans">Provenance & Audit Trail</h3>
            <div className="bg-gray-50 dark:bg-gray-900 p-4 rounded-xl border space-y-2">
              <div><span className="text-gray-400">Deterministic Fingerprint:</span> {finding.fingerprint}</div>
              <div><span className="text-gray-400">Scan Job ID:</span> {finding.scan_id}</div>
              <div><span className="text-gray-400">Verification Status:</span> {finding.verification_status}</div>
              <div><span className="text-gray-400">Engines:</span> {detectedScanners.join(', ').toUpperCase()}</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default FindingDetailPage;

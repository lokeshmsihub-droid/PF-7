import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';

interface ScanJobData {
  id: string;
  repository_name: string;
  branch: string;
  commit_sha: string;
  status: string;
  scan_type: string;
  scanners: string[];
  scanner_versions: Record<string, string>;
  files_scanned: number;
  rules_executed: number;
  finding_count: number;
  raw_result_hash?: string;
  error_message?: string;
  created_at: string;
  completed_at?: string;
}

interface ScannerExecutionItem {
  id: string;
  scanner: string;
  scanner_version?: string;
  scanner_type: string;
  status: string;
  execution_duration_seconds: number;
  rules_loaded: number;
  rules_executed: number;
  rules_skipped: number;
  finding_count: number;
  exit_code: number;
  error_message?: string;
  started_at?: string;
  completed_at?: string;
}

interface FindingItem {
  id: string;
  title: string;
  severity: string;
  finding_type?: string;
  file_path: string;
  start_line: number;
  rule_id: string;
  risk_score: number;
  package_name?: string;
  package_version?: string;
  fixed_version?: string;
  ghsa?: string;
  cvss?: number;
  detected_by_scanners?: string[];
}

interface RuleResultItem {
  id: string;
  scanner: string;
  ruleset_id?: string;
  rules_loaded: number;
  rules_executed: number;
  rules_skipped: number;
  applicable_languages: string[];
  validation_status: string;
  rule_details?: any[];
}

interface RepoProfileItem {
  languages: string[];
  frameworks: string[];
  package_managers: string[];
  source_targets: string[];
  dependency_targets: string[];
  iac_targets: string[];
  manifests: string[];
  files_discovered: number;
  files_scannable: number;
  coverage_percentage: number;
}

interface ComplianceItem {
  id: string;
  control_id: string;
  result: string;
  reason: string;
  input_evidence: any;
}

export const ScanProgressPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<ScanJobData | null>(null);
  const [scanners, setScanners] = useState<ScannerExecutionItem[]>([]);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [rules, setRules] = useState<RuleResultItem[]>([]);
  const [profile, setProfile] = useState<RepoProfileItem | null>(null);
  const [compliance, setCompliance] = useState<ComplianceItem[]>([]);
  const [activeTab, setActiveTab] = useState<'findings' | 'dependencies' | 'scanners' | 'rules' | 'profile' | 'compliance' | 'evidence'>('findings');
  const [lastPolledAt, setLastPolledAt] = useState<string>('');
  const [selectedRawScanner, setSelectedRawScanner] = useState<string | null>(null);
  const [rawArtifactJson, setRawArtifactJson] = useState<string | null>(null);

  useEffect(() => {
    const fetchStatus = () => {
      fetch(`/api/v1/scans/${id}`, { headers: { 'X-Tenant-ID': '1' } })
        .then((r) => r.json())
        .then((data: ScanJobData) => {
          setScan(data);
          setLastPolledAt(new Date().toLocaleTimeString());

          // Fetch scanners telemetry
          fetch(`/api/v1/scans/${id}/scanners`, { headers: { 'X-Tenant-ID': '1' } })
            .then((res) => res.json())
            .then((sData) => setScanners(sData))
            .catch(() => {});

          if (data.status === 'COMPLETED' || data.status === 'FAILED') {
            // Fetch findings
            fetch(`/api/v1/scans/${id}/findings`, { headers: { 'X-Tenant-ID': '1' } })
              .then((fr) => fr.json())
              .then((fData) => setFindings(fData))
              .catch(() => {});

            // Fetch rules
            fetch(`/api/v1/scans/${id}/rules`, { headers: { 'X-Tenant-ID': '1' } })
              .then((rr) => rr.json())
              .then((rData) => setRules(rData))
              .catch(() => {});

            // Fetch profile
            fetch(`/api/v1/scans/${id}/profile`, { headers: { 'X-Tenant-ID': '1' } })
              .then((pr) => pr.json())
              .then((pData) => setProfile(pData))
              .catch(() => {});

            // Fetch compliance
            fetch(`/api/v1/scans/${id}/compliance`, { headers: { 'X-Tenant-ID': '1' } })
              .then((cr) => cr.json())
              .then((cData) => setCompliance(cData))
              .catch(() => {});
          }
        })
        .catch((err) => console.error('Error fetching scan status:', err));
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 2000);
    return () => clearInterval(interval);
  }, [id]);

  const handleViewRaw = async (scannerName: string) => {
    setSelectedRawScanner(scannerName);
    setRawArtifactJson('Loading raw artifact from MongoDB collection raw_scan_results...');
    try {
      const res = await fetch(`/api/v1/scans/${id}/raw?scanner=${scannerName}`, {
        headers: { 'X-Tenant-ID': '1' }
      });
      const data = await res.json();
      setRawArtifactJson(data.raw_result || JSON.stringify(data, null, 2));
    } catch (err: any) {
      setRawArtifactJson(`Could not load raw artifact: ${err.message}`);
    }
  };

  if (!scan) {
    return <div className="p-8 text-center text-gray-500 font-medium">Connecting to scan telemetry pipeline...</div>;
  }

  const isCompleted = scan.status === 'COMPLETED';
  const isFailed = scan.status === 'FAILED';
  const isRunning = scan.status === 'RUNNING';
  const isQueued = scan.status === 'QUEUED';

  const statusColor =
    isCompleted ? 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300' :
    isFailed ? 'bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-950 dark:text-rose-300' :
    isRunning ? 'bg-blue-100 text-blue-800 border-blue-300 animate-pulse dark:bg-blue-950 dark:text-blue-300' :
    'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950 dark:text-amber-300';

  const sastFindings = findings.filter((f) => (f.finding_type || 'SAST').toUpperCase() !== 'SCA');
  const scaFindings = findings.filter((f) => (f.finding_type || '').toUpperCase() === 'SCA');

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header Banner */}
      <div className="bg-white dark:bg-gray-800 p-6 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-md">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-black text-gray-900 dark:text-white tracking-tight">Security Scan Telemetry</h1>
              <span className={`px-3.5 py-1 rounded-full text-xs font-bold border tracking-wide uppercase ${statusColor}`}>
                {scan.status}
              </span>
            </div>
            <p className="text-xs text-gray-500 mt-1.5 flex items-center gap-2">
              <span>Scan ID:</span>
              <code className="bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded font-mono text-gray-800 dark:text-gray-200">{scan.id}</code>
              <span>&bull;</span>
              <span>Updated: {lastPolledAt || 'Live'}</span>
            </p>
          </div>

          <div className="flex items-center gap-3">
            <Link
              to="/repositories"
              className="px-4 py-2 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 text-gray-800 dark:text-gray-200 text-xs font-bold rounded-xl transition"
            >
              &larr; Repositories
            </Link>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-6 pt-5 border-t border-gray-100 dark:border-gray-700 text-xs">
          <div>
            <span className="text-gray-400 block font-medium">Repository</span>
            <span className="font-bold text-gray-900 dark:text-white truncate block">{scan.repository_name}</span>
          </div>
          <div>
            <span className="text-gray-400 block font-medium">Branch & Exact SHA</span>
            <span className="font-mono text-gray-900 dark:text-white font-bold">
              {scan.branch} ({scan.commit_sha ? scan.commit_sha.substring(0, 8) : 'HEAD'})
            </span>
          </div>
          <div>
            <span className="text-gray-400 block font-medium">Scan Scope</span>
            <span className="font-bold text-indigo-600 dark:text-indigo-400 uppercase">{scan.scan_type} Multi-Engine</span>
          </div>
          <div>
            <span className="text-gray-400 block font-medium">Execution Engine Matrix</span>
            <span className="font-mono text-gray-800 dark:text-gray-200 font-bold">
              {scan.scanners && scan.scanners.length > 0 ? scan.scanners.join(', ').toUpperCase() : 'SEMGREP, CODEQL, TRIVY, OSV'}
            </span>
          </div>
        </div>
      </div>

      {/* Multi-Engine Execution Grid */}
      <div className="space-y-3">
        <h2 className="text-base font-bold text-gray-900 dark:text-white tracking-wide uppercase flex items-center gap-2">
          <span>Engine Execution Matrix</span>
          <span className="text-xs bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 px-2 py-0.5 rounded font-mono">
            {scanners.length} Engines Evaluated
          </span>
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {scanners.map((sc) => {
            const scColor =
              sc.status === 'COMPLETED' ? 'border-emerald-500/50 bg-emerald-50/40 dark:bg-emerald-950/20 text-emerald-700 dark:text-emerald-300' :
              sc.status === 'NOT_APPLICABLE' ? 'border-slate-300 bg-slate-50 dark:bg-slate-800/40 text-slate-600 dark:text-slate-400' :
              sc.status === 'RUNNING' ? 'border-blue-500/50 bg-blue-50/40 dark:bg-blue-950/20 text-blue-700 dark:text-blue-300 animate-pulse' :
              'border-rose-500/50 bg-rose-50/40 dark:bg-rose-950/20 text-rose-700 dark:text-rose-300';

            return (
              <div key={sc.id || sc.scanner} className={`p-4 rounded-2xl border ${scColor} flex flex-col justify-between shadow-sm`}>
                <div>
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-black uppercase text-sm">{sc.scanner}</span>
                    <span className="text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-full border bg-white/70 dark:bg-gray-800">
                      {sc.status}
                    </span>
                  </div>
                  <div className="text-[11px] text-gray-500 font-mono mt-0.5">
                    {sc.scanner_type} &bull; v{sc.scanner_version || 'auto'}
                  </div>

                  <div className="mt-3 space-y-1 text-xs text-gray-700 dark:text-gray-300">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Duration:</span>
                      <span className="font-mono font-semibold">{sc.execution_duration_seconds?.toFixed(2)}s</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Rules Executed:</span>
                      <span className="font-mono font-semibold">{sc.rules_executed}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Findings:</span>
                      <span className="font-mono font-bold text-indigo-600 dark:text-indigo-400">{sc.finding_count}</span>
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-gray-200/60 dark:border-gray-700 flex justify-end">
                  <button
                    onClick={() => handleViewRaw(sc.scanner)}
                    className="text-[11px] font-bold text-indigo-600 dark:text-indigo-400 hover:underline flex items-center gap-1"
                  >
                    Raw SARIF/JSON &rarr;
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Overview Stat Counters */}
      {isCompleted && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-gray-800 p-5 rounded-2xl border shadow-sm text-center">
            <span className="text-xs font-semibold uppercase text-gray-400">Files Scanned</span>
            <p className="text-3xl font-black text-indigo-600 mt-1">{scan.files_scanned}</p>
          </div>
          <div className="bg-white dark:bg-gray-800 p-5 rounded-2xl border shadow-sm text-center">
            <span className="text-xs font-semibold uppercase text-gray-400">Rules Evaluated</span>
            <p className="text-3xl font-black text-indigo-600 mt-1">{scan.rules_executed}</p>
          </div>
          <div className="bg-white dark:bg-gray-800 p-5 rounded-2xl border shadow-sm text-center">
            <span className="text-xs font-semibold uppercase text-gray-400">Code Issues (SAST)</span>
            <p className="text-3xl font-black text-amber-600 mt-1">{sastFindings.length}</p>
          </div>
          <div className="bg-white dark:bg-gray-800 p-5 rounded-2xl border shadow-sm text-center">
            <span className="text-xs font-semibold uppercase text-gray-400">Dependency CVEs (SCA)</span>
            <p className="text-3xl font-black text-rose-600 mt-1">{scaFindings.length}</p>
          </div>
        </div>
      )}

      {/* Tabs Navigation */}
      <div className="border-b border-gray-200 dark:border-gray-700 flex space-x-2 overflow-x-auto text-sm">
        {[
          { id: 'findings', label: `Code Findings (${sastFindings.length})` },
          { id: 'dependencies', label: `Dependencies (${scaFindings.length})` },
          { id: 'scanners', label: `Engines (${scanners.length})` },
          { id: 'rules', label: `Rules & Coverage (${rules.length})` },
          { id: 'profile', label: 'Repository Profile' },
          { id: 'compliance', label: `Compliance (${compliance.length})` },
          { id: 'evidence', label: 'Evidence & Audit' }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`pb-3 px-3 font-semibold border-b-2 transition whitespace-nowrap ${
              activeTab === tab.id
                ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400'
                : 'border-transparent text-gray-500 hover:text-gray-800 dark:hover:text-gray-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-sm p-6">
        {/* Tab 1: Code Findings (SAST & IaC) */}
        {activeTab === 'findings' && (
          <div>
            <div className="flex justify-between items-center mb-4">
              <h3 className="font-bold text-gray-900 dark:text-white">Static Code & Infrastructure Findings</h3>
              <span className="text-xs text-gray-400">Cross-engine correlated with line-shift resilient fingerprints</span>
            </div>

            {sastFindings.length === 0 ? (
              <div className="py-12 text-center text-emerald-600 font-semibold">
                ✓ No static code vulnerabilities or misconfigurations detected.
              </div>
            ) : (
              <div className="divide-y divide-gray-100 dark:divide-gray-700">
                {sastFindings.map((f) => (
                  <div key={f.id} className="py-4 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 hover:bg-gray-50 dark:hover:bg-gray-700/40 p-3 rounded-xl transition">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className={`px-2.5 py-0.5 rounded text-xs font-bold ${
                          f.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                          f.severity === 'HIGH' ? 'bg-orange-100 text-orange-800' : 'bg-yellow-100 text-yellow-800'
                        }`}>
                          {f.severity}
                        </span>
                        <Link to={`/findings/${f.id}`} className="font-bold text-gray-900 dark:text-white hover:underline text-sm">
                          {f.title}
                        </Link>
                      </div>
                      <div className="text-xs text-gray-500 mt-1.5 flex items-center gap-2">
                        <code className="bg-gray-100 dark:bg-gray-700 px-1.5 py-0.5 rounded font-mono">{f.file_path}:{f.start_line}</code>
                        <span>&bull;</span>
                        <span>Rule: {f.rule_id}</span>
                        <span>&bull;</span>
                        <span className="text-indigo-600 dark:text-indigo-400 font-medium">
                          Detected by: {(f.detected_by_scanners || ['semgrep']).join(', ').toUpperCase()}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-4 shrink-0">
                      <span className="text-xs font-semibold text-gray-600 dark:text-gray-300">
                        Risk: <span className="font-bold text-gray-900 dark:text-white">{f.risk_score}</span>
                      </span>
                      <Link
                        to={`/findings/${f.id}`}
                        className="px-3 py-1.5 bg-indigo-50 dark:bg-indigo-950/60 hover:bg-indigo-100 dark:hover:bg-indigo-900 text-indigo-700 dark:text-indigo-300 text-xs font-bold rounded-lg transition"
                      >
                        Investigate &rarr;
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Dependencies (SCA) */}
        {activeTab === 'dependencies' && (
          <div>
            <div className="flex justify-between items-center mb-4">
              <h3 className="font-bold text-gray-900 dark:text-white">Third-Party Dependency Vulnerabilities (SCA)</h3>
              <span className="text-xs text-gray-400">Scanned by Trivy & OSV-Scanner</span>
            </div>

            {scaFindings.length === 0 ? (
              <div className="py-12 text-center text-emerald-600 font-semibold">
                ✓ No vulnerable dependencies discovered in lockfiles or manifests.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-gray-50 dark:bg-gray-700 text-gray-500 uppercase font-semibold">
                    <tr>
                      <th className="p-3">Package</th>
                      <th className="p-3">Installed</th>
                      <th className="p-3">Fixed In</th>
                      <th className="p-3">Severity</th>
                      <th className="p-3">Advisory ID</th>
                      <th className="p-3">CVSS</th>
                      <th className="p-3">Detected By</th>
                      <th className="p-3">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                    {scaFindings.map((f) => (
                      <tr key={f.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/40">
                        <td className="p-3 font-bold font-mono text-gray-900 dark:text-white">{f.package_name || f.title}</td>
                        <td className="p-3 font-mono text-gray-600 dark:text-gray-300">{f.package_version || 'unknown'}</td>
                        <td className="p-3 font-mono text-emerald-600 font-semibold">{f.fixed_version || 'Not available'}</td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                            f.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' : 'bg-orange-100 text-orange-800'
                          }`}>
                            {f.severity}
                          </span>
                        </td>
                        <td className="p-3 font-mono text-indigo-600 dark:text-indigo-400">{f.ghsa || f.rule_id}</td>
                        <td className="p-3 font-mono font-bold">{f.cvss || '—'}</td>
                        <td className="p-3">
                          <span className="bg-slate-100 dark:bg-slate-700 px-2 py-0.5 rounded text-[10px] font-bold uppercase">
                            {(f.detected_by_scanners || ['trivy']).join(', ')}
                          </span>
                        </td>
                        <td className="p-3">
                          <Link to={`/findings/${f.id}`} className="text-indigo-600 font-bold hover:underline">
                            Details &rarr;
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Tab 3: Engines Telemetry */}
        {activeTab === 'scanners' && (
          <div className="space-y-4">
            <h3 className="font-bold text-gray-900 dark:text-white">Engine Execution Logs & Runtimes</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-gray-50 dark:bg-gray-700 text-gray-500 uppercase font-semibold">
                  <tr>
                    <th className="p-3">Scanner</th>
                    <th className="p-3">Type</th>
                    <th className="p-3">Version</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Duration</th>
                    <th className="p-3">Rules Run</th>
                    <th className="p-3">Findings</th>
                    <th className="p-3">Raw Output</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                  {scanners.map((sc) => (
                    <tr key={sc.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/40">
                      <td className="p-3 font-bold uppercase font-mono">{sc.scanner}</td>
                      <td className="p-3 text-gray-500">{sc.scanner_type}</td>
                      <td className="p-3 font-mono">{sc.scanner_version || 'auto'}</td>
                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-gray-100 dark:bg-gray-700">
                          {sc.status}
                        </span>
                      </td>
                      <td className="p-3 font-mono">{sc.execution_duration_seconds?.toFixed(2)}s</td>
                      <td className="p-3 font-mono">{sc.rules_executed}</td>
                      <td className="p-3 font-mono font-bold text-indigo-600">{sc.finding_count}</td>
                      <td className="p-3">
                        <button
                          onClick={() => handleViewRaw(sc.scanner)}
                          className="px-2.5 py-1 bg-indigo-50 dark:bg-indigo-950 text-indigo-600 dark:text-indigo-400 font-bold rounded hover:bg-indigo-100 text-[11px]"
                        >
                          View Raw
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 4: Rules & Coverage */}
        {activeTab === 'rules' && (
          <div className="space-y-4">
            <h3 className="font-bold text-gray-900 dark:text-white">Rule Validation & Language Coverage</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {rules.map((r) => (
                <div key={r.id} className="border p-4 rounded-xl space-y-2 bg-gray-50 dark:bg-gray-900">
                  <div className="flex justify-between items-center">
                    <span className="font-bold uppercase font-mono text-sm">{r.scanner} Ruleset</span>
                    <span className="text-[10px] px-2 py-0.5 rounded font-bold uppercase bg-emerald-100 text-emerald-800">
                      {r.validation_status}
                    </span>
                  </div>
                  <div className="text-xs text-gray-500">Ruleset ID: <code className="font-mono">{r.ruleset_id}</code></div>
                  <div className="grid grid-cols-3 gap-2 text-center text-xs pt-2">
                    <div className="bg-white dark:bg-gray-800 p-2 rounded border">
                      <span className="text-gray-400 block text-[10px]">LOADED</span>
                      <span className="font-bold">{r.rules_loaded}</span>
                    </div>
                    <div className="bg-white dark:bg-gray-800 p-2 rounded border">
                      <span className="text-gray-400 block text-[10px]">EXECUTED</span>
                      <span className="font-bold text-emerald-600">{r.rules_executed}</span>
                    </div>
                    <div className="bg-white dark:bg-gray-800 p-2 rounded border">
                      <span className="text-gray-400 block text-[10px]">SKIPPED</span>
                      <span className="font-bold text-gray-500">{r.rules_skipped}</span>
                    </div>
                  </div>
                  <div className="text-[11px] text-gray-500 pt-1">
                    Languages: {r.applicable_languages?.join(', ') || 'General'}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab 5: Repository Profile */}
        {activeTab === 'profile' && profile && (
          <div className="space-y-4 text-xs">
            <h3 className="font-bold text-gray-900 dark:text-white text-sm">Discovered Repository Profile</h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="border p-3 rounded-xl bg-gray-50 dark:bg-gray-900">
                <span className="text-gray-400 block">Languages</span>
                <span className="font-bold text-gray-800 dark:text-gray-200">{profile.languages?.join(', ') || 'None'}</span>
              </div>
              <div className="border p-3 rounded-xl bg-gray-50 dark:bg-gray-900">
                <span className="text-gray-400 block">Package Managers</span>
                <span className="font-bold text-gray-800 dark:text-gray-200">{profile.package_managers?.join(', ') || 'None'}</span>
              </div>
              <div className="border p-3 rounded-xl bg-gray-50 dark:bg-gray-900">
                <span className="text-gray-400 block">Files Discovered</span>
                <span className="font-bold text-gray-800 dark:text-gray-200">{profile.files_discovered}</span>
              </div>
              <div className="border p-3 rounded-xl bg-gray-50 dark:bg-gray-900">
                <span className="text-gray-400 block">Coverage</span>
                <span className="font-bold text-emerald-600">{profile.coverage_percentage}%</span>
              </div>
            </div>

            <div className="pt-2">
              <span className="font-semibold block mb-1">Manifests & Lockfiles:</span>
              <div className="flex flex-wrap gap-1.5">
                {profile.manifests?.length > 0 ? (
                  profile.manifests.map((m) => (
                    <code key={m} className="bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded text-[11px] font-mono">{m}</code>
                  ))
                ) : (
                  <span className="text-gray-400">No manifests found</span>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Tab 6: Compliance Controls */}
        {activeTab === 'compliance' && (
          <div className="space-y-4">
            <h3 className="font-bold text-gray-900 dark:text-white">Automated Compliance Control Evaluations</h3>
            <div className="space-y-3">
              {compliance.map((c) => (
                <div key={c.id || c.control_id} className="p-4 border rounded-xl flex justify-between items-start">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold font-mono text-sm">{c.control_id}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        c.result === 'PASS' ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'
                      }`}>
                        {c.result}
                      </span>
                    </div>
                    <p className="text-xs text-gray-600 dark:text-gray-300 mt-1">{c.reason}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab 7: Evidence & Audit */}
        {activeTab === 'evidence' && (
          <div className="space-y-4 text-xs">
            <h3 className="font-bold text-gray-900 dark:text-white text-sm">Cryptographic Scan Evidence</h3>
            <div className="space-y-2 font-mono bg-gray-50 dark:bg-gray-900 p-4 rounded-xl border">
              <div><span className="text-gray-400">SHA-256 Result Hash:</span> {scan.raw_result_hash}</div>
              <div><span className="text-gray-400">Commit SHA:</span> {scan.commit_sha}</div>
              <div><span className="text-gray-400">Scan Job UUID:</span> {scan.id}</div>
              <div><span className="text-gray-400">Timestamp:</span> {scan.completed_at || scan.created_at}</div>
            </div>
          </div>
        )}
      </div>

      {/* Raw Output Modal */}
      {selectedRawScanner && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white dark:bg-gray-800 rounded-2xl max-w-4xl w-full p-6 space-y-4 shadow-2xl max-h-[85vh] flex flex-col">
            <div className="flex justify-between items-center border-b pb-3">
              <h3 className="font-bold text-gray-900 dark:text-white uppercase font-mono">
                Raw Artifact: {selectedRawScanner}
              </h3>
              <button
                onClick={() => setSelectedRawScanner(null)}
                className="text-gray-400 hover:text-gray-600 text-lg font-bold"
              >
                &times;
              </button>
            </div>
            <div className="flex-1 overflow-auto bg-gray-900 text-emerald-400 p-4 rounded-xl font-mono text-xs">
              <pre>{rawArtifactJson}</pre>
            </div>
            <div className="flex justify-end pt-2 border-t">
              <button
                onClick={() => setSelectedRawScanner(null)}
                className="px-4 py-1.5 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 font-bold rounded-lg text-xs"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanProgressPage;

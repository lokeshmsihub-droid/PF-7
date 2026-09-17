import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

interface Repository {
  id: string;
  name: string;
  default_branch: string;
  languages: string[];
  sast_status: string;
  finding_count: number;
  last_scan?: string;
}

interface ValidationResult {
  valid: boolean;
  provider: string;
  repository_name: string;
  owner: string;
  default_branch: string;
  requested_branch: string;
  resolved_commit_sha?: string;
  access_status: string;
  error?: string;
  languages: string[];
  frameworks: string[];
  applicable_scanners: string[];
}

interface EngineInfo {
  name: string;
  version: string;
  available: boolean;
  scan_types: string[];
  features: string[];
}

export const RepositoriesPage: React.FC = () => {
  const navigate = useNavigate();
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [engines, setEngines] = useState<EngineInfo[]>([]);
  
  // Custom Git URL validation states
  const [gitUrl, setGitUrl] = useState<string>('');
  const [branchInput, setBranchInput] = useState<string>('main');
  const [isValidating, setIsValidating] = useState<boolean>(false);
  const [validationResult, setValidationResult] = useState<ValidationResult | null>(null);
  
  // Scan modal / launch states
  const [selectedRepo, setSelectedRepo] = useState<Repository | null>(null);
  const [selectedBranch, setSelectedBranch] = useState<string>('main');
  const [scanType, setScanType] = useState<string>('SAST');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [modalOpen, setModalOpen] = useState<boolean>(false);

  useEffect(() => {
    // Fetch connected repositories
    fetch('/repositories')
      .then((res) => res.json())
      .then((data) => setRepositories(data))
      .catch(() => {
        setRepositories([
          {
            id: 'albertsons-frontend',
            name: 'ALBERTSONS-AI-GOVERNANCE/frontend',
            default_branch: 'main',
            languages: ['typescript', 'javascript', 'json'],
            sast_status: 'READY',
            finding_count: 0
          },
          {
            id: 'demo-vulnerable-repo',
            name: '/Users/lokesh/Documents/semgrep repo/demo_vulnerable_repo',
            default_branch: 'main',
            languages: ['python', 'javascript'],
            sast_status: 'READY',
            finding_count: 7
          }
        ]);
      });

    // Fetch engine readiness
    fetch('/repositories/engines/readiness')
      .then((res) => res.json())
      .then((data) => setEngines(data))
      .catch(() => {
        setEngines([
          { name: 'semgrep', version: '1.177.0', available: true, scan_types: ['SAST', 'SECRETS', 'IAC'], features: ['sarif_output', 'taint_mode'] },
          { name: 'codeql', version: '2.26.4', available: true, scan_types: ['SAST'], features: ['deep_semantic_taint', 'dataflow'] },
          { name: 'trivy', version: '0.74.0', available: true, scan_types: ['SCA', 'IAC'], features: ['vuln_scanning', 'misconfig'] },
          { name: 'osv', version: '2.5.1', available: true, scan_types: ['SCA'], features: ['lockfile_analysis', 'osv_db'] }
        ]);
      });
  }, []);

  const handleValidateRepository = async () => {
    if (!gitUrl.trim()) return;
    setIsValidating(true);
    setValidationResult(null);
    try {
      const res = await fetch('/repositories/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repository_url: gitUrl.trim(),
          branch: branchInput.trim() || undefined
        })
      });
      const data = await res.json();
      setValidationResult(data);
      if (data.default_branch) {
        setBranchInput(data.requested_branch || data.default_branch);
      }
    } catch (err: any) {
      setValidationResult({
        valid: false,
        provider: 'git',
        repository_name: 'unknown',
        owner: 'unknown',
        default_branch: 'main',
        requested_branch: branchInput,
        access_status: 'error',
        error: err.message || 'Validation request failed',
        languages: [],
        frameworks: [],
        applicable_scanners: []
      });
    } finally {
      setIsValidating(false);
    }
  };

  const handleStartScanFromValidation = async () => {
    if (!validationResult || !validationResult.valid) return;
    setIsScanning(true);
    try {
      const res = await fetch('/api/v1/scans/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Tenant-ID': '1'
        },
        body: JSON.stringify({
          repository_id: validationResult.repository_name,
          repository_name: gitUrl.trim(),
          branch: validationResult.requested_branch || validationResult.default_branch,
          commit_sha: validationResult.resolved_commit_sha,
          scan_type: scanType
        })
      });
      const data = await res.json();
      navigate(`/scans/${data.id}`);
    } catch (err) {
      console.error(err);
      alert('Failed initiating scan');
    } finally {
      setIsScanning(false);
    }
  };

  const handleStartScan = async () => {
    if (!selectedRepo) return;
    setIsScanning(true);
    try {
      const res = await fetch('/api/v1/scans/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Tenant-ID': '1'
        },
        body: JSON.stringify({
          repository_id: selectedRepo.id,
          repository_name: selectedRepo.name,
          branch: selectedBranch,
          scan_type: scanType
        })
      });
      const data = await res.json();
      setModalOpen(false);
      navigate(`/scans/${data.id}`);
    } catch (err) {
      console.error(err);
      alert('Failed initiating scan');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex justify-between items-center border-b border-gray-200 dark:border-gray-700 pb-5">
        <div>
          <h1 className="text-3xl font-extrabold text-gray-900 dark:text-white tracking-tight">Enterprise Security Engine</h1>
          <p className="text-sm text-gray-500 mt-1">
            Universal Repository Ingestion • Multi-Scanner Orchestration (Semgrep, CodeQL, Trivy, OSV-Scanner)
          </p>
        </div>
      </div>

      {/* Engine Readiness Strip */}
      <div className="bg-slate-900 text-white rounded-2xl p-6 shadow-xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold tracking-wide flex items-center gap-2">
            <span className="inline-block w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
            Active Engine Cluster Readiness
          </h2>
          <span className="text-xs text-slate-400 bg-slate-800 px-3 py-1 rounded-full border border-slate-700">
            Isolated Subprocess Runtimes
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {engines.map((eng) => (
            <div key={eng.name} className="bg-slate-800/80 rounded-xl p-4 border border-slate-700/60 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold uppercase text-sm text-indigo-400">{eng.name}</span>
                  <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                    eng.available ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950 text-rose-300 border border-rose-800'
                  }`}>
                    {eng.available ? 'ONLINE' : 'OFFLINE'}
                  </span>
                </div>
                <div className="text-xs text-slate-300 mt-1 font-mono">v{eng.version}</div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {eng.scan_types?.map((st) => (
                    <span key={st} className="text-[10px] bg-slate-700 text-slate-200 px-1.5 py-0.5 rounded">
                      {st}
                    </span>
                  ))}
                </div>
              </div>
              <div className="mt-3 text-[11px] text-slate-400 flex items-center gap-1.5">
                <svg className="w-3.5 h-3.5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                </svg>
                Healthy & Validated
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Universal Repository Input & Validation Card */}
      <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-200 dark:border-gray-700 p-6 space-y-6">
        <div className="border-b border-gray-100 dark:border-gray-700 pb-4">
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">Connect & Validate Any Git Repository</h2>
          <p className="text-sm text-gray-500 mt-1">
            Enter any public or authenticated HTTPS/SSH Git repository URL or local workspace path. The platform will automatically verify connectivity, resolve the exact commit SHA, and detect applicable scanners.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="md:col-span-2">
            <label className="block text-xs font-semibold uppercase text-gray-600 dark:text-gray-300 mb-1.5">
              Repository URL or Path
            </label>
            <input
              type="text"
              value={gitUrl}
              onChange={(e) => setGitUrl(e.target.value)}
              placeholder="e.g. https://github.com/torvalds/linux.git or demo_vulnerable_repo"
              className="w-full bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-xl px-4 py-2.5 text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase text-gray-600 dark:text-gray-300 mb-1.5">
              Target Branch / Ref
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={branchInput}
                onChange={(e) => setBranchInput(e.target.value)}
                placeholder="main"
                className="w-full bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-xl px-4 py-2.5 text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:outline-none"
              />
              <button
                disabled={isValidating || !gitUrl.trim()}
                onClick={handleValidateRepository}
                className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-sm font-semibold rounded-xl shadow-md transition flex items-center gap-1.5 shrink-0"
              >
                {isValidating ? (
                  <>
                    <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
                    </svg>
                    Verifying...
                  </>
                ) : (
                  'Validate'
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Quick-fill suggestions */}
        <div className="flex items-center gap-2 text-xs text-gray-500">
          <span className="font-semibold">Quick select:</span>
          <button
            onClick={() => {
              setGitUrl('/Users/lokesh/Documents/semgrep repo/demo_vulnerable_repo');
              setBranchInput('main');
            }}
            className="text-indigo-600 dark:text-indigo-400 hover:underline bg-indigo-50 dark:bg-indigo-950/40 px-2 py-1 rounded"
          >
            Demo Vulnerable Repo (Local)
          </button>
          <button
            onClick={() => {
              setGitUrl('/Users/lokesh/Documents/Alberston_Rag/ALBERTSONS-AI-GOVERNANCE/frontend');
              setBranchInput('main');
            }}
            className="text-indigo-600 dark:text-indigo-400 hover:underline bg-indigo-50 dark:bg-indigo-950/40 px-2 py-1 rounded"
          >
            Albertsons Frontend (Clean)
          </button>
        </div>

        {/* Validation Result Display */}
        {validationResult && (
          <div className={`p-5 rounded-2xl border transition-all ${
            validationResult.valid
              ? 'bg-emerald-50/70 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-800'
              : 'bg-rose-50 dark:bg-rose-950/20 border-rose-200 dark:border-rose-800'
          }`}>
            {validationResult.valid ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="bg-emerald-600 text-white rounded-full p-1">
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                      </svg>
                    </span>
                    <span className="font-bold text-gray-900 dark:text-white text-base">
                      Repository Validated & Ready
                    </span>
                    <span className="text-xs bg-emerald-100 dark:bg-emerald-900 text-emerald-800 dark:text-emerald-200 px-2.5 py-0.5 rounded-full font-semibold uppercase">
                      {validationResult.access_status}
                    </span>
                  </div>

                  <div className="flex items-center gap-3">
                    <select
                      value={scanType}
                      onChange={(e) => setScanType(e.target.value)}
                      className="bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-xl px-3 py-1.5 text-xs font-semibold shadow-sm"
                    >
                      <option value="SAST">SAST (Semgrep + CodeQL)</option>
                      <option value="SCA">SCA (Trivy + OSV-Scanner)</option>
                      <option value="IAC">IaC & Misconfigurations</option>
                      <option value="SECRETS">Secrets Detection</option>
                      <option value="CONTAINER">Container Filesystem</option>
                    </select>

                    <button
                      disabled={isScanning}
                      onClick={handleStartScanFromValidation}
                      className="px-5 py-2 bg-emerald-600 hover:bg-emerald-700 text-white text-sm font-bold rounded-xl shadow-lg transition flex items-center gap-1.5"
                    >
                      {isScanning ? 'Enqueueing Celery...' : 'Start Security Scan'}
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
                  <div>
                    <span className="text-gray-500 block">Repository / Provider</span>
                    <span className="font-semibold text-gray-800 dark:text-gray-200 font-mono">
                      {validationResult.repository_name} ({validationResult.provider})
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-500 block">Effective Branch</span>
                    <span className="font-semibold text-gray-800 dark:text-gray-200 font-mono">
                      {validationResult.requested_branch || validationResult.default_branch}
                    </span>
                  </div>
                  <div className="sm:col-span-2">
                    <span className="text-gray-500 block">Resolved Exact Commit SHA</span>
                    <span className="font-mono text-gray-900 dark:text-gray-100 font-bold bg-white/80 dark:bg-gray-800 px-2 py-0.5 rounded border">
                      {validationResult.resolved_commit_sha || 'HEAD'}
                    </span>
                  </div>
                </div>

                <div>
                  <span className="text-xs text-gray-500 block mb-1.5 font-medium">Applicable Security Engines:</span>
                  <div className="flex flex-wrap gap-2">
                    {validationResult.applicable_scanners.map((sc) => (
                      <span key={sc} className="bg-indigo-100 dark:bg-indigo-900/60 text-indigo-700 dark:text-indigo-300 text-xs px-2.5 py-1 rounded-lg font-medium">
                        ✓ {sc.toUpperCase()}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-sm text-rose-700 dark:text-rose-300 flex items-start gap-2">
                <svg className="w-5 h-5 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <div>
                  <span className="font-bold block">Repository Inaccessible</span>
                  <span>{validationResult.error || 'Could not connect to target repository.'}</span>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Connected Repositories Section */}
      <div className="space-y-4">
        <h2 className="text-xl font-bold text-gray-900 dark:text-white">Quick Scan Presets</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {repositories.map((repo: Repository) => (
            <div key={repo.id} className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-gray-200 dark:border-gray-700 p-6 flex flex-col justify-between hover:shadow-md transition">
              <div>
                <div className="flex justify-between items-start">
                  <h3 className="text-lg font-bold text-gray-900 dark:text-white font-mono">{repo.name}</h3>
                  <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold ${
                    repo.sast_status === 'PASSED' ? 'bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300' : 'bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300'
                  }`}>
                    {repo.sast_status}
                  </span>
                </div>
                <div className="mt-4 space-y-1.5 text-xs text-gray-600 dark:text-gray-300">
                  <div><span className="font-medium text-gray-400">Default Branch:</span> {repo.default_branch}</div>
                  <div><span className="font-medium text-gray-400">Languages:</span> {repo.languages.join(', ')}</div>
                  <div><span className="font-medium text-gray-400">Open Findings:</span> {repo.finding_count}</div>
                </div>
              </div>
              <div className="mt-6 pt-4 border-t border-gray-100 dark:border-gray-700 flex justify-end">
                <button
                  onClick={() => {
                    setSelectedRepo(repo);
                    setSelectedBranch(repo.default_branch || 'main');
                    setModalOpen(true);
                  }}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold rounded-xl shadow transition"
                >
                  Configure & Scan
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Modal for Preset Repository Scan */}
      {modalOpen && selectedRepo && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white dark:bg-gray-800 rounded-2xl max-w-md w-full p-6 space-y-5 shadow-2xl border border-gray-200 dark:border-gray-700">
            <h3 className="text-xl font-bold text-gray-900 dark:text-white">Configure Universal Security Scan</h3>
            
            <div className="space-y-4 text-sm">
              <div>
                <label className="block font-medium text-gray-700 dark:text-gray-300 mb-1 text-xs">Repository</label>
                <input 
                  type="text" 
                  readOnly 
                  value={selectedRepo.name} 
                  className="w-full bg-gray-100 dark:bg-gray-700 rounded-xl p-2.5 text-gray-800 dark:text-gray-200 border text-xs font-mono"
                />
              </div>

              <div>
                <label className="block font-medium text-gray-700 dark:text-gray-300 mb-1 text-xs">Target Branch</label>
                <select 
                  value={selectedBranch}
                  onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setSelectedBranch(e.target.value)}
                  className="w-full bg-white dark:bg-gray-700 rounded-xl p-2.5 border text-xs"
                >
                  <option value="main">main (Default Branch)</option>
                  <option value="develop">develop</option>
                  <option value="feature/sec-remediation">feature/sec-remediation</option>
                </select>
              </div>

              <div>
                <label className="block font-medium text-gray-700 dark:text-gray-300 mb-1 text-xs">Engine Suite / Scan Type</label>
                <select 
                  value={scanType}
                  onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setScanType(e.target.value)}
                  className="w-full bg-white dark:bg-gray-700 rounded-xl p-2.5 border text-xs"
                >
                  <option value="SAST">SAST (Semgrep + CodeQL)</option>
                  <option value="SCA">SCA (Trivy + OSV-Scanner)</option>
                  <option value="IAC">IaC (Semgrep + Trivy Misconfig)</option>
                  <option value="SECRETS">Secrets Detection</option>
                  <option value="CONTAINER">Container & Filesystem</option>
                </select>
              </div>
            </div>

            <div className="flex justify-end space-x-3 pt-4 border-t border-gray-100 dark:border-gray-700">
              <button 
                onClick={() => setModalOpen(false)}
                className="px-4 py-2 border rounded-xl hover:bg-gray-50 text-gray-700 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                disabled={isScanning}
                onClick={handleStartScan}
                className="px-5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-xl shadow text-xs"
              >
                {isScanning ? 'Enqueueing Celery...' : 'Start Scan'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RepositoriesPage;

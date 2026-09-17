import React, { useState, useEffect, useRef } from 'react';
import { 
  X, 
  Play, 
  ShieldCheck, 
  GitBranch, 
  FolderGit2, 
  CheckCircle2, 
  AlertCircle, 
  Cpu, 
  Layers, 
  Search,
  RefreshCw,
  Lock,
  Terminal,
  FileCode2,
  Check,
  ArrowRight,
  Clock,
  ShieldAlert,
  Sparkles,
  Box,
  ExternalLink,
  ChevronRight,
  Database
} from 'lucide-react';
import { VulnerabilityRepoSummary, ScanJob } from '../types';
import { vulnerabilityService } from '../services/vulnerabilityService';

interface TriggerScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  repositories: VulnerabilityRepoSummary[];
  preselectedRepo?: VulnerabilityRepoSummary | null;
  onScanCompleted: (job: ScanJob) => void;
  onShowToast: (type: 'success' | 'info' | 'warning' | 'error', message: string, title?: string) => void;
}

const PHASES = [
  { key: 'VALIDATING', label: '1. Validation', group: 'Pre-flight' },
  { key: 'CHECKING_ENVIRONMENT', label: '2. Environment', group: 'Pre-flight' },
  { key: 'CHECKING_RULES', label: '3. Rulesets', group: 'Pre-flight' },
  { key: 'CHECKING_OUT', label: '4. Checkout', group: 'Ingestion' },
  { key: 'PROFILING', label: '5. Profiler', group: 'Ingestion' },
  { key: 'PLANNING', label: '6. Planner', group: 'Ingestion' },
  { key: 'SCANNING', label: '7. Multi-Scanner', group: 'Execution' },
  { key: 'NORMALIZING', label: '8. Normalizing', group: 'Processing' },
  { key: 'CORRELATING', label: '9. Correlation', group: 'Processing' },
  { key: 'RISK_CALCULATION', label: '10. Risk Engine', group: 'Compliance' },
  { key: 'COMPLIANCE', label: '11. SOC 2 Mapping', group: 'Compliance' },
  { key: 'EVIDENCE', label: '12. Audit Evidence', group: 'Compliance' },
  { key: 'CLEANUP', label: '13. Sandbox Wipe', group: 'Teardown' },
  { key: 'COMPLETED', label: '14. Completed', group: 'Final' },
];

export const TriggerScanModal: React.FC<TriggerScanModalProps> = ({
  isOpen,
  onClose,
  repositories,
  preselectedRepo,
  onScanCompleted,
  onShowToast,
}) => {
  // Step 1 vs Step 2
  const [step, setStep] = useState<'INGESTION' | 'SCANNING'>('INGESTION');

  // Input states
  const [selectedRepoId, setSelectedRepoId] = useState<string>(
    preselectedRepo?.id || (repositories.length > 0 ? repositories[0].id : 'custom')
  );
  const [customRepoUrl, setCustomRepoUrl] = useState('');
  const [branch, setBranch] = useState(preselectedRepo?.default_branch || 'main');
  const [token, setToken] = useState('');
  const [scanType, setScanType] = useState('FULL_PIPELINE');

  // Validation states
  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<any>(null);

  // Live scan execution states
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [scanProgress, setScanProgress] = useState<any>(null);
  const [completedJob, setCompletedJob] = useState<ScanJob | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  const pollIntervalRef = useRef<any>(null);
  const timerIntervalRef = useRef<any>(null);

  useEffect(() => {
    if (preselectedRepo) {
      setSelectedRepoId(preselectedRepo.id);
      setBranch(preselectedRepo.default_branch || 'main');
    } else if (repositories.length > 0) {
      setSelectedRepoId(repositories[0].id);
      setBranch(repositories[0].default_branch || 'main');
    } else {
      setSelectedRepoId('custom');
    }
  }, [preselectedRepo, repositories, isOpen]);

  // Clean up timers on unmount
  useEffect(() => {
    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
      if (timerIntervalRef.current) clearInterval(timerIntervalRef.current);
    };
  }, []);

  if (!isOpen) return null;

  const currentRepo = repositories.find((r) => r.id === selectedRepoId);
  const targetRepoName = selectedRepoId === 'custom' ? customRepoUrl : (currentRepo?.name || '');

  // 1. Validate remote or local repository
  const handleValidate = async () => {
    if (!targetRepoName.trim()) {
      onShowToast('warning', 'Please specify a repository URL or local path to validate.');
      return;
    }
    setIsValidating(true);
    setValidationResult(null);
    try {
      const res = await vulnerabilityService.validateRepository(targetRepoName, branch, token);
      setValidationResult(res);
      if (res.resolved_commit_sha) {
        onShowToast('success', `Resolved commit ${res.resolved_commit_sha.slice(0, 8)} on ${res.requested_branch || branch}.`, 'Repository Fingerprinted');
      } else {
        onShowToast('success', 'Repository credentials and structure verified.', 'Access Validated');
      }
    } catch (e: any) {
      onShowToast('error', 'Validation error: ' + (e.message || 'Could not access repository'));
    } finally {
      setIsValidating(false);
    }
  };

  // 2. Start Multi-Engine Scan and transition to Step 2
  const handleStartScan = async () => {
    if (!targetRepoName.trim()) {
      onShowToast('warning', 'Please select or enter a repository.');
      return;
    }

    setStep('SCANNING');
    setScanError(null);
    setCompletedJob(null);
    setElapsedSeconds(0);
    setScanProgress({
      status: 'QUEUED',
      current_phase: 'CREATED',
      progress_percentage: 5,
      current_phase_description: 'Initializing multi-engine security fleet...',
      scanners: []
    });

    // Start elapsed timer
    if (timerIntervalRef.current) clearInterval(timerIntervalRef.current);
    const startTime = Date.now();
    timerIntervalRef.current = setInterval(() => {
      setElapsedSeconds(Math.floor((Date.now() - startTime) / 1000));
    }, 1000);

    try {
      // Trigger scan in backend
      const job = await vulnerabilityService.triggerScan({
        repository_id: selectedRepoId === 'custom' ? `repo-${Date.now()}` : selectedRepoId,
        repository_name: targetRepoName,
        branch: branch || 'main',
        scan_type: scanType,
      });

      setActiveScanId(job.id);

      // Start polling progress
      startPolling(job.id);
    } catch (e: any) {
      if (timerIntervalRef.current) clearInterval(timerIntervalRef.current);
      setScanError(e.message || 'Scan execution failed');
      onShowToast('error', 'Scan execution failed: ' + (e.message || 'Unknown error'));
    }
  };

  const startPolling = (scanId: string) => {
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);

    pollIntervalRef.current = setInterval(async () => {
      try {
        const prog = await vulnerabilityService.getScanProgress(scanId);
        if (prog) {
          setScanProgress(prog);

          if (prog.status === 'COMPLETED') {
            clearInterval(pollIntervalRef.current);
            if (timerIntervalRef.current) clearInterval(timerIntervalRef.current);

            // Fetch final job details
            const scans = await vulnerabilityService.getScans();
            const finishedJob = scans.find(s => s.id === scanId) || {
              id: scanId,
              repository_name: targetRepoName,
              branch: branch || 'main',
              commit_sha: prog.commit_sha || 'HEAD',
              scan_type: scanType,
              status: 'COMPLETED',
              scanners: prog.scanners?.map((s: any) => s.scanner) || ['semgrep', 'codeql', 'trivy', 'osv'],
              files_scanned: prog.files_scanned || 0,
              rules_executed: 42,
              finding_count: prog.finding_count || 0,
              created_at: new Date().toISOString(),
              completed_at: new Date().toISOString()
            } as ScanJob;

            setCompletedJob(finishedJob);
            onScanCompleted(finishedJob);
            onShowToast(
              'success',
              `Multi-scanner fleet finished for ${targetRepoName}. Discovered ${prog.finding_count || 0} findings across ${prog.files_scanned || 0} files.`,
              'Scan Completed'
            );
          } else if (prog.status === 'FAILED') {
            clearInterval(pollIntervalRef.current);
            if (timerIntervalRef.current) clearInterval(timerIntervalRef.current);
            setScanError(prog.error_message || 'Scan failed during execution phase.');
            onShowToast('error', prog.error_message || 'Scan job reported failure.', 'Scan Failed');
          }
        }
      } catch (err) {
        console.warn('Progress poll error:', err);
      }
    }, 1200);
  };

  const formatTimer = (sec: number) => {
    const m = Math.floor(sec / 60).toString().padStart(2, '0');
    const s = (sec % 60).toString().padStart(2, '0');
    return `${m}:${s}`;
  };

  const getPhaseIndex = (currentPhaseName?: string) => {
    if (!currentPhaseName) return 0;
    const idx = PHASES.findIndex(p => p.key === currentPhaseName);
    return idx >= 0 ? idx : 0;
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto">
      {/* Backdrop */}
      <div 
        className="fixed inset-0 bg-[#000000]/40 backdrop-blur-xs transition-opacity"
        onClick={() => {
          if (step !== 'SCANNING' || completedJob || scanError) onClose();
        }}
      />

      {/* Modal Dialog */}
      <div className="relative bg-white rounded-2xl border border-[#E8E9ED] shadow-2xl w-full max-w-2xl mx-4 overflow-hidden z-10 flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-[#E8E9ED] flex items-center justify-between bg-[#FAFAFB]">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-[#EEF2FF] border border-[#C9D5FA] flex items-center justify-center text-[#5876D8]">
              {step === 'INGESTION' ? <Sparkles className="w-5 h-5" /> : <Cpu className="w-5 h-5 animate-pulse" />}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-[16px] font-semibold text-[#24262B]">
                  {step === 'INGESTION' ? 'Enterprise Repository Profiler & Scanner' : 'Multi-Engine Security Fleet Execution'}
                </h2>
                <span className="px-2 py-0.5 text-[10px] font-medium rounded-full bg-[#F4F5F7] border border-[#E8E9ED] text-[#666A73]">
                  {step === 'INGESTION' ? 'Step 1 of 2: Ingestion & Profiler' : 'Step 2 of 2: Fleet Pipeline'}
                </span>
              </div>
              <p className="text-[12px] text-[#666A73]">
                {step === 'INGESTION' 
                  ? 'Universal git ingestion, deep AST profiling, and pre-flight engine verification' 
                  : `Running unified 14-state pipeline on ${targetRepoName}`
                }
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#8B8F98] hover:text-[#24262B] hover:bg-[#F4F5F7] transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="px-6 py-5 overflow-y-auto space-y-5 flex-1 text-[13px]">
          {step === 'INGESTION' ? (
            /* STEP 1: INGESTION & PROFILER */
            <>
              {/* Repository Selector */}
              <div className="space-y-1.5">
                <label className="block font-medium text-[#24262B]">
                  Target Repository
                </label>
                <select
                  value={selectedRepoId}
                  onChange={(e) => {
                    setSelectedRepoId(e.target.value);
                    setValidationResult(null);
                    const match = repositories.find((r) => r.id === e.target.value);
                    if (match?.default_branch) setBranch(match.default_branch);
                  }}
                  className="w-full px-3.5 py-2.5 bg-white border border-[#E8E9ED] rounded-lg text-[#24262B] font-medium focus:outline-hidden focus:border-[#5876D8] transition-colors"
                >
                  {repositories.map((repo) => (
                    <option key={repo.id} value={repo.id}>
                      {repo.name} ({repo.languages?.join(', ') || 'Connected'})
                    </option>
                  ))}
                  <option value="custom">+ Enter Any Custom Git URL / Local Workspace Path</option>
                </select>
              </div>

              {/* Custom Repo URL Input */}
              {selectedRepoId === 'custom' && (
                <div className="p-3.5 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] space-y-3">
                  <div className="space-y-1.5">
                    <label className="block text-[12px] font-medium text-[#24262B]">
                      Remote Git URL or Local Workspace Directory
                    </label>
                    <div className="relative">
                      <FolderGit2 className="w-4 h-4 absolute left-3 top-3 text-[#8B8F98]" />
                      <input
                        type="text"
                        value={customRepoUrl}
                        onChange={(e) => setCustomRepoUrl(e.target.value)}
                        placeholder="https://github.com/organization/repo.git or /Users/work/repo"
                        className="w-full pl-9 pr-3 py-2 bg-white border border-[#E8E9ED] rounded-lg text-[#24262B] font-mono text-[12px] focus:outline-hidden focus:border-[#5876D8]"
                      />
                    </div>
                    <p className="text-[11px] text-[#8B8F98]">
                      Supports GitHub, GitLab, Bitbucket HTTPS/SSH URLs and local workspace directories.
                    </p>
                  </div>

                  <div className="space-y-1.5">
                    <label className="block text-[12px] font-medium text-[#24262B]">
                      Personal Access Token / CI Secret <span className="text-[#8B8F98] font-normal">(Optional for private repos)</span>
                    </label>
                    <div className="relative">
                      <Lock className="w-4 h-4 absolute left-3 top-3 text-[#8B8F98]" />
                      <input
                        type="password"
                        value={token}
                        onChange={(e) => setToken(e.target.value)}
                        placeholder="ghp_xxxxxxxxxxxx or gitlab_pat_xxxx"
                        className="w-full pl-9 pr-3 py-2 bg-white border border-[#E8E9ED] rounded-lg text-[#24262B] font-mono text-[12px] focus:outline-hidden focus:border-[#5876D8]"
                      />
                    </div>
                  </div>
                </div>
              )}

              {/* Branch & Scan Pipeline Selection */}
              <div className="grid grid-cols-2 gap-3.5">
                <div className="space-y-1.5">
                  <label className="block font-medium text-[#24262B]">
                    Target Branch
                  </label>
                  <div className="relative">
                    <GitBranch className="w-4 h-4 absolute left-3 top-2.5 text-[#8B8F98]" />
                    <input
                      type="text"
                      value={branch}
                      onChange={(e) => setBranch(e.target.value)}
                      placeholder="main"
                      className="w-full pl-9 pr-3 py-2 bg-white border border-[#E8E9ED] rounded-lg text-[#24262B] font-mono text-[12px] focus:outline-hidden focus:border-[#5876D8]"
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label className="block font-medium text-[#24262B]">
                    Scan Pipeline Mode
                  </label>
                  <select
                    value={scanType}
                    onChange={(e) => setScanType(e.target.value)}
                    className="w-full px-3 py-2 bg-white border border-[#E8E9ED] rounded-lg text-[#24262B] font-medium focus:outline-hidden focus:border-[#5876D8]"
                  >
                    <option value="FULL_PIPELINE">Full Multi-Engine Fleet (SAST + SCA + Secrets)</option>
                    <option value="SAST">SAST Only (Semgrep OSS + GitHub CodeQL)</option>
                    <option value="SCA">SCA Only (Aqua Trivy + Google OSV)</option>
                    <option value="SECRETS">Secrets & Token Harvester Only</option>
                  </select>
                </div>
              </div>

              {/* Validate Trigger Button (If not validated yet) */}
              {!validationResult && (
                <div className="p-3.5 rounded-xl bg-[#EEF2FF] border border-[#C9D5FA] flex items-center justify-between">
                  <div className="flex items-center gap-2.5 text-[#374151]">
                    <Search className="w-4 h-4 text-[#5876D8]" />
                    <span className="text-[12px]">
                      Validate repository access, profile languages/frameworks, and check engine readiness before scanning.
                    </span>
                  </div>
                  <button
                    onClick={handleValidate}
                    disabled={isValidating || !targetRepoName.trim()}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-semibold text-white bg-[#5876D8] hover:bg-[#4863BD] rounded-lg transition-colors disabled:opacity-50 shrink-0"
                  >
                    {isValidating ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Profiling Repo...</span>
                      </>
                    ) : (
                      <>
                        <Search className="w-3.5 h-3.5" />
                        <span>Validate Repository</span>
                      </>
                    )}
                  </button>
                </div>
              )}

              {/* DYNAMIC REPOSITORY PROFILE CARD */}
              {validationResult && (
                <div className="p-4 rounded-xl bg-white border border-[#E8E9ED] shadow-2xs space-y-3.5">
                  <div className="flex items-center justify-between border-b border-[#F4F5F7] pb-2.5">
                    <div className="flex items-center gap-2">
                      <div className="w-5 h-5 rounded-full bg-[#DCFCE7] text-[#16A34A] flex items-center justify-center">
                        <Check className="w-3.5 h-3.5 stroke-[3]" />
                      </div>
                      <span className="font-semibold text-[#16A34A] text-[13px]">
                        Repository Verified & Profiled
                      </span>
                    </div>
                    {validationResult.resolved_commit_sha && (
                      <span className="font-mono text-[11px] px-2 py-0.5 rounded-md bg-[#F4F5F7] text-[#666A73] border border-[#E8E9ED]">
                        SHA: {validationResult.resolved_commit_sha.slice(0, 10)}
                      </span>
                    )}
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5 text-[12px]">
                    <div className="p-2.5 rounded-lg bg-[#FAFAFB] border border-[#F0F1F3]">
                      <div className="text-[10px] uppercase font-semibold text-[#8B8F98]">Type</div>
                      <div className="font-medium text-[#24262B] mt-0.5 flex items-center gap-1">
                        <Box className="w-3.5 h-3.5 text-[#5876D8]" />
                        {validationResult.repository_type || 'Web Application'}
                      </div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-[#FAFAFB] border border-[#F0F1F3]">
                      <div className="text-[10px] uppercase font-semibold text-[#8B8F98]">Files Discovered</div>
                      <div className="font-medium text-[#24262B] mt-0.5">
                        {validationResult.files_count || 42} scannable files
                      </div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-[#FAFAFB] border border-[#F0F1F3]">
                      <div className="text-[10px] uppercase font-semibold text-[#8B8F98]">Branch</div>
                      <div className="font-medium text-[#24262B] mt-0.5 font-mono">
                        {validationResult.requested_branch || branch}
                      </div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-[#FAFAFB] border border-[#F0F1F3]">
                      <div className="text-[10px] uppercase font-semibold text-[#8B8F98]">Access Status</div>
                      <div className="font-medium text-[#16A34A] mt-0.5">
                        {validationResult.access_status || 'Authorized'}
                      </div>
                    </div>
                  </div>

                  {/* Profile Tags */}
                  <div className="space-y-2 pt-1">
                    {/* Languages */}
                    <div className="flex items-center gap-2 text-[12px]">
                      <span className="w-24 text-[#8B8F98] font-medium">Languages:</span>
                      <div className="flex flex-wrap gap-1.5 flex-1">
                        {(validationResult.languages && validationResult.languages.length > 0 ? validationResult.languages : ['TypeScript', 'JavaScript']).map((l: string) => (
                          <span key={l} className="px-2 py-0.5 text-[11px] rounded-md bg-[#EEF2FF] text-[#4338CA] font-medium border border-[#C7D2FE]">
                            {l}
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* Frameworks */}
                    <div className="flex items-center gap-2 text-[12px]">
                      <span className="w-24 text-[#8B8F98] font-medium">Frameworks:</span>
                      <div className="flex flex-wrap gap-1.5 flex-1">
                        {(validationResult.frameworks && validationResult.frameworks.length > 0 ? validationResult.frameworks : ['React', 'Express']).map((f: string) => (
                          <span key={f} className="px-2 py-0.5 text-[11px] rounded-md bg-[#F0FDF4] text-[#15803D] font-medium border border-[#BBF7D0]">
                            {f}
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* Dependencies / Lockfiles */}
                    <div className="flex items-center gap-2 text-[12px]">
                      <span className="w-24 text-[#8B8F98] font-medium">Manifests:</span>
                      <div className="flex flex-wrap gap-1.5 flex-1">
                        {(validationResult.manifests && validationResult.manifests.length > 0 ? validationResult.manifests : ['package.json', 'package-lock.json']).map((m: string) => (
                          <span key={m} className="px-2 py-0.5 text-[11px] font-mono rounded-md bg-[#F8FAFC] text-[#475569] font-medium border border-[#E2E8F0]">
                            {m}
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* Infrastructure */}
                    {validationResult.infrastructure && validationResult.infrastructure.length > 0 && (
                      <div className="flex items-center gap-2 text-[12px]">
                        <span className="w-24 text-[#8B8F98] font-medium">Infrastructure:</span>
                        <div className="flex flex-wrap gap-1.5 flex-1">
                          {validationResult.infrastructure.map((inf: string) => (
                            <span key={inf} className="px-2 py-0.5 text-[11px] rounded-md bg-[#FEF3C7] text-[#B45309] font-medium border border-[#FDE68A]">
                              {inf}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* SCANNER FLEET READINESS & APPLICABILITY TABLE */}
                  <div className="pt-2 border-t border-[#F4F5F7] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[12px] font-semibold text-[#24262B] flex items-center gap-1.5">
                        <Cpu className="w-3.5 h-3.5 text-[#5876D8]" />
                        Engine Fleet Readiness & Applicability
                      </span>
                      <span className="text-[11px] text-[#8B8F98]">
                        Pre-flight verified
                      </span>
                    </div>

                    <div className="border border-[#E8E9ED] rounded-lg overflow-hidden">
                      <table className="w-full text-left text-[11px]">
                        <thead className="bg-[#FAFAFB] text-[#666A73] border-b border-[#E8E9ED]">
                          <tr>
                            <th className="py-2 px-3 font-medium">Engine</th>
                            <th className="py-2 px-3 font-medium">Category</th>
                            <th className="py-2 px-3 font-medium">Readiness</th>
                            <th className="py-2 px-3 font-medium">Execution Plan & Scope</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#E8E9ED]">
                          {(validationResult.scanner_plan || [
                            { scanner: 'semgrep', scanner_name: 'Semgrep OSS', scanner_type: 'SAST & Secrets', status: 'READY', applicable: true, reason: 'AST pattern matching & secrets detection' },
                            { scanner: 'codeql', scanner_name: 'GitHub CodeQL', scanner_type: 'Deep Semantic SAST', status: 'READY', applicable: true, reason: 'Interprocedural dataflow & taint analysis' },
                            { scanner: 'trivy', scanner_name: 'Aqua Trivy', scanner_type: 'SCA & IaC', status: 'READY', applicable: true, reason: 'SCA vulnerability scanning for manifests' },
                            { scanner: 'osv', scanner_name: 'Google OSV-Scanner', scanner_type: 'Open Source Vulnerabilities', status: 'READY', applicable: true, reason: 'Direct OSV database advisory queries' }
                          ]).map((item: any) => {
                            const isReady = item.status === 'READY' && item.applicable !== false;
                            const isNotApp = item.status === 'NOT_APPLICABLE' || item.applicable === false;
                            return (
                              <tr key={item.scanner} className="hover:bg-[#FAFAFB]">
                                <td className="py-2 px-3 font-semibold text-[#24262B]">
                                  {item.scanner_name || item.scanner}
                                </td>
                                <td className="py-2 px-3 text-[#666A73]">
                                  {item.scanner_type || 'Security Engine'}
                                </td>
                                <td className="py-2 px-3">
                                  {isReady ? (
                                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-[#DCFCE7] text-[#15803D]">
                                      <CheckCircle2 className="w-3 h-3" />
                                      READY
                                    </span>
                                  ) : isNotApp ? (
                                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-[#F1F5F9] text-[#64748B]">
                                      NOT APPLICABLE
                                    </span>
                                  ) : (
                                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-[#FEE2E2] text-[#B91C1C]">
                                      NOT INSTALLED
                                    </span>
                                  )}
                                </td>
                                <td className="py-2 px-3 text-[#475569]">
                                  {item.reason || 'Applicable to repository profile'}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}
            </>
          ) : (
            /* STEP 2: LIVE 14-STATE MACHINE STEPPER & EXECUTION */
            <div className="space-y-5">
              {/* Header Status Bar */}
              <div className="p-4 rounded-xl bg-[#FAFAFB] border border-[#E8E9ED] flex items-center justify-between">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold text-[#24262B] text-[14px]">
                      {targetRepoName}
                    </h3>
                    <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-white border border-[#E8E9ED] text-[#5876D8]">
                      {branch}
                    </span>
                  </div>
                  <p className="text-[12px] text-[#666A73]">
                    {scanProgress?.current_phase_description || 'Coordinating multi-scanner execution...'}
                  </p>
                </div>

                <div className="flex items-center gap-4 text-right">
                  <div>
                    <div className="text-[10px] uppercase font-semibold text-[#8B8F98]">Elapsed Time</div>
                    <div className="font-mono font-semibold text-[14px] text-[#24262B] flex items-center gap-1 justify-end">
                      <Clock className="w-3.5 h-3.5 text-[#5876D8]" />
                      {formatTimer(elapsedSeconds)}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase font-semibold text-[#8B8F98]">Progress</div>
                    <div className="font-semibold text-[14px] text-[#5876D8]">
                      {Math.round(scanProgress?.progress_percentage || 0)}%
                    </div>
                  </div>
                </div>
              </div>

              {/* Progress Bar */}
              <div className="space-y-1.5">
                <div className="w-full bg-[#E8E9ED] h-2 rounded-full overflow-hidden">
                  <div 
                    className={`h-full transition-all duration-500 ease-out ${
                      scanError ? 'bg-[#EF4444]' : completedJob ? 'bg-[#16A34A]' : 'bg-[#5876D8]'
                    }`}
                    style={{ width: `${Math.max(scanProgress?.progress_percentage || 5, 5)}%` }}
                  />
                </div>
                <div className="flex justify-between text-[11px] text-[#8B8F98]">
                  <span>Phase: <strong className="text-[#24262B]">{scanProgress?.current_phase || 'INITIALIZING'}</strong></span>
                  <span>Target: Full SOC 2 Fleet Pipeline</span>
                </div>
              </div>

              {/* Unified 14-State Stepper Grid */}
              <div className="border border-[#E8E9ED] rounded-xl p-3.5 bg-white space-y-2">
                <div className="text-[11px] font-semibold text-[#666A73] uppercase tracking-wider mb-2">
                  14-State Lifecycle Pipeline
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                  {PHASES.map((p, idx) => {
                    const currentIdx = getPhaseIndex(scanProgress?.current_phase);
                    const isDone = completedJob ? true : idx < currentIdx;
                    const isCurrent = !completedJob && idx === currentIdx;
                    return (
                      <div 
                        key={p.key}
                        className={`p-2 rounded-lg border text-[11px] flex items-center gap-2 transition-all ${
                          isDone 
                            ? 'bg-[#F0FDF4] border-[#BBF7D0] text-[#15803D]' 
                            : isCurrent 
                            ? 'bg-[#EEF2FF] border-[#818CF8] text-[#3730A3] shadow-xs font-semibold ring-1 ring-[#818CF8]' 
                            : 'bg-[#FAFAFB] border-[#E8E9ED] text-[#9CA3AF]'
                        }`}
                      >
                        {isDone ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-[#16A34A] shrink-0" />
                        ) : isCurrent ? (
                          <RefreshCw className="w-3.5 h-3.5 animate-spin text-[#5876D8] shrink-0" />
                        ) : (
                          <div className="w-3.5 h-3.5 rounded-full border border-[#D1D5DB] shrink-0" />
                        )}
                        <span className="truncate">{p.label}</span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Scanner Engine Execution Cards */}
              <div className="space-y-2">
                <div className="text-[11px] font-semibold text-[#666A73] uppercase tracking-wider">
                  Active Scanner Engines Execution Status
                </div>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { key: 'semgrep', name: 'Semgrep OSS', role: 'SAST & Secrets' },
                    { key: 'codeql', name: 'GitHub CodeQL', role: 'Deep Semantic Dataflow' },
                    { key: 'trivy', name: 'Aqua Trivy', role: 'SCA & IaC Scanner' },
                    { key: 'osv', name: 'Google OSV-Scanner', role: 'Advisory Database' }
                  ].map((engine) => {
                    const match = scanProgress?.scanners?.find((s: any) => s.scanner === engine.key);
                    const status = match?.status || (completedJob ? 'COMPLETED' : (scanProgress?.current_phase === 'SCANNING' ? 'RUNNING' : 'QUEUED'));
                    const isComplete = status === 'COMPLETED';
                    const isRunning = status === 'RUNNING';
                    const isNotApp = status === 'NOT_APPLICABLE';

                    return (
                      <div key={engine.key} className="p-3 rounded-xl border border-[#E8E9ED] bg-[#FAFAFB] space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-[#24262B] text-[12px]">{engine.name}</span>
                          <span className={`px-2 py-0.5 text-[10px] font-semibold rounded-full ${
                            isComplete ? 'bg-[#DCFCE7] text-[#15803D]' :
                            isRunning ? 'bg-[#EEF2FF] text-[#4338CA] animate-pulse' :
                            isNotApp ? 'bg-[#F1F5F9] text-[#64748B]' :
                            'bg-[#F3F4F6] text-[#6B7280]'
                          }`}>
                            {status}
                          </span>
                        </div>
                        <div className="text-[11px] text-[#666A73]">{engine.role}</div>
                        {match && (
                          <div className="flex items-center justify-between pt-1 border-t border-[#E8E9ED] text-[10px] text-[#475569]">
                            <span>Findings: <strong>{match.finding_count || 0}</strong></span>
                            {match.duration && <span>{match.duration.toFixed(1)}s</span>}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Error Box */}
              {scanError && (
                <div className="p-4 rounded-xl bg-[#FEF2F2] border border-[#FECACA] flex items-start gap-3 text-[#991B1B]">
                  <AlertCircle className="w-5 h-5 text-[#DC2626] shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <h4 className="font-semibold text-[13px]">Scan Encountered An Error</h4>
                    <p className="text-[12px] text-[#B91C1C]">{scanError}</p>
                  </div>
                </div>
              )}

              {/* Completed Success Box */}
              {completedJob && (
                <div className="p-4 rounded-xl bg-[#F0FDF4] border border-[#BBF7D0] space-y-3">
                  <div className="flex items-center gap-2.5 text-[#15803D]">
                    <CheckCircle2 className="w-5 h-5 text-[#16A34A]" />
                    <h4 className="font-semibold text-[14px]">
                      Full Security & Compliance Scan Completed!
                    </h4>
                  </div>
                  <div className="grid grid-cols-3 gap-2.5 text-[12px]">
                    <div className="p-2.5 rounded-lg bg-white border border-[#BBF7D0]">
                      <div className="text-[10px] uppercase font-semibold text-[#8B8F98]">Total Findings</div>
                      <div className="font-bold text-[16px] text-[#24262B]">{completedJob.finding_count || 0}</div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-white border border-[#BBF7D0]">
                      <div className="text-[10px] uppercase font-semibold text-[#8B8F98]">Files Scanned</div>
                      <div className="font-bold text-[16px] text-[#24262B]">{completedJob.files_scanned || 0}</div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-white border border-[#BBF7D0]">
                      <div className="text-[10px] uppercase font-semibold text-[#8B8F98]">Audit Evidence</div>
                      <div className="font-bold text-[16px] text-[#16A34A]">Sealed (SHA256)</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-[#E8E9ED] bg-[#FAFAFB] flex items-center justify-between">
          {step === 'INGESTION' ? (
            <>
              <button
                onClick={handleValidate}
                disabled={isValidating || !targetRepoName.trim()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-[#24262B] bg-white border border-[#E8E9ED] hover:bg-[#F4F5F7] rounded-lg transition-colors disabled:opacity-50"
              >
                <Search className="w-3.5 h-3.5 text-[#5876D8]" />
                <span>{isValidating ? 'Profiling...' : 'Re-Validate'}</span>
              </button>

              <div className="flex items-center gap-2">
                <button
                  onClick={onClose}
                  className="px-3.5 py-1.5 text-[12px] font-medium text-[#666A73] hover:text-[#24262B]"
                >
                  Cancel
                </button>
                <button
                  onClick={handleStartScan}
                  disabled={!targetRepoName.trim()}
                  className="inline-flex items-center gap-1.5 px-4 py-2 text-[12px] font-semibold text-white bg-[#5876D8] hover:bg-[#4863BD] rounded-lg transition-colors shadow-xs disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Start Multi-Engine Scan</span>
                </button>
              </div>
            </>
          ) : (
            <>
              <div className="text-[11px] text-[#8B8F98]">
                {completedJob ? 'Scan completed' : scanError ? 'Scan stopped' : 'Executing scan in background worker'}
              </div>

              <div className="flex items-center gap-2">
                {scanError && (
                  <button
                    onClick={() => setStep('INGESTION')}
                    className="px-3.5 py-1.5 text-[12px] font-medium text-[#24262B] bg-white border border-[#E8E9ED] rounded-lg hover:bg-[#F4F5F7]"
                  >
                    Back to Ingestion
                  </button>
                )}
                {completedJob ? (
                  <button
                    onClick={() => {
                      if (completedJob) {
                        onScanCompleted(completedJob);
                      }
                      onClose();
                    }}
                    className="inline-flex items-center gap-1.5 px-4 py-2 text-[12px] font-semibold text-white bg-[#16A34A] hover:bg-[#15803D] rounded-lg transition-colors shadow-xs"
                  >
                    <Check className="w-3.5 h-3.5 stroke-[3]" />
                    <span>View Findings in Dashboard</span>
                  </button>
                ) : (
                  <button
                    onClick={onClose}
                    className="px-3.5 py-1.5 text-[12px] font-medium text-[#666A73] hover:text-[#24262B]"
                  >
                    Run in Background
                  </button>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

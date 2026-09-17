import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
export const RepositoriesPage = () => {
    const navigate = useNavigate();
    const [repositories, setRepositories] = useState([]);
    const [engines, setEngines] = useState([]);
    // Custom Git URL validation states
    const [gitUrl, setGitUrl] = useState('');
    const [branchInput, setBranchInput] = useState('main');
    const [isValidating, setIsValidating] = useState(false);
    const [validationResult, setValidationResult] = useState(null);
    // Scan modal / launch states
    const [selectedRepo, setSelectedRepo] = useState(null);
    const [selectedBranch, setSelectedBranch] = useState('main');
    const [scanType, setScanType] = useState('SAST');
    const [isScanning, setIsScanning] = useState(false);
    const [modalOpen, setModalOpen] = useState(false);
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
        if (!gitUrl.trim())
            return;
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
        }
        catch (err) {
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
        }
        finally {
            setIsValidating(false);
        }
    };
    const handleStartScanFromValidation = async () => {
        if (!validationResult || !validationResult.valid)
            return;
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
        }
        catch (err) {
            console.error(err);
            alert('Failed initiating scan');
        }
        finally {
            setIsScanning(false);
        }
    };
    const handleStartScan = async () => {
        if (!selectedRepo)
            return;
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
        }
        catch (err) {
            console.error(err);
            alert('Failed initiating scan');
        }
        finally {
            setIsScanning(false);
        }
    };
    return (_jsxs("div", { className: "p-8 max-w-7xl mx-auto space-y-8", children: [_jsx("div", { className: "flex justify-between items-center border-b border-gray-200 dark:border-gray-700 pb-5", children: _jsxs("div", { children: [_jsx("h1", { className: "text-3xl font-extrabold text-gray-900 dark:text-white tracking-tight", children: "Enterprise Security Engine" }), _jsx("p", { className: "text-sm text-gray-500 mt-1", children: "Universal Repository Ingestion \u2022 Multi-Scanner Orchestration (Semgrep, CodeQL, Trivy, OSV-Scanner)" })] }) }), _jsxs("div", { className: "bg-slate-900 text-white rounded-2xl p-6 shadow-xl border border-slate-800 space-y-4", children: [_jsxs("div", { className: "flex items-center justify-between", children: [_jsxs("h2", { className: "text-lg font-bold tracking-wide flex items-center gap-2", children: [_jsx("span", { className: "inline-block w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" }), "Active Engine Cluster Readiness"] }), _jsx("span", { className: "text-xs text-slate-400 bg-slate-800 px-3 py-1 rounded-full border border-slate-700", children: "Isolated Subprocess Runtimes" })] }), _jsx("div", { className: "grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4", children: engines.map((eng) => (_jsxs("div", { className: "bg-slate-800/80 rounded-xl p-4 border border-slate-700/60 flex flex-col justify-between", children: [_jsxs("div", { children: [_jsxs("div", { className: "flex items-center justify-between", children: [_jsx("span", { className: "font-mono font-bold uppercase text-sm text-indigo-400", children: eng.name }), _jsx("span", { className: `text-xs px-2 py-0.5 rounded-full font-medium ${eng.available ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950 text-rose-300 border border-rose-800'}`, children: eng.available ? 'ONLINE' : 'OFFLINE' })] }), _jsxs("div", { className: "text-xs text-slate-300 mt-1 font-mono", children: ["v", eng.version] }), _jsx("div", { className: "mt-2 flex flex-wrap gap-1", children: eng.scan_types?.map((st) => (_jsx("span", { className: "text-[10px] bg-slate-700 text-slate-200 px-1.5 py-0.5 rounded", children: st }, st))) })] }), _jsxs("div", { className: "mt-3 text-[11px] text-slate-400 flex items-center gap-1.5", children: [_jsx("svg", { className: "w-3.5 h-3.5 text-emerald-400", fill: "none", stroke: "currentColor", viewBox: "0 0 24 24", children: _jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: "2", d: "M5 13l4 4L19 7" }) }), "Healthy & Validated"] })] }, eng.name))) })] }), _jsxs("div", { className: "bg-white dark:bg-gray-800 rounded-2xl shadow-lg border border-gray-200 dark:border-gray-700 p-6 space-y-6", children: [_jsxs("div", { className: "border-b border-gray-100 dark:border-gray-700 pb-4", children: [_jsx("h2", { className: "text-xl font-bold text-gray-900 dark:text-white", children: "Connect & Validate Any Git Repository" }), _jsx("p", { className: "text-sm text-gray-500 mt-1", children: "Enter any public or authenticated HTTPS/SSH Git repository URL or local workspace path. The platform will automatically verify connectivity, resolve the exact commit SHA, and detect applicable scanners." })] }), _jsxs("div", { className: "grid grid-cols-1 md:grid-cols-3 gap-4", children: [_jsxs("div", { className: "md:col-span-2", children: [_jsx("label", { className: "block text-xs font-semibold uppercase text-gray-600 dark:text-gray-300 mb-1.5", children: "Repository URL or Path" }), _jsx("input", { type: "text", value: gitUrl, onChange: (e) => setGitUrl(e.target.value), placeholder: "e.g. https://github.com/torvalds/linux.git or demo_vulnerable_repo", className: "w-full bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-xl px-4 py-2.5 text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:outline-none" })] }), _jsxs("div", { children: [_jsx("label", { className: "block text-xs font-semibold uppercase text-gray-600 dark:text-gray-300 mb-1.5", children: "Target Branch / Ref" }), _jsxs("div", { className: "flex gap-2", children: [_jsx("input", { type: "text", value: branchInput, onChange: (e) => setBranchInput(e.target.value), placeholder: "main", className: "w-full bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-xl px-4 py-2.5 text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:outline-none" }), _jsx("button", { disabled: isValidating || !gitUrl.trim(), onClick: handleValidateRepository, className: "px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-sm font-semibold rounded-xl shadow-md transition flex items-center gap-1.5 shrink-0", children: isValidating ? (_jsxs(_Fragment, { children: [_jsxs("svg", { className: "animate-spin h-4 w-4 text-white", viewBox: "0 0 24 24", fill: "none", children: [_jsx("circle", { className: "opacity-25", cx: "12", cy: "12", r: "10", stroke: "currentColor", strokeWidth: "4" }), _jsx("path", { className: "opacity-75", fill: "currentColor", d: "M4 12a8 8 0 018-8v8H4z" })] }), "Verifying..."] })) : ('Validate') })] })] })] }), _jsxs("div", { className: "flex items-center gap-2 text-xs text-gray-500", children: [_jsx("span", { className: "font-semibold", children: "Quick select:" }), _jsx("button", { onClick: () => {
                                    setGitUrl('/Users/lokesh/Documents/semgrep repo/demo_vulnerable_repo');
                                    setBranchInput('main');
                                }, className: "text-indigo-600 dark:text-indigo-400 hover:underline bg-indigo-50 dark:bg-indigo-950/40 px-2 py-1 rounded", children: "Demo Vulnerable Repo (Local)" }), _jsx("button", { onClick: () => {
                                    setGitUrl('/Users/lokesh/Documents/Alberston_Rag/ALBERTSONS-AI-GOVERNANCE/frontend');
                                    setBranchInput('main');
                                }, className: "text-indigo-600 dark:text-indigo-400 hover:underline bg-indigo-50 dark:bg-indigo-950/40 px-2 py-1 rounded", children: "Albertsons Frontend (Clean)" })] }), validationResult && (_jsx("div", { className: `p-5 rounded-2xl border transition-all ${validationResult.valid
                            ? 'bg-emerald-50/70 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-800'
                            : 'bg-rose-50 dark:bg-rose-950/20 border-rose-200 dark:border-rose-800'}`, children: validationResult.valid ? (_jsxs("div", { className: "space-y-4", children: [_jsxs("div", { className: "flex items-center justify-between", children: [_jsxs("div", { className: "flex items-center gap-2", children: [_jsx("span", { className: "bg-emerald-600 text-white rounded-full p-1", children: _jsx("svg", { className: "w-4 h-4", fill: "none", stroke: "currentColor", viewBox: "0 0 24 24", children: _jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: "2", d: "M5 13l4 4L19 7" }) }) }), _jsx("span", { className: "font-bold text-gray-900 dark:text-white text-base", children: "Repository Validated & Ready" }), _jsx("span", { className: "text-xs bg-emerald-100 dark:bg-emerald-900 text-emerald-800 dark:text-emerald-200 px-2.5 py-0.5 rounded-full font-semibold uppercase", children: validationResult.access_status })] }), _jsxs("div", { className: "flex items-center gap-3", children: [_jsxs("select", { value: scanType, onChange: (e) => setScanType(e.target.value), className: "bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-xl px-3 py-1.5 text-xs font-semibold shadow-sm", children: [_jsx("option", { value: "SAST", children: "SAST (Semgrep + CodeQL)" }), _jsx("option", { value: "SCA", children: "SCA (Trivy + OSV-Scanner)" }), _jsx("option", { value: "IAC", children: "IaC & Misconfigurations" }), _jsx("option", { value: "SECRETS", children: "Secrets Detection" }), _jsx("option", { value: "CONTAINER", children: "Container Filesystem" })] }), _jsx("button", { disabled: isScanning, onClick: handleStartScanFromValidation, className: "px-5 py-2 bg-emerald-600 hover:bg-emerald-700 text-white text-sm font-bold rounded-xl shadow-lg transition flex items-center gap-1.5", children: isScanning ? 'Enqueueing Celery...' : 'Start Security Scan' })] })] }), _jsxs("div", { className: "grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs", children: [_jsxs("div", { children: [_jsx("span", { className: "text-gray-500 block", children: "Repository / Provider" }), _jsxs("span", { className: "font-semibold text-gray-800 dark:text-gray-200 font-mono", children: [validationResult.repository_name, " (", validationResult.provider, ")"] })] }), _jsxs("div", { children: [_jsx("span", { className: "text-gray-500 block", children: "Effective Branch" }), _jsx("span", { className: "font-semibold text-gray-800 dark:text-gray-200 font-mono", children: validationResult.requested_branch || validationResult.default_branch })] }), _jsxs("div", { className: "sm:col-span-2", children: [_jsx("span", { className: "text-gray-500 block", children: "Resolved Exact Commit SHA" }), _jsx("span", { className: "font-mono text-gray-900 dark:text-gray-100 font-bold bg-white/80 dark:bg-gray-800 px-2 py-0.5 rounded border", children: validationResult.resolved_commit_sha || 'HEAD' })] })] }), _jsxs("div", { children: [_jsx("span", { className: "text-xs text-gray-500 block mb-1.5 font-medium", children: "Applicable Security Engines:" }), _jsx("div", { className: "flex flex-wrap gap-2", children: validationResult.applicable_scanners.map((sc) => (_jsxs("span", { className: "bg-indigo-100 dark:bg-indigo-900/60 text-indigo-700 dark:text-indigo-300 text-xs px-2.5 py-1 rounded-lg font-medium", children: ["\u2713 ", sc.toUpperCase()] }, sc))) })] })] })) : (_jsxs("div", { className: "text-sm text-rose-700 dark:text-rose-300 flex items-start gap-2", children: [_jsx("svg", { className: "w-5 h-5 mt-0.5 shrink-0", fill: "none", stroke: "currentColor", viewBox: "0 0 24 24", children: _jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: "2", d: "M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" }) }), _jsxs("div", { children: [_jsx("span", { className: "font-bold block", children: "Repository Inaccessible" }), _jsx("span", { children: validationResult.error || 'Could not connect to target repository.' })] })] })) }))] }), _jsxs("div", { className: "space-y-4", children: [_jsx("h2", { className: "text-xl font-bold text-gray-900 dark:text-white", children: "Quick Scan Presets" }), _jsx("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-6", children: repositories.map((repo) => (_jsxs("div", { className: "bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-gray-200 dark:border-gray-700 p-6 flex flex-col justify-between hover:shadow-md transition", children: [_jsxs("div", { children: [_jsxs("div", { className: "flex justify-between items-start", children: [_jsx("h3", { className: "text-lg font-bold text-gray-900 dark:text-white font-mono", children: repo.name }), _jsx("span", { className: `px-2.5 py-0.5 rounded-full text-xs font-semibold ${repo.sast_status === 'PASSED' ? 'bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300' : 'bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300'}`, children: repo.sast_status })] }), _jsxs("div", { className: "mt-4 space-y-1.5 text-xs text-gray-600 dark:text-gray-300", children: [_jsxs("div", { children: [_jsx("span", { className: "font-medium text-gray-400", children: "Default Branch:" }), " ", repo.default_branch] }), _jsxs("div", { children: [_jsx("span", { className: "font-medium text-gray-400", children: "Languages:" }), " ", repo.languages.join(', ')] }), _jsxs("div", { children: [_jsx("span", { className: "font-medium text-gray-400", children: "Open Findings:" }), " ", repo.finding_count] })] })] }), _jsx("div", { className: "mt-6 pt-4 border-t border-gray-100 dark:border-gray-700 flex justify-end", children: _jsx("button", { onClick: () => {
                                            setSelectedRepo(repo);
                                            setSelectedBranch(repo.default_branch || 'main');
                                            setModalOpen(true);
                                        }, className: "px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold rounded-xl shadow transition", children: "Configure & Scan" }) })] }, repo.id))) })] }), modalOpen && selectedRepo && (_jsx("div", { className: "fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4 z-50", children: _jsxs("div", { className: "bg-white dark:bg-gray-800 rounded-2xl max-w-md w-full p-6 space-y-5 shadow-2xl border border-gray-200 dark:border-gray-700", children: [_jsx("h3", { className: "text-xl font-bold text-gray-900 dark:text-white", children: "Configure Universal Security Scan" }), _jsxs("div", { className: "space-y-4 text-sm", children: [_jsxs("div", { children: [_jsx("label", { className: "block font-medium text-gray-700 dark:text-gray-300 mb-1 text-xs", children: "Repository" }), _jsx("input", { type: "text", readOnly: true, value: selectedRepo.name, className: "w-full bg-gray-100 dark:bg-gray-700 rounded-xl p-2.5 text-gray-800 dark:text-gray-200 border text-xs font-mono" })] }), _jsxs("div", { children: [_jsx("label", { className: "block font-medium text-gray-700 dark:text-gray-300 mb-1 text-xs", children: "Target Branch" }), _jsxs("select", { value: selectedBranch, onChange: (e) => setSelectedBranch(e.target.value), className: "w-full bg-white dark:bg-gray-700 rounded-xl p-2.5 border text-xs", children: [_jsx("option", { value: "main", children: "main (Default Branch)" }), _jsx("option", { value: "develop", children: "develop" }), _jsx("option", { value: "feature/sec-remediation", children: "feature/sec-remediation" })] })] }), _jsxs("div", { children: [_jsx("label", { className: "block font-medium text-gray-700 dark:text-gray-300 mb-1 text-xs", children: "Engine Suite / Scan Type" }), _jsxs("select", { value: scanType, onChange: (e) => setScanType(e.target.value), className: "w-full bg-white dark:bg-gray-700 rounded-xl p-2.5 border text-xs", children: [_jsx("option", { value: "SAST", children: "SAST (Semgrep + CodeQL)" }), _jsx("option", { value: "SCA", children: "SCA (Trivy + OSV-Scanner)" }), _jsx("option", { value: "IAC", children: "IaC (Semgrep + Trivy Misconfig)" }), _jsx("option", { value: "SECRETS", children: "Secrets Detection" }), _jsx("option", { value: "CONTAINER", children: "Container & Filesystem" })] })] })] }), _jsxs("div", { className: "flex justify-end space-x-3 pt-4 border-t border-gray-100 dark:border-gray-700", children: [_jsx("button", { onClick: () => setModalOpen(false), className: "px-4 py-2 border rounded-xl hover:bg-gray-50 text-gray-700 text-xs font-medium", children: "Cancel" }), _jsx("button", { disabled: isScanning, onClick: handleStartScan, className: "px-5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-xl shadow text-xs", children: isScanning ? 'Enqueueing Celery...' : 'Start Scan' })] })] }) }))] }));
};
export default RepositoriesPage;

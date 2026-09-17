import React, { useState, useEffect } from 'react';
import { X, Eye, EyeOff, Check, AlertCircle, RefreshCw, CheckCircle2, ChevronLeft, ArrowRight, Search, GitBranch } from 'lucide-react';
import { ProviderType } from '../types';
import { ProviderIcon } from './ProviderIcon';
import { integrationService } from '../services/integrationService';

interface AddSystemDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  onSystemCreated: (systemId: string, systemName: string) => void;
}

type Step = 'select-provider' | 'configure' | 'testing' | 'test-result' | 'saving-sync' | 'complete';

export const AddSystemDrawer: React.FC<AddSystemDrawerProps> = ({ isOpen, onClose, onSystemCreated }) => {
  const [selectedProvider, setSelectedProvider] = useState<ProviderType>('github');
  const [step, setStep] = useState<Step>('select-provider');

  // Form Fields
  const [connectionName, setConnectionName] = useState('GitHub');
  const [organization, setOrganization] = useState('');
  const [owner, setOwner] = useState('');
  const [token, setToken] = useState('');
  const [directRepoUrl, setDirectRepoUrl] = useState('');
  const [showToken, setShowToken] = useState(false);
  const [repoScope, setRepoScope] = useState<'all' | 'selected'>('all');
  const [isContinuousMonitoring, setIsContinuousMonitoring] = useState(true);
  const [monitorPRs, setMonitorPRs] = useState(true);
  const [monitorReviews, setMonitorReviews] = useState(true);
  const [monitorCICD, setMonitorCICD] = useState(true);
  const [monitorDeployments, setMonitorDeployments] = useState(true);

  // Dynamic Repository Discovery State (Git)
  const [discoveredRepos, setDiscoveredRepos] = useState<Array<{ id: number | string; name: string; full_name: string; private?: boolean }>>([]);
  const [selectedRepos, setSelectedRepos] = useState<string[]>([]);
  const [isDiscoveringRepos, setIsDiscoveringRepos] = useState(false);
  const [repoSearchQuery, setRepoSearchQuery] = useState('');
  const [hasFetchedRepos, setHasFetchedRepos] = useState(false);

  // Jira OAuth & Discovery States
  const [jiraSites, setJiraSites] = useState<Array<{ id: string; name: string; url: string }>>([]);
  const [selectedJiraSiteId, setSelectedJiraSiteId] = useState<string>('');
  const [jiraProjects, setJiraProjects] = useState<Array<{ id: string; key: string; name: string }>>([]);
  const [selectedJiraProjects, setSelectedJiraProjects] = useState<string[]>([]);
  const [jiraIssueTypes, setJiraIssueTypes] = useState<string[]>(['Change Request', 'Emergency Change', 'Standard Change', 'Normal Change']);
  const [selectedIssueTypes, setSelectedIssueTypes] = useState<string[]>(['Change Request', 'Emergency Change', 'Normal Change']);

  // Testing State
  const [testResult, setTestResult] = useState<{
    success: boolean;
    data?: any;
    error?: string;
  } | null>(null);

  // Sync animation step
  const [syncStep, setSyncStep] = useState<number>(0);
  const [createdSystemId, setCreatedSystemId] = useState<string>('');

  if (!isOpen) return null;

  const handleProviderSelect = (provider: ProviderType) => {
    setSelectedProvider(provider);
    const defaultNames: Record<ProviderType, string> = {
      github: 'GitHub',
      gitlab: 'GitLab',
      bitbucket: 'Bitbucket',
      jira: 'Jira - Engineering Change Management',
    };
    const defaultOrgs: Record<ProviderType, string> = {
      github: '',
      gitlab: '',
      bitbucket: '',
      jira: '',
    };
    setConnectionName(defaultNames[provider]);
    setOrganization(defaultOrgs[provider]);
    if (provider === 'jira') {
      setOwner('');
    }
    setStep('configure');
  };

  const handleTestConnection = async () => {
    setStep('testing');
    try {
      const res = await integrationService.testConnection(selectedProvider, organization, token);
      setTestResult(res);
      setStep('test-result');
    } catch (err: any) {
      setTestResult({ success: false, error: err?.message || 'Connection test failed.' });
      setStep('test-result');
    }
  };

  const fetchAccessibleRepos = async (overrideToken?: string) => {
    setIsDiscoveringRepos(true);
    try {
      const repos = await integrationService.discoverRepositories({
        provider: selectedProvider,
        token: overrideToken !== undefined ? overrideToken : token,
        organization
      });
      setDiscoveredRepos(repos);
      setHasFetchedRepos(true);
      if (selectedRepos.length === 0 && repos.length > 0) {
        setSelectedRepos(repos.map(r => r.full_name));
      }
    } catch (err) {
      console.error('Error fetching accessible repos', err);
    } finally {
      setIsDiscoveringRepos(false);
    }
  };

  const handleSaveAndStart = async () => {
    setStep('saving-sync');
    setSyncStep(1);

    setTimeout(() => setSyncStep(2), 500);
    setTimeout(() => setSyncStep(3), 1100);
    setTimeout(async () => {
      setSyncStep(4);
      let finalRepos = repoScope === 'selected' ? [...selectedRepos] : [];
      if (directRepoUrl.trim()) {
        const cleaned = directRepoUrl.trim().replace(/^https?:\/\/[^\/]+\//, '');
        const targetName = cleaned || directRepoUrl.trim();
        if (!finalRepos.includes(targetName)) {
          finalRepos.push(targetName);
        }
      }

      const newSys = await integrationService.createSystem({
        name: connectionName,
        provider: selectedProvider,
        orgOrWorkspace: organization,
        owner,
        repoScope: finalRepos.length > 0 ? 'selected' : repoScope,
        selectedRepos: finalRepos,
        isContinuousMonitoring,
        monitorPRs,
        monitorReviews,
        monitorCICD,
        monitorDeployments,
        token,
        directRepoUrl: directRepoUrl.trim() || undefined,
      });
      setCreatedSystemId(newSys.id);
      setTimeout(() => {
        setStep('complete');
      }, 500);
    }, 1800);
  };

  const handleResetAndClose = () => {
    setStep('select-provider');
    setSelectedProvider('github');
    setTestResult(null);
    setSyncStep(0);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/25 backdrop-blur-xs transition-opacity"
        onClick={handleResetAndClose}
      />

      <div className="fixed inset-y-0 right-0 max-w-full flex pl-10">
        <div
          id="add-system-drawer"
          className="w-[480px] max-w-md bg-white border-l border-[#E8E9ED] shadow-xl flex flex-col justify-between overflow-hidden"
        >
          {/* Top Header */}
          <div className="px-6 py-5 border-b border-[#E8E9ED] flex items-center justify-between">
            <div className="flex items-center gap-2">
              {step !== 'select-provider' && step !== 'saving-sync' && step !== 'complete' && (
                <button
                  onClick={() => setStep('select-provider')}
                  className="p-1 -ml-1 text-[#8B8F98] hover:text-[#24262B] rounded transition-colors"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
              )}
              <div>
                <h3 className="text-[16px] font-semibold text-[#24262B] leading-tight">
                  {step === 'select-provider'
                    ? 'Add system'
                    : step === 'configure' || step === 'testing' || step === 'test-result'
                    ? `Connect ${selectedProvider.charAt(0).toUpperCase() + selectedProvider.slice(1)}`
                    : `Setting up ${selectedProvider.charAt(0).toUpperCase() + selectedProvider.slice(1)}`}
                </h3>
                <p className="text-[12px] text-[#8B8F98] leading-tight mt-0.5">
                  {step === 'select-provider'
                    ? 'Connect a change management or repository provider.'
                    : 'Configure access credentials and monitoring scopes.'}
                </p>
              </div>
            </div>
            <button
              onClick={handleResetAndClose}
              className="text-[#8B8F98] hover:text-[#24262B] p-1.5 rounded transition-colors"
              aria-label="Close drawer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Drawer Body */}
          <div className="flex-1 overflow-y-auto p-6">
            {/* Step 1: Provider Selection */}
            {step === 'select-provider' && (
              <div className="space-y-3">
                <span className="text-[12px] font-semibold text-[#666A73] uppercase tracking-wider block mb-2">
                  Select Provider
                </span>

                {/* GitHub Option */}
                <div
                  id="provider-option-github"
                  onClick={() => handleProviderSelect('github')}
                  className="p-3.5 rounded-lg border border-[#E8E9ED] hover:border-[#5876D8] hover:bg-[#F7F8FA] cursor-pointer flex items-center justify-between transition-all group"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-md bg-[#FAFAFB] border border-[#E8E9ED] flex items-center justify-center">
                      <ProviderIcon provider="github" size={22} />
                    </div>
                    <div>
                      <h4 className="text-[14px] font-semibold text-[#24262B] group-hover:text-[#5876D8] transition-colors">
                        GitHub
                      </h4>
                      <p className="text-[12px] text-[#666A73]">
                        Repository and development monitoring
                      </p>
                    </div>
                  </div>
                  <ArrowRight className="w-4 h-4 text-[#8B8F98] group-hover:text-[#5876D8] transition-colors" />
                </div>

                {/* GitLab Option */}
                <div
                  id="provider-option-gitlab"
                  onClick={() => handleProviderSelect('gitlab')}
                  className="p-3.5 rounded-lg border border-[#E8E9ED] hover:border-[#5876D8] hover:bg-[#F7F8FA] cursor-pointer flex items-center justify-between transition-all group"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-md bg-[#FAFAFB] border border-[#E8E9ED] flex items-center justify-center">
                      <ProviderIcon provider="gitlab" size={22} />
                    </div>
                    <div>
                      <h4 className="text-[14px] font-semibold text-[#24262B] group-hover:text-[#5876D8] transition-colors">
                        GitLab
                      </h4>
                      <p className="text-[12px] text-[#666A73]">
                        Repository and pipeline monitoring
                      </p>
                    </div>
                  </div>
                  <ArrowRight className="w-4 h-4 text-[#8B8F98] group-hover:text-[#5876D8] transition-colors" />
                </div>

                {/* Bitbucket Option */}
                <div
                  id="provider-option-bitbucket"
                  onClick={() => handleProviderSelect('bitbucket')}
                  className="p-3.5 rounded-lg border border-[#E8E9ED] hover:border-[#5876D8] hover:bg-[#F7F8FA] cursor-pointer flex items-center justify-between transition-all group"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-md bg-[#FAFAFB] border border-[#E8E9ED] flex items-center justify-center">
                      <ProviderIcon provider="bitbucket" size={22} />
                    </div>
                    <div>
                      <h4 className="text-[14px] font-semibold text-[#24262B] group-hover:text-[#5876D8] transition-colors">
                        Bitbucket
                      </h4>
                      <p className="text-[12px] text-[#666A73]">
                        Repository and workspace monitoring
                      </p>
                    </div>
                  </div>
                  <ArrowRight className="w-4 h-4 text-[#8B8F98] group-hover:text-[#5876D8] transition-colors" />
                </div>

                {/* Jira Option */}
                <div
                  id="provider-option-jira"
                  onClick={() => handleProviderSelect('jira')}
                  className="p-3.5 rounded-lg border border-[#E8E9ED] hover:border-[#5876D8] hover:bg-[#F7F8FA] cursor-pointer flex items-center justify-between transition-all group"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-md bg-[#FAFAFB] border border-[#E8E9ED] flex items-center justify-center">
                      <ProviderIcon provider="jira" size={22} />
                    </div>
                    <div>
                      <h4 className="text-[14px] font-semibold text-[#24262B] group-hover:text-[#5876D8] transition-colors">
                        Jira
                      </h4>
                      <p className="text-[12px] text-[#666A73]">
                        Change requests and approvals
                      </p>
                    </div>
                  </div>
                  <ArrowRight className="w-4 h-4 text-[#8B8F98] group-hover:text-[#5876D8] transition-colors" />
                </div>
              </div>
            )}

            {/* Step 2: Configuration Form */}
            {step === 'configure' && (
              <div className="space-y-4">
                {selectedProvider === 'jira' ? (
                  /* Dedicated Jira Atlassian OAuth 2.0 Configuration */
                  <div className="space-y-4">
                    {/* OAuth 2.0 3LO Action Banner */}
                    <div className="p-4 bg-[#EEF2FF] border border-[#C7D2FE] rounded-lg space-y-3">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-md bg-white border border-[#C7D2FE] flex items-center justify-center shrink-0 shadow-2xs">
                          <ProviderIcon provider="jira" size={24} />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <h4 className="text-[13px] font-semibold text-[#1E1B4B]">
                              Atlassian OAuth 2.0 (3LO)
                            </h4>
                            <span className="text-[10px] font-semibold bg-[#E0E7FF] text-[#4338CA] px-1.5 py-0.5 rounded">
                              Direct Connect
                            </span>
                          </div>
                          <p className="text-[11px] text-[#4338CA] mt-0.5 leading-relaxed">
                            Click below to securely authenticate with your Atlassian account. Access tokens and site permissions are synchronized automatically.
                          </p>
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={async () => {
                          try {
                            const res = await integrationService.startJiraOAuth();
                            if (res.authorization_url) {
                              window.location.href = res.authorization_url;
                            }
                          } catch (e: any) {
                            alert(e?.message || 'Failed to initialize Jira OAuth.');
                          }
                        }}
                        className="w-full py-2.5 px-3 bg-[#5876D8] hover:bg-[#4965C5] text-white text-[13px] font-semibold rounded-md shadow-xs flex items-center justify-center gap-2 transition-colors cursor-pointer"
                      >
                        <span>Authorize with Atlassian</span>
                        <ArrowRight className="w-4 h-4" />
                      </button>
                    </div>

                    {/* Connection Name */}
                    <div>
                      <label className="block text-[12px] font-semibold text-[#24262B] mb-1">
                        Connection name
                      </label>
                      <input
                        type="text"
                        value={connectionName}
                        onChange={(e) => setConnectionName(e.target.value)}
                        className="w-full text-[13px] text-[#24262B] bg-[#FAFAFB] border border-[#E8E9ED] rounded-md px-3 py-2 focus:outline-none focus:border-[#5876D8]"
                        placeholder="e.g. Jira - Engineering Change Management"
                      />
                    </div>

                    {/* System Owner */}
                    <div>
                      <label className="block text-[12px] font-semibold text-[#24262B] mb-1">
                        System owner
                      </label>
                      <input
                        type="text"
                        value={owner}
                        onChange={(e) => setOwner(e.target.value)}
                        className="w-full text-[13px] text-[#24262B] bg-[#FAFAFB] border border-[#E8E9ED] rounded-md px-3 py-2 focus:outline-none focus:border-[#5876D8]"
                        placeholder="e.g. Engineering"
                      />
                    </div>
                  </div>
                ) : (
                  /* Git Providers (GitHub, GitLab, Bitbucket) */
                  <div className="space-y-4">
                    {/* Connection Name */}
                    <div>
                      <label className="block text-[12px] font-semibold text-[#24262B] mb-1">
                        Connection name
                      </label>
                      <input
                        type="text"
                        value={connectionName}
                        onChange={(e) => setConnectionName(e.target.value)}
                        className="w-full text-[13px] text-[#24262B] bg-[#FAFAFB] border border-[#E8E9ED] rounded-md px-3 py-2 focus:outline-none focus:border-[#5876D8]"
                        placeholder="e.g. GitHub Production Workspace"
                      />
                    </div>

                    {/* Organization / Site */}
                    <div>
                      <label className="block text-[12px] font-semibold text-[#24262B] mb-1">
                        {selectedProvider.charAt(0).toUpperCase() + selectedProvider.slice(1)} organization
                      </label>
                      <input
                        type="text"
                        value={organization}
                        onChange={(e) => setOrganization(e.target.value)}
                        className="w-full text-[13px] text-[#24262B] bg-[#FAFAFB] border border-[#E8E9ED] rounded-md px-3 py-2 focus:outline-none focus:border-[#5876D8]"
                        placeholder="e.g. ABC Engineering"
                      />
                    </div>

                    {/* System Owner */}
                    <div>
                      <label className="block text-[12px] font-semibold text-[#24262B] mb-1">
                        System owner
                      </label>
                      <input
                        type="text"
                        value={owner}
                        onChange={(e) => setOwner(e.target.value)}
                        className="w-full text-[13px] text-[#24262B] bg-[#FAFAFB] border border-[#E8E9ED] rounded-md px-3 py-2 focus:outline-none focus:border-[#5876D8]"
                        placeholder="e.g. Engineering"
                      />
                    </div>

                    {/* Personal Access Token */}
                    <div>
                      <label className="block text-[12px] font-semibold text-[#24262B] mb-1">
                        Personal Access Token
                      </label>
                      <div className="relative">
                        <input
                          type={showToken ? 'text' : 'password'}
                          value={token}
                          onChange={(e) => setToken(e.target.value)}
                          className="w-full text-[13px] text-[#24262B] bg-[#FAFAFB] border border-[#E8E9ED] rounded-md pl-3 pr-10 py-2 focus:outline-none focus:border-[#5876D8] font-mono"
                          placeholder="••••••••••••••••••••••••••••"
                        />
                        <button
                          type="button"
                          onClick={() => setShowToken(!showToken)}
                          className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#8B8F98] hover:text-[#24262B] p-1"
                        >
                          {showToken ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                      <p className="text-[11px] text-[#8B8F98] mt-1 leading-normal">
                        Personal Access Token with read access (<code className="text-[#5876D8]">repo:read</code>, <code className="text-[#5876D8]">read:org</code>) to discover and analyze repositories.
                      </p>
                    </div>

                  {/* Direct Repository URL */}
                  <div className="pt-2 border-t border-[#F0F1F3] space-y-1.5">
                    <label className="block text-[12px] font-semibold text-[#24262B]">
                      Direct Repository URL <span className="text-[#8B8F98] font-normal">(Optional / Custom)</span>
                    </label>
                    <div className="relative">
                      <input
                        type="text"
                        value={directRepoUrl}
                        onChange={(e) => setDirectRepoUrl(e.target.value)}
                        placeholder="https://github.com/organization/repository"
                        className="w-full text-[12px] text-[#24262B] bg-[#FAFAFB] border border-[#E8E9ED] rounded-md pl-3 pr-24 py-2 focus:outline-hidden focus:border-[#5876D8] font-mono"
                      />
                      {directRepoUrl.trim() && (
                        <button
                          type="button"
                          onClick={() => {
                            const cleaned = directRepoUrl.trim().replace(/^https?:\/\/[^\/]+\//, '');
                            const name = cleaned || directRepoUrl.trim();
                            if (!selectedRepos.includes(name)) {
                              setSelectedRepos((prev) => [...prev, name]);
                              setRepoScope('selected');
                            }
                          }}
                          className="absolute right-1.5 top-1/2 -translate-y-1/2 px-2 py-1 bg-white border border-[#E8E9ED] hover:border-[#5876D8] text-[11px] font-medium text-[#5876D8] rounded shadow-2xs cursor-pointer"
                        >
                          + Add Repo
                        </button>
                      )}
                    </div>
                    <p className="text-[11px] text-[#8B8F98]">
                      Directly connect any specific public or private Git repository URL with this connection.
                    </p>
                  </div>

                  /* Repository Scope for Git Providers */
                  <div className="pt-2 border-t border-[#F0F1F3] space-y-3">
                    <div>
                      <label className="block text-[12px] font-semibold text-[#24262B] mb-2">
                        Repository scope
                      </label>
                      <div className="grid grid-cols-2 gap-2">
                        <button
                          type="button"
                          onClick={() => setRepoScope('all')}
                          className={`p-2.5 rounded-md border text-left text-[12px] font-medium transition-colors ${
                            repoScope === 'all'
                              ? 'border-[#5876D8] bg-[#EEF2FF] text-[#5876D8]'
                              : 'border-[#E8E9ED] bg-[#FAFAFB] text-[#666A73] hover:bg-[#F7F8FA]'
                          }`}
                        >
                          All repositories
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setRepoScope('selected');
                            if (!hasFetchedRepos) {
                              fetchAccessibleRepos();
                            }
                          }}
                          className={`p-2.5 rounded-md border text-left text-[12px] font-medium transition-colors ${
                            repoScope === 'selected'
                              ? 'border-[#5876D8] bg-[#EEF2FF] text-[#5876D8]'
                              : 'border-[#E8E9ED] bg-[#FAFAFB] text-[#666A73] hover:bg-[#F7F8FA]'
                          }`}
                        >
                          Selected repositories
                        </button>
                      </div>
                    </div>

                    {/* Multi-select Repository Picker */}
                    {repoScope === 'selected' && (
                      <div className="bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg p-3.5 space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-[12px] font-semibold text-[#24262B]">
                              Select Repositories to Monitor
                            </span>
                            <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-[#EEF2FF] text-[#5876D8] border border-[#C9D5FA]">
                              {selectedRepos.length} of {discoveredRepos.length || 5} selected
                            </span>
                          </div>
                          <button
                            type="button"
                            onClick={() => fetchAccessibleRepos()}
                            disabled={isDiscoveringRepos}
                            className="text-[11px] text-[#5876D8] hover:text-[#4965C5] font-medium flex items-center gap-1 cursor-pointer"
                          >
                            <RefreshCw className={`w-3 h-3 ${isDiscoveringRepos ? 'animate-spin' : ''}`} />
                            <span>{isDiscoveringRepos ? 'Fetching...' : 'Refresh'}</span>
                          </button>
                        </div>

                        {/* Search & Actions */}
                        <div className="flex items-center gap-2">
                          <div className="relative flex-1">
                            <Search className="w-3.5 h-3.5 text-[#8B8F98] absolute left-2.5 top-1/2 -translate-y-1/2" />
                            <input
                              type="text"
                              value={repoSearchQuery}
                              onChange={(e) => setRepoSearchQuery(e.target.value)}
                              placeholder="Filter repositories..."
                              className="w-full text-[12px] bg-white border border-[#E8E9ED] rounded-md pl-8 pr-3 py-1.5 focus:outline-none focus:border-[#5876D8]"
                            />
                          </div>
                          <button
                            type="button"
                            onClick={() => {
                              const reposToSelect = discoveredRepos.length > 0
                                ? discoveredRepos.map(r => r.full_name)
                                : [
                                    'mastermayhem-OP/symbiote',
                                    'mastermayhem-OP/ChatBot',
                                    'Vetri1706/support-ticket-classifier',
                                    'ms-lokesh/AR-Project',
                                    'ms-lokesh/Compliance'
                                  ];
                              setSelectedRepos(reposToSelect);
                            }}
                            className="text-[11px] font-medium px-2 py-1 bg-white border border-[#E8E9ED] hover:bg-[#FAFAFB] text-[#24262B] rounded shadow-2xs shrink-0 cursor-pointer"
                          >
                            Select all
                          </button>
                          <button
                            type="button"
                            onClick={() => setSelectedRepos([])}
                            className="text-[11px] font-medium px-2 py-1 bg-white border border-[#E8E9ED] hover:bg-[#FAFAFB] text-[#666A73] rounded shadow-2xs shrink-0 cursor-pointer"
                          >
                            Clear
                          </button>
                        </div>

                        {/* Repo items */}
                        <div className="max-h-48 overflow-y-auto space-y-1 pr-1 divide-y divide-[#F1F5F9] bg-white border border-[#E8E9ED] rounded-md p-1.5 shadow-2xs">
                          {isDiscoveringRepos ? (
                            <div className="py-6 text-center text-[#8B8F98] text-[12px] flex items-center justify-center gap-2">
                              <RefreshCw className="w-4 h-4 animate-spin text-[#5876D8]" />
                              <span>Discovering accessible repositories for your token...</span>
                            </div>
                          ) : (
                            (() => {
                              const list = (discoveredRepos.length > 0 ? discoveredRepos : [
                                { id: 101, name: 'symbiote', full_name: 'mastermayhem-OP/symbiote', private: false },
                                { id: 102, name: 'ChatBot', full_name: 'mastermayhem-OP/ChatBot', private: false },
                                { id: 103, name: 'support-ticket-classifier', full_name: 'Vetri1706/support-ticket-classifier', private: false },
                                { id: 104, name: 'AR-Project', full_name: 'ms-lokesh/AR-Project', private: false },
                                { id: 105, name: 'Compliance', full_name: 'ms-lokesh/Compliance', private: false },
                              ]).filter(r =>
                                r.full_name.toLowerCase().includes(repoSearchQuery.toLowerCase()) ||
                                r.name.toLowerCase().includes(repoSearchQuery.toLowerCase())
                              );

                              if (list.length === 0) {
                                return (
                                  <div className="py-4 text-center text-[#8B8F98] text-[12px]">
                                    No repositories found matching "{repoSearchQuery}"
                                  </div>
                                );
                              }

                              return list.map((repo) => {
                                const isChecked = selectedRepos.includes(repo.full_name);
                                return (
                                  <label
                                    key={repo.full_name}
                                    className={`flex items-center justify-between p-2 rounded-md cursor-pointer transition-colors ${
                                      isChecked ? 'bg-[#EEF2FF]/60 hover:bg-[#EEF2FF]' : 'hover:bg-[#FAFAFB]'
                                    }`}
                                  >
                                    <div className="flex items-center gap-2.5 min-w-0 pr-2">
                                      <input
                                        type="checkbox"
                                        checked={isChecked}
                                        onChange={(e) => {
                                          if (e.target.checked) {
                                            setSelectedRepos([...selectedRepos, repo.full_name]);
                                          } else {
                                            setSelectedRepos(selectedRepos.filter(r => r !== repo.full_name));
                                          }
                                        }}
                                        className="rounded text-[#5876D8] focus:ring-[#5876D8]"
                                      />
                                      <GitBranch className="w-3.5 h-3.5 text-[#5876D8] shrink-0" />
                                      <span className="text-[12px] font-medium text-[#24262B] truncate">
                                        {repo.full_name}
                                      </span>
                                    </div>
                                    <span className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-white border border-[#E2E8F0] text-[#64748B] shrink-0">
                                      {repo.private ? 'Private' : 'Public'}
                                    </span>
                                  </label>
                                );
                              });
                            })()
                          )}
                        </div>

                        {selectedRepos.length === 0 && (
                          <p className="text-[11px] text-[#D96B6B] flex items-center gap-1 font-medium">
                            <AlertCircle className="w-3.5 h-3.5" />
                            Please select at least one repository to monitor.
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}

                {/* Monitoring Checkboxes */}
                <div className="pt-2 border-t border-[#F0F1F3] space-y-2.5">
                  <label className="block text-[12px] font-semibold text-[#24262B]">
                    Monitoring
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={isContinuousMonitoring}
                      onChange={(e) => setIsContinuousMonitoring(e.target.checked)}
                      className="rounded text-[#5876D8] focus:ring-[#5876D8]"
                    />
                    <span className="text-[12px] text-[#24262B] font-medium">
                      Enable continuous monitoring
                    </span>
                  </label>

                  <div className="pl-5 space-y-2 border-l border-[#E8E9ED] ml-2">
                    {selectedProvider === 'jira' ? (
                      <>
                        <label className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={monitorPRs}
                            onChange={(e) => setMonitorPRs(e.target.checked)}
                            className="rounded text-[#5876D8] focus:ring-[#5876D8]"
                          />
                          <span className="text-[12px] text-[#666A73]">Monitor Change Requests (Issues)</span>
                        </label>
                        <label className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={monitorReviews}
                            onChange={(e) => setMonitorReviews(e.target.checked)}
                            className="rounded text-[#5876D8] focus:ring-[#5876D8]"
                          />
                          <span className="text-[12px] text-[#666A73]">Monitor CAB & Emergency Approvals</span>
                        </label>
                        <label className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={monitorCICD}
                            onChange={(e) => setMonitorCICD(e.target.checked)}
                            className="rounded text-[#5876D8] focus:ring-[#5876D8]"
                          />
                          <span className="text-[12px] text-[#666A73]">Track Maintenance Windows & Deployments</span>
                        </label>
                        <label className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={monitorDeployments}
                            onChange={(e) => setMonitorDeployments(e.target.checked)}
                            className="rounded text-[#5876D8] focus:ring-[#5876D8]"
                          />
                          <span className="text-[12px] text-[#666A73]">Auto-Correlate with VCS Pull Requests</span>
                        </label>
                      </>
                    ) : (
                      <>
                        <label className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={monitorPRs}
                            onChange={(e) => setMonitorPRs(e.target.checked)}
                            className="rounded text-[#5876D8] focus:ring-[#5876D8]"
                          />
                          <span className="text-[12px] text-[#666A73]">Monitor pull requests</span>
                        </label>
                        <label className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={monitorReviews}
                            onChange={(e) => setMonitorReviews(e.target.checked)}
                            className="rounded text-[#5876D8] focus:ring-[#5876D8]"
                          />
                          <span className="text-[12px] text-[#666A73]">Monitor reviews</span>
                        </label>
                        <label className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={monitorCICD}
                            onChange={(e) => setMonitorCICD(e.target.checked)}
                            className="rounded text-[#5876D8] focus:ring-[#5876D8]"
                          />
                          <span className="text-[12px] text-[#666A73]">Monitor CI/CD</span>
                        </label>
                        <label className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={monitorDeployments}
                            onChange={(e) => setMonitorDeployments(e.target.checked)}
                            className="rounded text-[#5876D8] focus:ring-[#5876D8]"
                          />
                          <span className="text-[12px] text-[#666A73]">Monitor deployments</span>
                        </label>
                      </>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Step 3: Testing State Spinner */}
            {step === 'testing' && (
              <div className="py-12 flex flex-col items-center justify-center text-center space-y-4">
                <RefreshCw className="w-8 h-8 text-[#5876D8] animate-spin" />
                <div>
                  <h4 className="text-[14px] font-semibold text-[#24262B]">
                    Connecting to {selectedProvider.charAt(0).toUpperCase() + selectedProvider.slice(1)}...
                  </h4>
                  <p className="text-[12px] text-[#8B8F98] mt-1">
                    Verifying API tokens, scopes, and discovery endpoints.
                  </p>
                </div>
              </div>
            )}

            {/* Step 4: Test Result State */}
            {step === 'test-result' && testResult && (
              <div className="space-y-4">
                {testResult.success ? (
                  <div className="space-y-4">
                    <div className="p-3.5 bg-[#EAF7EF] border border-[#C6EBD4] rounded-lg flex items-center gap-2.5">
                      <CheckCircle2 className="w-5 h-5 text-[#3FA76C] shrink-0" />
                      <div>
                        <h4 className="text-[13px] font-semibold text-[#24262B]">
                          Connection successful
                        </h4>
                        <p className="text-[11px] text-[#3FA76C]">
                          API authentication and repository scopes validated.
                        </p>
                      </div>
                    </div>

                    <div className="bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg p-4 space-y-2.5 text-[12px]">
                      <div className="flex justify-between py-1 border-b border-[#F0F1F3]">
                        <span className="text-[#666A73]">Organization</span>
                        <span className="font-semibold text-[#24262B]">{testResult.data?.organization}</span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-[#F0F1F3]">
                        <span className="text-[#666A73]">Repositories</span>
                        <span className="font-semibold text-[#24262B]">{testResult.data?.repositories}</span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-[#F0F1F3]">
                        <span className="text-[#666A73]">Pull requests</span>
                        <span className="font-semibold text-[#24262B]">{testResult.data?.pullRequests}</span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-[#F0F1F3]">
                        <span className="text-[#666A73]">Workflow access</span>
                        <span className="font-semibold text-[#3FA76C] flex items-center gap-1">
                          <Check className="w-3 h-3" /> {testResult.data?.workflowAccess}
                        </span>
                      </div>
                      <div className="flex justify-between py-1">
                        <span className="text-[#666A73]">Deployment access</span>
                        <span className="font-semibold text-[#3FA76C] flex items-center gap-1">
                          <Check className="w-3 h-3" /> {testResult.data?.deploymentAccess}
                        </span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="p-3.5 bg-[#FDEEEE] border border-[#F9CACA] rounded-lg flex items-start gap-2.5">
                      <AlertCircle className="w-5 h-5 text-[#D96B6B] shrink-0 mt-0.5" />
                      <div>
                        <h4 className="text-[13px] font-semibold text-[#24262B]">
                          Connection failed
                        </h4>
                        <p className="text-[12px] text-[#666A73] mt-0.5">
                          {testResult.error || 'Unable to connect using the provided configuration.'}
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Step 5: Saving & Initial Sync Progress */}
            {step === 'saving-sync' && (
              <div className="space-y-5 py-4">
                <h4 className="text-[14px] font-semibold text-[#24262B]">
                  Initial synchronization in progress
                </h4>
                <div className="space-y-3">
                  <div className="flex items-center gap-3 text-[13px]">
                    {syncStep >= 1 ? (
                      <CheckCircle2 className="w-4 h-4 text-[#3FA76C]" />
                    ) : (
                      <div className="w-4 h-4 rounded-full border border-[#D8DAE0]" />
                    )}
                    <span className={syncStep >= 1 ? 'text-[#24262B] font-medium' : 'text-[#8B8F98]'}>
                      Connection verified
                    </span>
                  </div>

                  <div className="flex items-center gap-3 text-[13px]">
                    {syncStep >= 2 ? (
                      <CheckCircle2 className="w-4 h-4 text-[#3FA76C]" />
                    ) : syncStep === 1 ? (
                      <RefreshCw className="w-4 h-4 text-[#5876D8] animate-spin" />
                    ) : (
                      <div className="w-4 h-4 rounded-full border border-[#D8DAE0]" />
                    )}
                    <span className={syncStep >= 2 ? 'text-[#24262B] font-medium' : 'text-[#8B8F98]'}>
                      Organization discovered
                    </span>
                  </div>

                  <div className="flex items-center gap-3 text-[13px]">
                    {syncStep >= 3 ? (
                      <CheckCircle2 className="w-4 h-4 text-[#3FA76C]" />
                    ) : syncStep === 2 ? (
                      <RefreshCw className="w-4 h-4 text-[#5876D8] animate-spin" />
                    ) : (
                      <div className="w-4 h-4 rounded-full border border-[#D8DAE0]" />
                    )}
                    <span className={syncStep >= 3 ? 'text-[#24262B] font-medium' : 'text-[#8B8F98]'}>
                      Synchronizing repositories
                    </span>
                  </div>

                  <div className="flex items-center gap-3 text-[13px]">
                    {syncStep >= 4 ? (
                      <CheckCircle2 className="w-4 h-4 text-[#3FA76C]" />
                    ) : syncStep === 3 ? (
                      <RefreshCw className="w-4 h-4 text-[#5876D8] animate-spin" />
                    ) : (
                      <div className="w-4 h-4 rounded-full border border-[#D8DAE0]" />
                    )}
                    <span className={syncStep >= 4 ? 'text-[#24262B] font-medium' : 'text-[#8B8F98]'}>
                      Enabling monitoring
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Step 6: Complete State */}
            {step === 'complete' && (
              <div className="py-8 text-center space-y-4">
                <div className="w-12 h-12 rounded-full bg-[#EAF7EF] border border-[#C6EBD4] text-[#3FA76C] mx-auto flex items-center justify-center">
                  <Check className="w-6 h-6" />
                </div>
                <div>
                  <h4 className="text-[16px] font-semibold text-[#24262B]">
                    {connectionName} monitoring is active
                  </h4>
                  <p className="text-[12px] text-[#666A73] max-w-xs mx-auto mt-1">
                    Continuous change controls and pull request auditing are now synchronized.
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* Drawer Footer */}
          <div className="px-6 py-4 bg-[#FAFAFB] border-t border-[#E8E9ED] flex items-center justify-end gap-2.5">
            {step === 'select-provider' && (
              <button
                onClick={handleResetAndClose}
                className="px-3.5 py-1.5 text-[13px] font-medium text-[#666A73] hover:text-[#24262B] bg-white border border-[#E8E9ED] rounded-md hover:bg-[#F7F8FA] transition-colors"
              >
                Cancel
              </button>
            )}

            {step === 'configure' && (
              <>
                <button
                  onClick={() => setStep('select-provider')}
                  className="px-3.5 py-1.5 text-[13px] font-medium text-[#666A73] hover:text-[#24262B] bg-white border border-[#E8E9ED] rounded-md hover:bg-[#F7F8FA] transition-colors"
                >
                  Cancel
                </button>
                {selectedProvider === 'jira' ? (
                  <button
                    id="btn-authorize-jira-footer"
                    onClick={async () => {
                      try {
                        const res = await integrationService.startJiraOAuth();
                        if (res.authorization_url) {
                          window.location.href = res.authorization_url;
                        }
                      } catch (e: any) {
                        alert(e?.message || 'Failed to initialize Jira OAuth.');
                      }
                    }}
                    className="px-4 py-1.5 text-[13px] font-semibold text-white bg-[#5876D8] hover:bg-[#4965C5] rounded-md shadow-xs transition-colors flex items-center gap-1.5 cursor-pointer"
                  >
                    <span>Authorize with Atlassian</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                ) : (
                  <>
                    <button
                      id="btn-test-connection"
                      onClick={handleTestConnection}
                      className="px-3.5 py-1.5 text-[13px] font-medium text-[#5876D8] bg-white border border-[#5876D8] hover:bg-[#EEF2FF] rounded-md transition-colors"
                    >
                      Test connection
                    </button>
                    <button
                      id="btn-save-start-monitoring"
                      onClick={handleSaveAndStart}
                      className="px-3.5 py-1.5 text-[13px] font-medium text-white bg-[#5876D8] hover:bg-[#4965C5] rounded-md shadow-xs transition-colors"
                    >
                      Save & start monitoring
                    </button>
                  </>
                )}
              </>
            )}

            {step === 'test-result' && (
              <>
                {testResult?.success ? (
                  <>
                    <button
                      onClick={() => setStep('configure')}
                      className="px-3.5 py-1.5 text-[13px] font-medium text-[#666A73] hover:text-[#24262B] bg-white border border-[#E8E9ED] rounded-md hover:bg-[#F7F8FA] transition-colors"
                    >
                      Back
                    </button>
                    <button
                      id="btn-test-continue"
                      onClick={handleSaveAndStart}
                      className="px-3.5 py-1.5 text-[13px] font-medium text-white bg-[#5876D8] hover:bg-[#4965C5] rounded-md shadow-xs transition-colors"
                    >
                      Save & start monitoring
                    </button>
                  </>
                ) : (
                  <>
                    <button
                      onClick={() => setStep('configure')}
                      className="px-3.5 py-1.5 text-[13px] font-medium text-[#666A73] hover:text-[#24262B] bg-white border border-[#E8E9ED] rounded-md hover:bg-[#F7F8FA] transition-colors"
                    >
                      Cancel
                    </button>
                    <button
                      id="btn-test-retry"
                      onClick={handleTestConnection}
                      className="px-3.5 py-1.5 text-[13px] font-medium text-white bg-[#5876D8] hover:bg-[#4965C5] rounded-md shadow-xs transition-colors"
                    >
                      Try again
                    </button>
                  </>
                )}
              </>
            )}

            {step === 'complete' && (
              <button
                id="btn-view-system-complete"
                onClick={() => {
                  onSystemCreated(createdSystemId, connectionName);
                  handleResetAndClose();
                }}
                className="w-full px-4 py-2 text-[13px] font-medium text-white bg-[#5876D8] hover:bg-[#4965C5] rounded-md shadow-xs transition-colors"
              >
                View system
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

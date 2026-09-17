import React, { useState } from 'react';
import { 
  X, GitBranch, ExternalLink, GitCommit, GitPullRequest, 
  Terminal, ShieldCheck, ShieldAlert, CheckCircle2, AlertTriangle, 
  Clock, ArrowUpRight, Search 
} from 'lucide-react';
import { Repository, PullRequest, Pipeline } from '../types';

interface RepoChange {
  change_id: string;
  title: string;
  application_id?: string;
  compliance_status?: string;
  status?: string;
  requester_id?: string;
  implemented_at?: string;
  findings_count?: number;
}

interface RepoDetailsModalProps {
  repo: Repository | null;
  isOpen: boolean;
  onClose: () => void;
  pullRequests: PullRequest[];
  pipelines: Pipeline[];
  changes?: RepoChange[];
}

export const RepoDetailsModal: React.FC<RepoDetailsModalProps> = ({
  repo,
  isOpen,
  onClose,
  pullRequests,
  pipelines,
  changes = [],
}) => {
  const [activeTab, setActiveTab] = useState<'changes' | 'prs' | 'cicd' | 'gates'>('changes');
  const [searchFilter, setSearchFilter] = useState('');

  if (!isOpen || !repo) return null;

  // Filter repository specific data
  const repoPRs = pullRequests.filter((pr) => pr.repoName === repo.name);
  const repoPipelines = pipelines.filter((p) => p.repoName === repo.name);
  const repoChanges = changes.filter(
    (c) => c.application_id === repo.name || (!c.application_id && repo.name.includes('symbiote'))
  );

  const filteredChanges = repoChanges.filter(
    (c) =>
      c.title?.toLowerCase().includes(searchFilter.toLowerCase()) ||
      c.change_id?.toLowerCase().includes(searchFilter.toLowerCase())
  );

  const isGatesCompliant =
    repo.branchProtectionEnforced &&
    !repo.allowAdminBypass &&
    repo.requireStatusChecks &&
    repo.requireReviewersCount > 0;

  return (
    <div className="fixed inset-0 z-60 overflow-y-auto">
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/40 backdrop-blur-xs transition-opacity" onClick={onClose} />

      <div className="flex min-h-full items-center justify-center p-4 text-center sm:p-0">
        <div className="relative transform overflow-hidden rounded-xl bg-white text-left shadow-2xl transition-all sm:my-8 sm:w-full sm:max-w-4xl border border-[#E8E9ED] select-text">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-[#E8E9ED] px-6 py-4 bg-[#FAFAFB]">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-[#EEF2FF] border border-[#C9D5FA] text-[#5876D8] flex items-center justify-center">
                <GitBranch className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-[16px] font-bold text-[#24262B] font-mono">
                    {repo.name}
                  </h3>
                  <span className="px-2 py-0.5 rounded-full text-[11px] font-medium bg-[#EAF7EF] text-[#3FA76C] border border-[#C2E9D1] flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#3FA76C]" /> Active Monitored
                  </span>
                </div>
                <div className="flex items-center gap-3 text-[12px] text-[#8B8F98] mt-0.5 font-mono">
                  <span>Default branch: <b>{repo.defaultBranch}</b></span>
                  <span>•</span>
                  <span>Last Activity: <b>{repo.lastActivity}</b></span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <a
                href={`https://github.com/${repo.name}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-[#5876D8] hover:text-[#4A67C4] hover:bg-[#EEF2FF] rounded-lg border border-[#C9D5FA] transition-colors"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                View on GitHub
              </a>
              <button
                onClick={onClose}
                className="p-1.5 rounded-md text-[#8B8F98] hover:text-[#24262B] hover:bg-gray-100 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Metrics summary ribbon */}
          <div className="grid grid-cols-4 border-b border-[#E8E9ED] bg-white divide-x divide-[#E8E9ED] text-center py-3 text-[12px]">
            <div>
              <span className="text-[#8B8F98] block">Ingested Changes</span>
              <span className="text-[16px] font-bold text-[#24262B]">{repo.changesCount || repoChanges.length || 0}</span>
            </div>
            <div>
              <span className="text-[#8B8F98] block">Pull Requests</span>
              <span className="text-[16px] font-bold text-[#24262B]">{repo.pullRequestsCount || repoPRs.length || 0}</span>
            </div>
            <div>
              <span className="text-[#8B8F98] block">CI/CD Pipelines</span>
              <span className="text-[16px] font-bold text-[#24262B]">{repoPipelines.length}</span>
            </div>
            <div>
              <span className="text-[#8B8F98] block">Branch Gate Status</span>
              <span className={`text-[13px] font-bold inline-flex items-center gap-1 mt-0.5 ${
                isGatesCompliant ? 'text-[#3FA76C]' : 'text-[#D96B6B]'
              }`}>
                {isGatesCompliant ? <ShieldCheck className="w-3.5 h-3.5" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                {isGatesCompliant ? 'Compliant' : 'Review Required'}
              </span>
            </div>
          </div>

          {/* Sub Navigation Tabs */}
          <div className="flex items-center space-x-2 border-b border-[#E8E9ED] px-6 pt-3 bg-[#FAFAFB]">
            <button
              onClick={() => setActiveTab('changes')}
              className={`pb-2.5 px-3 text-[13px] font-medium border-b-2 transition-all flex items-center gap-1.5 ${
                activeTab === 'changes'
                  ? 'border-[#5876D8] text-[#5876D8]'
                  : 'border-transparent text-[#666A73] hover:text-[#24262B]'
              }`}
            >
              <GitCommit className="w-3.5 h-3.5" />
              Changes & Commits ({repo.changesCount || repoChanges.length || 0})
            </button>
            <button
              onClick={() => setActiveTab('prs')}
              className={`pb-2.5 px-3 text-[13px] font-medium border-b-2 transition-all flex items-center gap-1.5 ${
                activeTab === 'prs'
                  ? 'border-[#5876D8] text-[#5876D8]'
                  : 'border-transparent text-[#666A73] hover:text-[#24262B]'
              }`}
            >
              <GitPullRequest className="w-3.5 h-3.5" />
              Pull Requests ({repoPRs.length})
            </button>
            <button
              onClick={() => setActiveTab('cicd')}
              className={`pb-2.5 px-3 text-[13px] font-medium border-b-2 transition-all flex items-center gap-1.5 ${
                activeTab === 'cicd'
                  ? 'border-[#5876D8] text-[#5876D8]'
                  : 'border-transparent text-[#666A73] hover:text-[#24262B]'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              CI/CD Pipelines ({repoPipelines.length})
            </button>
            <button
              onClick={() => setActiveTab('gates')}
              className={`pb-2.5 px-3 text-[13px] font-medium border-b-2 transition-all flex items-center gap-1.5 ${
                activeTab === 'gates'
                  ? 'border-[#5876D8] text-[#5876D8]'
                  : 'border-transparent text-[#666A73] hover:text-[#24262B]'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              Branch Protection Rules
            </button>
          </div>

          {/* Tab Content Body */}
          <div className="p-6 max-h-[480px] overflow-y-auto">
            {/* 1. CHANGES TAB */}
            {activeTab === 'changes' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="relative w-72">
                    <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[#8B8F98]" />
                    <input
                      type="text"
                      placeholder="Search commits or change IDs..."
                      value={searchFilter}
                      onChange={(e) => setSearchFilter(e.target.value)}
                      className="w-full pl-8 pr-3 py-1.5 text-[12px] border border-[#E8E9ED] rounded-lg focus:outline-none focus:border-[#5876D8] bg-[#FAFAFB]"
                    />
                  </div>
                  <span className="text-[12px] text-[#8B8F98]">
                    Showing {filteredChanges.length} changes
                  </span>
                </div>

                {filteredChanges.length > 0 ? (
                  <div className="border border-[#E8E9ED] rounded-lg overflow-hidden divide-y divide-[#F0F1F3]">
                    {filteredChanges.map((chg) => (
                      <div key={chg.change_id} className="p-3 hover:bg-[#FAFAFB] transition-colors flex items-center justify-between">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-[11px] font-semibold text-[#5876D8] bg-[#EEF2FF] px-1.5 py-0.5 rounded border border-[#C9D5FA]">
                              {chg.change_id.replace('chg-com-', '').substring(0, 8)}
                            </span>
                            <span className="font-medium text-[13px] text-[#24262B]">
                              {chg.title}
                            </span>
                          </div>
                          <div className="flex items-center gap-3 text-[11px] text-[#8B8F98]">
                            <span>Author: <b>{chg.requester_id || 'Developer'}</b></span>
                            <span>•</span>
                            <span>{chg.implemented_at ? new Date(chg.implemented_at).toLocaleDateString() : 'Recent'}</span>
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          {chg.compliance_status === 'COMPLIANT' || chg.compliance_status === 'APPROVED' ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-[#EAF7EF] text-[#3FA76C]">
                              <CheckCircle2 className="w-3 h-3" /> Compliant
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-[#FFF7E6] text-[#C99532]">
                              <AlertTriangle className="w-3 h-3" /> {chg.compliance_status || 'Review'}
                            </span>
                          )}
                          <a
                            href={`https://github.com/${repo.name}/commit/${chg.change_id.replace('chg-com-', '')}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="p-1 text-[#8B8F98] hover:text-[#5876D8]"
                          >
                            <ArrowUpRight className="w-4 h-4" />
                          </a>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-8 text-center border border-dashed border-[#E8E9ED] rounded-lg">
                    <GitCommit className="w-8 h-8 text-[#8B8F98] mx-auto mb-2 opacity-50" />
                    <p className="text-[13px] font-medium text-[#24262B]">No commits ingested yet</p>
                    <p className="text-[12px] text-[#8B8F98] mt-0.5">Push changes to this repository or trigger sync.</p>
                  </div>
                )}
              </div>
            )}

            {/* 2. PULL REQUESTS TAB */}
            {activeTab === 'prs' && (
              <div className="space-y-3">
                {repoPRs.length > 0 ? (
                  <div className="border border-[#E8E9ED] rounded-lg overflow-hidden divide-y divide-[#F0F1F3]">
                    {repoPRs.map((pr) => (
                      <div key={pr.id} className="p-3 hover:bg-[#FAFAFB] transition-colors flex items-center justify-between">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-[12px] font-bold text-[#5876D8]">
                              {pr.prNumber}
                            </span>
                            <span className="font-medium text-[13px] text-[#24262B]">
                              {pr.title}
                            </span>
                          </div>
                          <div className="flex items-center gap-3 text-[11px] text-[#8B8F98]">
                            <span>Author: <b>{pr.author}</b></span>
                            <span>•</span>
                            <span>Reviewers: <b>{pr.reviewers?.length ? pr.reviewers.join(', ') : '0'}</b></span>
                            <span>•</span>
                            <span>Updated: {pr.updatedTime}</span>
                          </div>
                        </div>

                        <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold ${
                          pr.approvalStatus === 'Approved' 
                            ? 'bg-[#EAF7EF] text-[#3FA76C]' 
                            : 'bg-[#FFF7E6] text-[#C99532]'
                        }`}>
                          {pr.approvalStatus}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-8 text-center border border-dashed border-[#E8E9ED] rounded-lg">
                    <GitPullRequest className="w-8 h-8 text-[#8B8F98] mx-auto mb-2 opacity-50" />
                    <p className="text-[13px] font-medium text-[#24262B]">0 Pull Requests found</p>
                    <p className="text-[12px] text-[#8B8F98] mt-0.5">No open or merged PRs recorded for this repository.</p>
                  </div>
                )}
              </div>
            )}

            {/* 3. CI/CD PIPELINES TAB */}
            {activeTab === 'cicd' && (
              <div className="space-y-3">
                {repoPipelines.length > 0 ? (
                  <div className="border border-[#E8E9ED] rounded-lg overflow-hidden divide-y divide-[#F0F1F3]">
                    {repoPipelines.map((pipe) => (
                      <div key={pipe.id} className="p-3 hover:bg-[#FAFAFB] transition-colors flex items-center justify-between">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-semibold text-[13px] text-[#24262B]">
                              {pipe.pipelineId}
                            </span>
                            <span className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-[#FAFAFB] border border-[#E8E9ED] text-[#666A73]">
                              {pipe.deploymentEnv}
                            </span>
                          </div>
                          <div className="flex items-center gap-3 text-[11px] text-[#8B8F98] font-mono">
                            <span>Commit: <b>{pipe.commitSha}</b></span>
                            <span>•</span>
                            <span>{pipe.testsSummary}</span>
                            <span>•</span>
                            <span>{pipe.completedTime}</span>
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold ${
                            pipe.status === 'PASS' 
                              ? 'bg-[#EAF7EF] text-[#3FA76C]' 
                              : 'bg-[#FDEEEE] text-[#D96B6B]'
                          }`}>
                            {pipe.status === 'PASS' ? '✓ PASS' : '✕ FAIL'}
                          </span>
                          {pipe.htmlUrl && (
                            <a
                              href={pipe.htmlUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="p-1 text-[#8B8F98] hover:text-[#5876D8]"
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                            </a>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-8 text-center border border-dashed border-[#E8E9ED] rounded-lg">
                    <Terminal className="w-8 h-8 text-[#8B8F98] mx-auto mb-2 opacity-50" />
                    <p className="text-[13px] font-medium text-[#24262B]">No CI/CD pipeline runs found</p>
                    <p className="text-[12px] text-[#8B8F98] mt-0.5">GitHub Actions workflows have not triggered on this repository.</p>
                  </div>
                )}
              </div>
            )}

            {/* 4. BRANCH GATES TAB */}
            {activeTab === 'gates' && (
              <div className="space-y-3 text-[13px]">
                <div className="p-3.5 rounded-lg border border-[#E8E9ED] bg-[#FAFAFB] flex items-center justify-between">
                  <div>
                    <div className="font-semibold text-[#24262B]">Admin Bypass Lock (SOC 2 CC8.1)</div>
                    <div className="text-[11px] text-[#8B8F98]">Prevents repo admins from pushing unapproved changes directly to {repo.defaultBranch}.</div>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                    !repo.allowAdminBypass ? 'bg-[#EAF7EF] text-[#3FA76C]' : 'bg-[#FDEEEE] text-[#D96B6B]'
                  }`}>
                    {!repo.allowAdminBypass ? 'PROHIBITED (PASS)' : 'ALLOWED (BREACH)'}
                  </span>
                </div>

                <div className="p-3.5 rounded-lg border border-[#E8E9ED] bg-[#FAFAFB] flex items-center justify-between">
                  <div>
                    <div className="font-semibold text-[#24262B]">Mandatory Peer Review Approvals</div>
                    <div className="text-[11px] text-[#8B8F98]">Requires at least 1 independent engineer to review and approve pull requests.</div>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                    repo.requireReviewersCount > 0 ? 'bg-[#EAF7EF] text-[#3FA76C]' : 'bg-[#FFF7E6] text-[#C99532]'
                  }`}>
                    {repo.requireReviewersCount > 0 ? `${repo.requireReviewersCount} Approved` : '0 Required (Gap)'}
                  </span>
                </div>

                <div className="p-3.5 rounded-lg border border-[#E8E9ED] bg-[#FAFAFB] flex items-center justify-between">
                  <div>
                    <div className="font-semibold text-[#24262B]">Automated CI/CD Status Checks</div>
                    <div className="text-[11px] text-[#8B8F98]">Requires automated test suites and linters to succeed prior to merge.</div>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                    repo.requireStatusChecks ? 'bg-[#EAF7EF] text-[#3FA76C]' : 'bg-[#FFF7E6] text-[#C99532]'
                  }`}>
                    {repo.requireStatusChecks ? 'Strict Passing' : 'Optional (Gap)'}
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between border-t border-[#E8E9ED] px-6 py-4 bg-[#FAFAFB]">
            <span className="text-[12px] text-[#8B8F98] font-mono">
              Repository ID: {repo.id}
            </span>
            <button
              onClick={onClose}
              className="px-4 py-2 text-[12px] font-medium text-[#666A73] hover:text-[#24262B] bg-white border border-[#E8E9ED] rounded-lg hover:bg-gray-50 transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

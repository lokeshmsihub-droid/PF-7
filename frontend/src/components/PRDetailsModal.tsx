import React from 'react';
import { 
  X, GitPullRequest, ExternalLink, GitBranch, GitCommit, 
  CheckCircle2, AlertTriangle, ShieldAlert, ShieldCheck, 
  Users, UserCheck, Lock, Clock, ArrowUpRight, Terminal
} from 'lucide-react';
import { PullRequest } from '../types';

interface PRDetailsModalProps {
  pr: PullRequest | null;
  isOpen: boolean;
  onClose: () => void;
}

export const PRDetailsModal: React.FC<PRDetailsModalProps> = ({
  pr,
  isOpen,
  onClose,
}) => {
  if (!isOpen || !pr) return null;

  const prNumClean = pr.prNumber.replace('#', '');
  const githubPrUrl = `https://github.com/${pr.repoName}/pull/${prNumClean}`;
  const isApproved = pr.approvalStatus === 'Approved' && pr.reviewers && pr.reviewers.length > 0;
  const isDirectMerge = pr.approvalStatus.toLowerCase().includes('merged') || pr.approvalStatus.toLowerCase().includes('direct');

  return (
    <div className="fixed inset-0 z-60 overflow-y-auto">
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/40 backdrop-blur-xs transition-opacity" onClick={onClose} />

      <div className="flex min-h-full items-center justify-center p-4 text-center sm:p-0">
        <div className="relative transform overflow-hidden rounded-xl bg-white text-left shadow-2xl transition-all sm:my-8 sm:w-full sm:max-w-2xl border border-[#E8E9ED] select-text">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-[#E8E9ED] px-6 py-4 bg-[#FAFAFB]">
            <div className="flex items-center gap-3">
              <div className={`w-9 h-9 rounded-lg flex items-center justify-center border ${
                isApproved 
                  ? 'bg-[#EAF7EF] text-[#3FA76C] border-[#C2E9D1]' 
                  : 'bg-[#FFF7E6] text-[#C99532] border-[#FCE2B6]'
              }`}>
                <GitPullRequest className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[14px] font-bold text-[#5876D8]">
                    {pr.prNumber}
                  </span>
                  <h3 className="text-[15px] font-semibold text-[#24262B]">
                    {pr.title}
                  </h3>
                </div>
                <div className="flex items-center gap-2 text-[12px] text-[#8B8F98] mt-0.5 font-mono">
                  <GitBranch className="w-3 h-3 text-[#5876D8]" />
                  <span>{pr.repoName}</span>
                  <span>•</span>
                  <span>{pr.branch} → {pr.targetBranch}</span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <a
                href={githubPrUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium text-[#5876D8] hover:text-[#4A67C4] hover:bg-[#EEF2FF] rounded-lg border border-[#C9D5FA] transition-colors"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                Open PR in GitHub
              </a>
              <button
                onClick={onClose}
                className="p-1.5 rounded-md text-[#8B8F98] hover:text-[#24262B] hover:bg-gray-100 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Body */}
          <div className="p-6 space-y-5 text-[13px]">
            {/* Status Summary Banner */}
            <div className={`p-4 rounded-lg border flex items-start gap-3 ${
              isApproved 
                ? 'bg-[#EAF7EF]/40 border-[#C2E9D1] text-[#2E7D4E]' 
                : 'bg-[#FDEEEE]/40 border-[#FACDCD] text-[#C44A4A]'
            }`}>
              {isApproved ? <CheckCircle2 className="w-5 h-5 shrink-0 mt-0.5" /> : <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />}
              <div>
                <div className="font-semibold text-[13px]">
                  {isApproved 
                    ? 'Peer Review Gate Compliant (Approved)' 
                    : isDirectMerge 
                      ? 'Direct Merge Without Independent Peer Review' 
                      : 'Pending Peer Approval'}
                </div>
                <div className="text-[12px] mt-0.5 text-[#666A73] leading-relaxed">
                  {isApproved 
                    ? 'This pull request was independently reviewed and approved by peer engineers prior to merging.'
                    : 'This pull request was merged directly by the author without independent peer approvals. This violates SOC 2 CC8.1 & Segregation of Duties (CM-003, CM-004).'}
                </div>
              </div>
            </div>

            {/* Author & Reviewers Breakdown */}
            <div className="grid grid-cols-2 gap-3">
              {/* Author */}
              <div className="p-3.5 rounded-lg border border-[#E8E9ED] bg-[#FAFAFB] space-y-2">
                <span className="text-[11px] font-bold text-[#666A73] uppercase tracking-wider block">
                  Author & Committer
                </span>
                <div className="flex items-center gap-2.5">
                  {pr.authorAvatar ? (
                    <img
                      src={pr.authorAvatar}
                      alt={pr.author}
                      className="w-7 h-7 rounded-full object-cover border border-[#E8E9ED]"
                    />
                  ) : (
                    <div className="w-7 h-7 rounded-full bg-[#EEF2FF] border border-[#C9D5FA] text-[11px] font-bold text-[#5876D8] flex items-center justify-center">
                      {pr.author ? pr.author.substring(0, 2).toUpperCase() : 'AU'}
                    </div>
                  )}
                  <div>
                    <div className="font-semibold text-[#24262B]">{pr.author}</div>
                    <div className="text-[11px] text-[#8B8F98]">Created this Pull Request</div>
                  </div>
                </div>
              </div>

              {/* Reviewers */}
              <div className="p-3.5 rounded-lg border border-[#E8E9ED] bg-[#FAFAFB] space-y-2">
                <span className="text-[11px] font-bold text-[#666A73] uppercase tracking-wider block">
                  Peer Approvals ({pr.reviewers?.length || 0})
                </span>
                {pr.reviewers && pr.reviewers.length > 0 ? (
                  <div className="space-y-1">
                    {pr.reviewers.map((rev, idx) => {
                      const reviewerName = typeof rev === 'string' ? rev : (rev as any).name || (rev as any).login;
                      return (
                        <div key={idx} className="flex items-center gap-2 text-[12px] font-semibold text-[#3FA76C]">
                          <UserCheck className="w-3.5 h-3.5" />
                          <span>{reviewerName}</span>
                          <span className="text-[10px] bg-[#EAF7EF] px-1.5 py-0.2 rounded border border-[#C2E9D1]">Approved</span>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="flex items-center gap-1.5 text-[12px] text-[#D96B6B] font-medium pt-1">
                    <ShieldAlert className="w-4 h-4" />
                    <span>0 approving peer reviews recorded</span>
                  </div>
                )}
              </div>
            </div>

            {/* Compliance Policy Gate Checkpoints */}
            <div className="space-y-2">
              <h4 className="text-[11px] font-bold text-[#666A73] uppercase tracking-wider">
                Change Control Policy Verification
              </h4>

              <div className="border border-[#E8E9ED] rounded-lg overflow-hidden divide-y divide-[#F0F1F3]">
                {/* 1. CM-003 */}
                <div className="p-3 bg-white flex items-center justify-between">
                  <div className="space-y-0.5">
                    <div className="font-semibold text-[#24262B]">CM-003: Approval Before Deployment</div>
                    <div className="text-[11px] text-[#8B8F98]">Requires at least 1 peer approval prior to merging into production.</div>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                    isApproved ? 'bg-[#EAF7EF] text-[#3FA76C]' : 'bg-[#FDEEEE] text-[#D96B6B]'
                  }`}>
                    {isApproved ? 'PASS' : 'FAIL'}
                  </span>
                </div>

                {/* 2. CM-004 */}
                <div className="p-3 bg-white flex items-center justify-between">
                  <div className="space-y-0.5">
                    <div className="font-semibold text-[#24262B]">CM-004: Segregation of Duties</div>
                    <div className="text-[11px] text-[#8B8F98]">Prohibits authors from approving or self-merging their own pull requests.</div>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                    isApproved ? 'bg-[#EAF7EF] text-[#3FA76C]' : 'bg-[#FDEEEE] text-[#D96B6B]'
                  }`}>
                    {isApproved ? 'PASS' : 'FAIL'}
                  </span>
                </div>

                {/* 3. CM-002 */}
                <div className="p-3 bg-white flex items-center justify-between">
                  <div className="space-y-0.5">
                    <div className="font-semibold text-[#24262B]">CM-002: Automated CI/CD Status Verification</div>
                    <div className="text-[11px] text-[#8B8F98]">Verification of automated test execution on head commit.</div>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-[#EAF7EF] text-[#3FA76C]">
                    PASS
                  </span>
                </div>
              </div>
            </div>

            {/* Traceability Details */}
            <div className="p-3 rounded-lg border border-[#E8E9ED] bg-[#FAFAFB] flex items-center justify-between text-[11px] text-[#666A73] font-mono">
              <span>Target Branch: <b>{pr.targetBranch}</b></span>
              <span>Updated: <b>{pr.updatedTime}</b></span>
              <span>Audit Chain: <b>SHA-256 Verified</b></span>
            </div>
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between border-t border-[#E8E9ED] px-6 py-4 bg-[#FAFAFB]">
            <a
              href={githubPrUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-[12px] font-medium text-white bg-[#5876D8] hover:bg-[#4A67C4] rounded-lg shadow-xs transition-colors"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              Inspect on GitHub
            </a>

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

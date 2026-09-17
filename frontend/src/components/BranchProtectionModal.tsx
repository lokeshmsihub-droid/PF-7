import React from 'react';
import { ShieldAlert, ShieldCheck, CheckCircle2, AlertTriangle, ExternalLink, X, RefreshCw, GitBranch, Lock, Users, Terminal } from 'lucide-react';
import { Repository } from '../types';

interface BranchProtectionModalProps {
  repo: Repository | null;
  isOpen: boolean;
  onClose: () => void;
  onRecheck?: () => void;
}

export const BranchProtectionModal: React.FC<BranchProtectionModalProps> = ({
  repo,
  isOpen,
  onClose,
  onRecheck,
}) => {
  if (!isOpen || !repo) return null;

  const isCompliant = repo.branchProtectionEnforced && !repo.allowAdminBypass && repo.requireStatusChecks && repo.requireReviewersCount > 0;
  const githubSettingsUrl = `https://github.com/${repo.name}/settings/branches`;

  return (
    <div className="fixed inset-0 z-60 overflow-y-auto">
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/40 backdrop-blur-xs transition-opacity" onClick={onClose} />

      <div className="flex min-h-full items-center justify-center p-4 text-center sm:p-0">
        <div className="relative transform overflow-hidden rounded-xl bg-white text-left shadow-2xl transition-all sm:my-8 sm:w-full sm:max-w-xl border border-[#E8E9ED] select-text">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-[#E8E9ED] px-6 py-4 bg-[#FAFAFB]">
            <div className="flex items-center gap-2.5">
              <div className={`w-8 h-8 rounded-lg flex items-center justify-center border ${
                isCompliant 
                  ? 'bg-[#EAF7EF] text-[#3FA76C] border-[#C2E9D1]' 
                  : 'bg-[#FDEEEE] text-[#D96B6B] border-[#FACDCD]'
              }`}>
                {isCompliant ? <ShieldCheck className="w-4 h-4" /> : <ShieldAlert className="w-4 h-4" />}
              </div>
              <div>
                <h3 className="text-[15px] font-semibold text-[#24262B]">
                  Branch Gate Analysis & Rules
                </h3>
                <span className="text-[12px] text-[#8B8F98] font-mono flex items-center gap-1">
                  <GitBranch className="w-3 h-3 text-[#5876D8]" />
                  {repo.name} ({repo.defaultBranch})
                </span>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-1 rounded-md text-[#8B8F98] hover:text-[#24262B] hover:bg-gray-100 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Body */}
          <div className="p-6 space-y-4 text-[13px]">
            {/* Status Banner */}
            <div className={`p-3.5 rounded-lg border flex items-start gap-3 ${
              isCompliant 
                ? 'bg-[#EAF7EF]/40 border-[#C2E9D1] text-[#2E7D4E]' 
                : 'bg-[#FDEEEE]/40 border-[#FACDCD] text-[#C44A4A]'
            }`}>
              {isCompliant ? <CheckCircle2 className="w-5 h-5 shrink-0 mt-0.5" /> : <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />}
              <div>
                <div className="font-semibold text-[13px]">
                  {isCompliant ? 'Branch Protection Rules Enforced' : 'Branch Gate Policy Gaps Detected'}
                </div>
                <div className="text-[12px] mt-0.5 text-[#666A73]">
                  {isCompliant 
                    ? 'All required change control gates (peer reviews, CI status checks, and admin bypass lock) are verified compliant.'
                    : 'The target branch does not meet the minimum SOC 2 / ISO 27001 change management controls.'}
                </div>
              </div>
            </div>

            {/* Checklist of Gates */}
            <div className="space-y-2.5">
              <h4 className="text-[11px] font-bold text-[#666A73] uppercase tracking-wider">
                Enforced Controls Breakdown
              </h4>

              {/* 1. Admin Bypass */}
              <div className="p-3 rounded-lg border border-[#E8E9ED] bg-[#FAFAFB] flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <Lock className="w-4 h-4 text-[#5876D8]" />
                  <div>
                    <div className="font-semibold text-[#24262B]">Admin Bypass Lock</div>
                    <div className="text-[11px] text-[#8B8F98]">
                      Prevents administrators from overriding branch protections without review.
                    </div>
                  </div>
                </div>
                <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                  !repo.allowAdminBypass 
                    ? 'bg-[#EAF7EF] text-[#3FA76C]' 
                    : 'bg-[#FDEEEE] text-[#D96B6B]'
                }`}>
                  {!repo.allowAdminBypass ? 'PROHIBITED (PASS)' : 'ALLOWED (BREACH)'}
                </span>
              </div>

              {/* 2. Peer Reviewers */}
              <div className="p-3 rounded-lg border border-[#E8E9ED] bg-[#FAFAFB] flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <Users className="w-4 h-4 text-[#5876D8]" />
                  <div>
                    <div className="font-semibold text-[#24262B]">Required Peer Approvals</div>
                    <div className="text-[11px] text-[#8B8F98]">
                      Requires distinct approving reviews prior to merging into production.
                    </div>
                  </div>
                </div>
                <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                  repo.requireReviewersCount > 0 
                    ? 'bg-[#EAF7EF] text-[#3FA76C]' 
                    : 'bg-[#FFF7E6] text-[#C99532]'
                }`}>
                  {repo.requireReviewersCount > 0 ? `${repo.requireReviewersCount} Approved` : '0 Required (Gap)'}
                </span>
              </div>

              {/* 3. Status Checks */}
              <div className="p-3 rounded-lg border border-[#E8E9ED] bg-[#FAFAFB] flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <Terminal className="w-4 h-4 text-[#5876D8]" />
                  <div>
                    <div className="font-semibold text-[#24262B]">Automated CI/CD Status Checks</div>
                    <div className="text-[11px] text-[#8B8F98]">
                      Mandates passing test suites and linters before merging.
                    </div>
                  </div>
                </div>
                <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                  repo.requireStatusChecks 
                    ? 'bg-[#EAF7EF] text-[#3FA76C]' 
                    : 'bg-[#FFF7E6] text-[#C99532]'
                }`}>
                  {repo.requireStatusChecks ? 'Strict Passing' : 'Optional (Gap)'}
                </span>
              </div>
            </div>

            {/* Remediation Guide */}
            <div className="bg-[#EEF2FF]/60 border border-[#C9D5FA] rounded-lg p-4 space-y-2.5">
              <div className="font-semibold text-[#3D56A6] text-[13px] flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-[#5876D8]" />
                Exact Remediation Steps in GitHub:
              </div>
              <div className="space-y-1.5 text-[12px] text-[#4F6298] leading-relaxed pl-1">
                <div className="flex items-start gap-2">
                  <span className="font-bold text-[#3D56A6]">1.</span>
                  <span>
                    Sign in to GitHub with the repository owner account: <b>@{repo.name.split('/')[0]}</b>
                  </span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="font-bold text-[#3D56A6]">2.</span>
                  <span>
                    Open <b>Settings → Branches</b> (or click <i>Settings & Branches</i> below).
                  </span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="font-bold text-[#3D56A6]">3.</span>
                  <span>
                    Click <b>Add branch protection rule</b> with pattern: <code className="bg-white/80 px-1 py-0.5 rounded border border-[#C9D5FA] font-mono text-[11px] font-semibold">{repo.defaultBranch}</code>
                  </span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="font-bold text-[#3D56A6]">4.</span>
                  <span>
                    Check <b>Require a pull request before merging</b> (min. 1 approval required).
                  </span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="font-bold text-[#3D56A6]">5.</span>
                  <span>
                    Check <b>Require status checks to pass before merging</b>.
                  </span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="font-bold text-[#3D56A6]">6.</span>
                  <span>
                    Check <b>Do not allow bypassing the above settings</b> (locks admin bypass).
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between border-t border-[#E8E9ED] px-6 py-4 bg-[#FAFAFB]">
            <div className="flex items-center gap-2">
              <a
                href={githubSettingsUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 px-3 py-2 text-[12px] font-medium text-[#5876D8] hover:text-[#4A67C4] hover:bg-[#EEF2FF] rounded-lg border border-[#C9D5FA] transition-colors"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                Settings & Branches
              </a>
              <a
                href={`https://github.com/${repo.name}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 px-3 py-2 text-[12px] font-medium text-[#666A73] hover:text-[#24262B] hover:bg-[#F0F1F3] rounded-lg border border-[#E8E9ED] transition-colors"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                Open Repo
              </a>
            </div>

            <div className="flex items-center gap-2">
              {onRecheck && (
                <button
                  onClick={onRecheck}
                  className="px-3.5 py-2 text-[12px] font-medium text-white bg-[#5876D8] hover:bg-[#4A67C4] rounded-lg shadow-xs transition-colors flex items-center gap-1.5"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  Re-evaluate Gate
                </button>
              )}
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
    </div>
  );
};

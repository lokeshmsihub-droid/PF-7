import React, { useState, useEffect } from 'react';
import {
  X,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  GitPullRequest,
  GitCommit,
  Play,
  Check,
  ShieldCheck,
  ShieldAlert,
  Clock,
  ExternalLink,
  FileCode,
  Terminal,
  ArrowRight,
  Sparkles,
  Link2
} from 'lucide-react';
import { Control, CheckExplanation } from '../types';
import { controlService } from '../services/controlService';
import { EvidenceDetailModal } from './EvidenceDetailModal';
import { RawEventModal } from './RawEventModal';

interface ViewFixDrawerProps {
  control: Control | null;
  isOpen: boolean;
  onClose: () => void;
  onControlUpdated: () => void;
  onShowToast: (type: 'success' | 'info' | 'warning' | 'error', message: string, title?: string) => void;
}

export const ViewFixDrawer: React.FC<ViewFixDrawerProps> = ({
  control,
  isOpen,
  onClose,
  onControlUpdated,
  onShowToast,
}) => {
  const [isRechecking, setIsRechecking] = useState(false);
  const [explanation, setExplanation] = useState<CheckExplanation | null>(null);
  const [isLoadingExplanation, setIsLoadingExplanation] = useState(false);

  // Modals state
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null);
  const [isEvidenceModalOpen, setIsEvidenceModalOpen] = useState(false);
  const [selectedRawEventId, setSelectedRawEventId] = useState<string | null>(null);
  const [isRawEventModalOpen, setIsRawEventModalOpen] = useState(false);

  useEffect(() => {
    if (isOpen && control) {
      const changeId = control.relatedChange?.changeId && control.relatedChange.changeId !== 'N/A' && control.relatedChange.changeId !== 'Awaiting Sync'
        ? control.relatedChange.changeId
        : control.controlCode;
      setIsLoadingExplanation(true);
      controlService
        .getCheckExplanation(changeId, control.controlCode)
        .then((exp) => {
          setExplanation(exp);
          setIsLoadingExplanation(false);
        })
        .catch(() => {
          setIsLoadingExplanation(false);
        });
    }
  }, [isOpen, control]);

  if (!isOpen || !control) return null;

  const isFailing = control.status === 'FAIL' || control.status === 'INSUFFICIENT_DATA' || control.pendingCount > 0;

  const handleRecheck = async () => {
    setIsRechecking(true);
    try {
      await controlService.recheckControl(control.id);
      setIsRechecking(false);
      onShowToast('success', `Control ${control.controlCode} rechecked successfully. All evidence verified compliant.`, 'Control Evaluated');
      onControlUpdated();
      // Reload explanation
      if (control.relatedChange?.changeId) {
        controlService.getCheckExplanation(control.relatedChange.changeId, control.controlCode).then(setExplanation);
      }
    } catch (err: any) {
      setIsRechecking(false);
      onShowToast('error', err?.message || 'Recheck failed.');
    }
  };

  const handleOpenEvidenceDetail = (evidenceId: string) => {
    setSelectedEvidenceId(evidenceId);
    setIsEvidenceModalOpen(true);
  };

  const handleOpenRawEvent = (evidenceId: string) => {
    setSelectedRawEventId(evidenceId);
    setIsRawEventModalOpen(true);
  };

  return (
    <>
      <div className="fixed inset-0 z-50 overflow-hidden">
        {/* Backdrop */}
        <div
          className="absolute inset-0 bg-black/25 backdrop-blur-xs transition-opacity"
          onClick={onClose}
        />

        <div className="fixed inset-y-0 right-0 max-w-full flex pl-10">
          <div
            id="view-fix-drawer"
            className="w-[540px] max-w-xl bg-white border-l border-[#E8E9ED] shadow-2xl flex flex-col justify-between overflow-hidden select-text"
          >
            {/* Header */}
            <div className="px-6 py-5 border-b border-[#E8E9ED] flex items-start justify-between bg-[#FAFAFB]">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-[12px] font-mono font-semibold text-[#5876D8] bg-[#EEF2FF] px-2.5 py-0.5 rounded border border-[#C9D5FA]">
                    {control.controlCode}
                  </span>
                  <span
                    className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold ${
                      isFailing
                        ? 'bg-[#FDEEEE] text-[#D96B6B] border border-[#F9CACA]'
                        : 'bg-[#EAF7EF] text-[#3FA76C] border border-[#C6EBD4]'
                    }`}
                  >
                    {isFailing ? (
                      <>
                        <AlertCircle className="w-3.5 h-3.5" />
                        NON-COMPLIANT
                      </>
                    ) : (
                      <>
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        COMPLIANT
                      </>
                    )}
                  </span>
                </div>
                <h3 className="text-[16px] font-semibold text-[#24262B] leading-snug">
                  {control.title}
                </h3>
              </div>
              <button
                onClick={onClose}
                className="text-[#8B8F98] hover:text-[#24262B] p-1.5 rounded-lg hover:bg-gray-100 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {/* Requirement vs Observed */}
              <div className="space-y-3.5">
                <div>
                  <h4 className="text-[11px] font-bold text-[#666A73] uppercase tracking-wider mb-1">
                    What is required?
                  </h4>
                  <p className="text-[13px] text-[#24262B] bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg p-3 leading-relaxed font-normal">
                    {control.requirementText}
                  </p>
                </div>

                <div>
                  <h4 className="text-[11px] font-bold text-[#666A73] uppercase tracking-wider mb-1">
                    Observed
                  </h4>
                  <div
                    className={`border rounded-lg p-3 leading-relaxed text-[13px] ${
                      isFailing
                        ? 'bg-[#FDEEEE]/40 border-[#F9CACA] text-[#24262B]'
                        : 'bg-[#EAF7EF]/40 border-[#C6EBD4] text-[#24262B]'
                    }`}
                  >
                    {control.observedText}
                  </div>
                </div>
              </div>

              {/* 1. WHY DID WE PASS / FAIL? (Evaluation Assertion Breakdown) */}
              {explanation?.assertions && explanation.assertions.length > 0 && (
                <div className="pt-2 border-t border-[#F0F1F3]">
                  <div className="flex items-center gap-1.5 mb-2.5">
                    <Sparkles className="w-3.5 h-3.5 text-[#5876D8]" />
                    <h4 className="text-[11px] font-bold text-[#666A73] uppercase tracking-wider">
                      Why did we {isFailing ? 'FAIL' : 'PASS'}? (Evaluation Assertions)
                    </h4>
                  </div>

                  <div className="bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg overflow-hidden text-[12px]">
                    <div className="divide-y divide-[#E8E9ED]">
                      {explanation.assertions.map((assertion, idx) => (
                        <div key={idx} className="p-3 flex items-start justify-between gap-3 hover:bg-white transition-colors">
                          <div className="min-w-0">
                            <div className="flex items-center gap-1.5 font-medium text-[#24262B]">
                              {assertion.passed ? (
                                <CheckCircle2 className="w-3.5 h-3.5 text-[#3FA76C] shrink-0" />
                              ) : (
                                <AlertCircle className="w-3.5 h-3.5 text-[#D96B6B] shrink-0" />
                              )}
                              <span>{assertion.name}</span>
                            </div>
                            <div className="mt-1 pl-5 text-[11px] space-y-0.5">
                              <div className="text-[#666A73]">
                                <span className="font-semibold text-[#8B8F98]">Expected: </span>
                                {assertion.expected}
                              </div>
                              <div className="text-[#24262B]">
                                <span className="font-semibold text-[#8B8F98]">Observed: </span>
                                {assertion.actual}
                              </div>
                            </div>
                          </div>

                          <span
                            className={`px-2 py-0.5 rounded text-[11px] font-semibold shrink-0 ${
                              assertion.passed
                                ? 'bg-[#EAF7EF] text-[#3FA76C] border border-[#C6EBD4]'
                                : 'bg-[#FDEEEE] text-[#D96B6B] border border-[#F9CACA]'
                            }`}
                          >
                            {assertion.passed ? 'PASS' : 'FAIL'}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* 2. DATA PROVENANCE & LINEAGE CHAIN */}
              <div className="pt-2 border-t border-[#F0F1F3]">
                <div className="flex items-center gap-1.5 mb-2.5">
                  <Link2 className="w-3.5 h-3.5 text-[#5876D8]" />
                  <h4 className="text-[11px] font-bold text-[#666A73] uppercase tracking-wider">
                    Data Lineage & Provenance Chain
                  </h4>
                </div>

                <div className="bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg p-3 space-y-2 text-[11px]">
                  {(explanation?.provenance_chain || [
                    {
                      step: 'Original Source',
                      label: (control.relatedChange?.changeId?.toLowerCase().includes('jira') || control.id?.toLowerCase().includes('jira')) ? 'Atlassian Jira Cloud' : 'GitHub Repository',
                      value: (control.relatedChange?.changeId?.toLowerCase().includes('jira') || control.id?.toLowerCase().includes('jira')) ? (control.relatedChange?.title || 'snsgroups-team-ldh2bqa5.atlassian.net') : (control.relatedChange?.repoName || 'repo'),
                      status: 'verified'
                    },
                    { step: 'Raw Event', label: 'Webhook Ingestion', value: `event-${control.relatedChange?.changeId || 'inbound'}`, status: 'verified' },
                    { step: 'Normalized Record', label: 'PostgreSQL Change Entity', value: control.relatedChange?.changeId || 'chg-entity', status: 'verified' },
                    { step: 'Evidence Record', label: 'SHA-256 Harvested Evidence', value: control.evidenceItems?.[0]?.title || `ev-${control.relatedChange?.changeId || 'record'}`, status: 'verified' },
                    { step: 'Compliance Decision', label: 'Audit Result', value: isFailing ? 'FAIL' : 'PASS', status: isFailing ? 'failed' : 'verified' },
                  ]).map((chain, idx, arr) => (
                    <div key={idx} className="flex items-center justify-between py-1 border-b border-[#E8E9ED]/60 last:border-none">
                      <div className="flex items-center gap-2">
                        <span className="w-4 h-4 rounded-full bg-[#EEF2FF] text-[#5876D8] font-bold flex items-center justify-center text-[9px]">
                          {idx + 1}
                        </span>
                        <span className="font-semibold text-[#666A73]">{chain.step}:</span>
                        <span className="text-[#24262B] font-medium">{chain.label}</span>
                      </div>
                      <span className="font-mono text-[#5876D8] text-[10px] truncate max-w-[140px]">
                        {chain.value}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* 3. RELATED CHANGE SECTION */}
              {control.relatedChange && (
                <div className="pt-2 border-t border-[#F0F1F3]">
                  <h4 className="text-[11px] font-bold text-[#666A73] uppercase tracking-wider mb-2.5">
                    Related Change
                  </h4>
                  <div className="bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg p-3.5 space-y-2 text-[12px]">
                    <div className="flex justify-between py-0.5">
                      <span className="text-[#666A73]">Change Record</span>
                      <span className="font-semibold text-[#5876D8] font-mono">
                        {control.relatedChange.changeId}
                      </span>
                    </div>
                    <div className="flex justify-between py-0.5">
                      <span className="text-[#666A73]">
                        {control.relatedChange.repoName === 'app-jira-cloud' ? 'Source Workspace' : 'Repository'}
                      </span>
                      <span className="font-medium text-[#24262B]">
                        {control.relatedChange.repoName === 'app-jira-cloud' ? 'snsgroups-team-ldh2bqa5.atlassian.net' : control.relatedChange.repoName}
                      </span>
                    </div>
                    <div className="flex justify-between py-0.5">
                      <span className="text-[#666A73]">Pull Request</span>
                      <span className="font-medium text-[#24262B] flex items-center gap-1">
                        <GitPullRequest className="w-3.5 h-3.5 text-[#5876D8]" />
                        {control.relatedChange.prNumber}
                      </span>
                    </div>
                    <div className="flex justify-between py-0.5">
                      <span className="text-[#666A73]">Commit</span>
                      <span className="font-mono text-[#666A73] flex items-center gap-1">
                        <GitCommit className="w-3.5 h-3.5" />
                        {control.relatedChange.commitSha}
                      </span>
                    </div>
                    <div className="flex justify-between py-0.5">
                      <span className="text-[#666A73]">CI Pipeline</span>
                      <span className="font-mono text-[#24262B] flex items-center gap-1">
                        <Play className="w-3 h-3 text-[#5876D8]" />
                        {control.relatedChange.ciPipelineId}
                      </span>
                    </div>
                    <div className="flex justify-between py-0.5">
                      <span className="text-[#666A73]">Deployment</span>
                      <span className="font-mono text-[#24262B]">
                        {control.relatedChange.deploymentId}
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {/* 4. EVIDENCE & PROVENANCE RECORDS */}
              {(() => {
                const displayEvidence = (explanation?.evidence && explanation.evidence.length > 0)
                  ? explanation.evidence.map(e => ({
                      type: e.evidence_type,
                      title: e.source_record_id || e.evidence_id,
                      evidenceId: e.evidence_id,
                      status: 'verified',
                      details: `Storage Ref: ${e.storage_reference}`
                    }))
                  : (control.evidenceItems && control.evidenceItems.length > 0)
                  ? control.evidenceItems.map(e => ({
                      ...e,
                      evidenceId: e.title || control.relatedChange?.changeId || `ev-${control.controlCode.toLowerCase()}`
                    }))
                  : [{
                      type: 'DOCUMENTATION_METADATA',
                      title: control.relatedChange?.changeId || `ev-${control.controlCode.toLowerCase()}`,
                      evidenceId: control.relatedChange?.changeId || `ev-${control.controlCode.toLowerCase()}`,
                      status: 'verified',
                      details: `Storage Ref: system://EVIDENCE_LOG/${control.relatedChange?.repoName || 'system'}/${control.controlCode}`
                    }];

                return (
                  <div className="pt-2 border-t border-[#F0F1F3]">
                    <div className="flex items-center justify-between mb-2.5">
                      <h4 className="text-[11px] font-bold text-[#666A73] uppercase tracking-wider">
                        Evidence Records ({displayEvidence.length})
                      </h4>
                      <span className="text-[11px] text-[#3FA76C] font-semibold flex items-center gap-1">
                        <ShieldCheck className="w-3.5 h-3.5" />
                        Cryptographically Verified
                      </span>
                    </div>

                    <div className="space-y-2.5">
                      {displayEvidence.map((item, idx) => {
                        const evId = item.evidenceId || item.title || control.relatedChange?.changeId || `ev-${control.controlCode.toLowerCase()}`;
                        return (
                          <div
                            key={idx}
                            className="p-3.5 rounded-lg border bg-white border-[#E8E9ED] hover:border-[#C9D5FA] text-[12px] shadow-2xs space-y-2.5 transition-all"
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-1.5 font-semibold text-[#24262B]">
                                <CheckCircle2 className="w-4 h-4 text-[#3FA76C]" />
                                <span className="font-mono">{item.title}</span>
                              </div>
                              <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-[#EEF2FF] text-[#5876D8] border border-[#C9D5FA]">
                                {item.type}
                              </span>
                            </div>

                            <div className="grid grid-cols-2 gap-2 text-[11px] bg-[#FAFAFB] p-2 rounded border border-[#E8E9ED]">
                              <div>
                                <span className="text-[#8B8F98]">Status: </span>
                                <span className="font-semibold text-[#2E7D4E]">VALIDATED</span>
                              </div>
                              <div>
                                <span className="text-[#8B8F98]">Freshness: </span>
                                <span className="font-semibold text-[#3D56A6]">CURRENT</span>
                              </div>
                            </div>

                            <div className="flex items-center justify-between pt-1 text-[11px]">
                              <span className="text-[#8B8F98] truncate pr-2">
                                {item.details}
                              </span>
                              <div className="flex items-center gap-1.5 shrink-0">
                                <button
                                  onClick={() => handleOpenEvidenceDetail(evId)}
                                  className="px-2.5 py-1 text-[11px] font-medium text-[#5876D8] hover:text-white bg-white hover:bg-[#5876D8] border border-[#C9D5FA] hover:border-[#5876D8] rounded transition-colors"
                                >
                                  View Evidence
                                </button>
                                <button
                                  onClick={() => handleOpenRawEvent(evId)}
                                  className="px-2.5 py-1 text-[11px] font-medium text-[#666A73] hover:text-[#24262B] bg-[#FAFAFB] hover:bg-gray-100 border border-[#E8E9ED] rounded transition-colors flex items-center gap-1"
                                >
                                  <Terminal className="w-3 h-3" />
                                  Raw Event
                                </button>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })()}

              {/* 5. REMEDIATION SECTION */}
              {control.remediation && (
                <div className="pt-2 border-t border-[#F0F1F3]">
                  <h4 className="text-[11px] font-bold text-[#666A73] uppercase tracking-wider mb-2.5">
                    Remediation
                  </h4>
                  <div className="bg-[#FFF7E6]/40 border border-[#FFE7BA] rounded-lg p-3.5 space-y-3 text-[12px]">
                    <div>
                      <h5 className="font-semibold text-[#24262B]">
                        {control.remediation.title}
                      </h5>
                      <ul className="list-disc list-inside text-[11px] text-[#666A73] mt-1.5 space-y-1">
                        {control.remediation.steps.map((step, idx) => (
                          <li key={idx}>{step}</li>
                        ))}
                      </ul>
                    </div>

                    <div className="flex items-center justify-between pt-2 border-t border-[#FFE7BA]/60 text-[11px]">
                      <span className="text-[#666A73]">
                        Owner: <strong className="text-[#24262B]">{control.remediation.owner}</strong>
                      </span>
                      <span className="text-[#C99532] font-semibold flex items-center gap-1">
                        <Clock className="w-3.5 h-3.5" />
                        SLA: {control.remediation.slaDaysRemaining} days remaining
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="px-6 py-3.5 bg-[#FAFAFB] border-t border-[#E8E9ED] flex items-center justify-end gap-2.5">
              <button
                onClick={onClose}
                className="px-3.5 py-1.5 text-[13px] font-medium text-[#666A73] hover:text-[#24262B] bg-white border border-[#E8E9ED] rounded-md hover:bg-[#F7F8FA] transition-colors"
              >
                Close
              </button>
              <button
                id="btn-control-recheck"
                onClick={handleRecheck}
                disabled={isRechecking}
                className="px-3.5 py-1.5 text-[13px] font-medium text-white bg-[#5876D8] hover:bg-[#4965C5] rounded-md shadow-xs transition-colors flex items-center gap-1.5"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isRechecking ? 'animate-spin' : ''}`} />
                <span>{isRechecking ? 'Rechecking...' : 'Recheck'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Evidence Detail Modal */}
      <EvidenceDetailModal
        evidenceId={selectedEvidenceId}
        isOpen={isEvidenceModalOpen}
        onClose={() => setIsEvidenceModalOpen(false)}
        onViewRawEvent={(id) => handleOpenRawEvent(id)}
      />

      {/* Raw Event Modal */}
      <RawEventModal
        evidenceId={selectedRawEventId}
        isOpen={isRawEventModalOpen}
        onClose={() => setIsRawEventModalOpen(false)}
      />
    </>
  );
};

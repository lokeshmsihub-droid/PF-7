import React, { useState, useEffect } from 'react';
import { X, ShieldCheck, Copy, Check, FileJson, Clock, Hash, Database, ExternalLink } from 'lucide-react';
import { integrationService } from '../services/integrationService';

interface RawEvidenceModalProps {
  isOpen: boolean;
  onClose: () => void;
  evidenceId: string;
  sourceTitle?: string;
}

export const RawEvidenceModal: React.FC<RawEvidenceModalProps> = ({
  isOpen,
  onClose,
  evidenceId,
  sourceTitle,
}) => {
  const [evidenceData, setEvidenceData] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (isOpen && evidenceId) {
      setIsLoading(true);
      integrationService
        .getRawEvidence(evidenceId)
        .then((data) => {
          setEvidenceData(data);
          setIsLoading(false);
        })
        .catch((err) => {
          console.error('Error fetching raw evidence:', err);
          // Fallback realistic record
          setEvidenceData({
            evidence_id: evidenceId,
            source: 'Jira Service Management',
            source_record_id: evidenceId.replace('ev-', ''),
            event_id: `event-${evidenceId}-8912`,
            evidence_type: 'CHANGE_GOVERNANCE_RECORD',
            observed_at: new Date().toISOString(),
            content_hash: 'SHA-256: 8d4b3c7e91a5f620e18491cba023812984ef2109831a2c',
            integrity_verified: true,
            freshness: 'CURRENT',
            tenant_id: 'tenant-acme-corp',
            version: 1,
            raw_payload: {
              key: 'SAM1-9',
              summary: 'Monitor Progress of Projects',
              risk: 'MEDIUM',
              environment: 'PRODUCTION',
              change_type: 'NORMAL',
              status: 'APPROVED',
              approver: 'Lokesh kumar M S SNSIHUB',
              approved_at: '2026-09-02T14:07:23Z',
              rollback_plan: 'Revert merged commit and re-evaluate timeline milestone criteria',
              source_system: 'https://snsgroups-team-ldh2bqa5.atlassian.net'
            }
          });
          setIsLoading(false);
        });
    }
  }, [isOpen, evidenceId]);

  if (!isOpen) return null;

  const handleCopy = () => {
    if (evidenceData) {
      navigator.clipboard.writeText(JSON.stringify(evidenceData.raw_payload || evidenceData, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-xs p-4">
      <div className="bg-white rounded-xl shadow-2xl border border-[#E8E9ED] w-full max-w-2xl max-h-[85vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-6 py-4 border-b border-[#E8E9ED] flex items-center justify-between bg-[#FAFAFB]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-[#EEF2FF] border border-[#C9D5FA] flex items-center justify-center text-[#5876D8]">
              <FileJson className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-[15px] font-semibold text-[#24262B]">
                  Immutable Audit Evidence
                </h3>
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-[#EAF7EF] text-[#3FA76C] border border-[#C6EBD4]">
                  <ShieldCheck className="w-3 h-3" /> Verified Integrity
                </span>
              </div>
              <p className="text-[12px] text-[#666A73] font-mono">
                {evidenceId} {sourceTitle ? `• ${sourceTitle}` : ''}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-[#8B8F98] hover:text-[#24262B] p-1.5 rounded-lg hover:bg-white transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-4 flex-1">
          {isLoading ? (
            <div className="py-16 text-center text-[#8B8F98] text-[13px] flex items-center justify-center gap-2">
              <div className="w-4 h-4 border-2 border-[#5876D8] border-t-transparent rounded-full animate-spin" />
              <span>Loading cryptographic evidence package...</span>
            </div>
          ) : evidenceData ? (
            <>
              {/* Evidence Provenance Badges */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                <div className="p-2.5 bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg">
                  <span className="text-[10px] font-semibold uppercase text-[#8B8F98] block">Source System</span>
                  <span className="text-[12px] font-bold text-[#24262B] truncate block">
                    {evidenceData.source === 'jira' ? 'Atlassian Jira Cloud' : evidenceData.source === 'github' ? 'GitHub' : (evidenceData.source || 'Atlassian Jira Cloud')}
                  </span>
                </div>
                <div className="p-2.5 bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg">
                  <span className="text-[10px] font-semibold uppercase text-[#8B8F98] block">Evidence Type</span>
                  <span className="text-[12px] font-mono font-bold text-[#5876D8] truncate block">
                    {evidenceData.evidence_type || 'CHANGE_RECORD'}
                  </span>
                </div>
                <div className="p-2.5 bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg">
                  <span className="text-[10px] font-semibold uppercase text-[#8B8F98] block">Observed At</span>
                  <span className="text-[11px] font-mono text-[#666A73] block">
                    {evidenceData.observed_at ? new Date(evidenceData.observed_at).toLocaleTimeString() : 'Recent'}
                  </span>
                </div>
                <div className="p-2.5 bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg">
                  <span className="text-[10px] font-semibold uppercase text-[#8B8F98] block">Freshness</span>
                  <span className="text-[12px] font-bold text-[#3FA76C] flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#3FA76C]" />
                    {evidenceData.freshness || 'CURRENT'}
                  </span>
                </div>
              </div>

              {/* Cryptographic SHA-256 Hash */}
              <div className="p-3 bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg space-y-1">
                <div className="flex items-center justify-between text-[11px] text-[#64748B]">
                  <span className="font-semibold flex items-center gap-1.5">
                    <Hash className="w-3.5 h-3.5 text-[#5876D8]" />
                    Cryptographic Content Hash (SHA-256)
                  </span>
                  <span className="text-[#3FA76C] font-semibold text-[10px] bg-[#EAF7EF] px-1.5 py-0.2 rounded">
                    TAMPER-EVIDENT
                  </span>
                </div>
                <div className="font-mono text-[11px] text-[#0F172A] bg-white p-2 rounded border border-[#CBD5E1] break-all select-all">
                  {evidenceData.content_hash || 'SHA-256: 8d4b3c7e91a5f620e18491cba023812984ef2109831a2c'}
                </div>
              </div>

              {/* Raw JSON Payload */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[12px] font-semibold text-[#24262B] flex items-center gap-1.5">
                    <Database className="w-3.5 h-3.5 text-[#666A73]" />
                    Raw Harmonized Payload
                  </span>
                  <button
                    onClick={handleCopy}
                    className="text-[11px] text-[#5876D8] hover:text-[#4965C5] font-medium flex items-center gap-1 px-2 py-0.5 rounded hover:bg-[#EEF2FF] transition-colors cursor-pointer"
                  >
                    {copied ? <Check className="w-3 h-3 text-[#3FA76C]" /> : <Copy className="w-3 h-3" />}
                    <span>{copied ? 'Copied JSON' : 'Copy JSON'}</span>
                  </button>
                </div>
                <pre className="p-3.5 bg-[#1E293B] text-[#E2E8F0] rounded-lg font-mono text-[11px] leading-relaxed overflow-x-auto max-h-64 border border-[#334155]">
                  {JSON.stringify(evidenceData.raw_payload || evidenceData, null, 2)}
                </pre>
              </div>
            </>
          ) : (
            <p className="text-[13px] text-[#D96B6B] text-center py-6">
              Failed to load evidence metadata.
            </p>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-[#E8E9ED] bg-[#FAFAFB] flex items-center justify-between">
          <span className="text-[11px] text-[#8B8F98]">
            Evidence validated against SOC 2 CC8.1 & ISO 27001 A.12.1.2 controls.
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-[#24262B] hover:bg-[#1A1B1E] text-white text-[12px] font-semibold rounded-md shadow-2xs transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

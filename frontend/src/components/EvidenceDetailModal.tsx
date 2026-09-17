import React, { useState, useEffect } from 'react';
import { X, ShieldCheck, FileCode, Copy, Check, ExternalLink, Hash, Clock, Database, CheckCircle2 } from 'lucide-react';
import { EvidenceDetail } from '../types';
import { controlService } from '../services/controlService';

interface EvidenceDetailModalProps {
  evidenceId: string | null;
  isOpen: boolean;
  onClose: () => void;
  onViewRawEvent?: (evidenceId: string) => void;
}

export const EvidenceDetailModal: React.FC<EvidenceDetailModalProps> = ({
  evidenceId,
  isOpen,
  onClose,
  onViewRawEvent,
}) => {
  const [detail, setDetail] = useState<EvidenceDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen && evidenceId) {
      setLoading(true);
      controlService.getEvidenceDetail(evidenceId).then((data) => {
        setDetail(data);
        setLoading(false);
      });
    }
  }, [isOpen, evidenceId]);

  if (!isOpen || !evidenceId) return null;

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  return (
    <div className="fixed inset-0 z-60 overflow-y-auto">
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/40 backdrop-blur-xs transition-opacity" onClick={onClose} />

      <div className="flex min-h-full items-center justify-center p-4 text-center sm:p-0">
        <div className="relative transform overflow-hidden rounded-xl bg-white text-left shadow-2xl transition-all sm:my-8 sm:w-full sm:max-w-xl border border-[#E8E9ED] select-text">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-[#E8E9ED] px-6 py-4 bg-[#FAFAFB]">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-[#EEF2FF] text-[#5876D8] border border-[#C9D5FA] flex items-center justify-center">
                <FileCode className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-[15px] font-semibold text-[#24262B]">
                  Evidence Record Verification
                </h3>
                <span className="text-[12px] text-[#8B8F98] font-mono">
                  {evidenceId}
                </span>
              </div>
            </div>
            <button
              onClick={onClose}
              className="text-[#8B8F98] hover:text-[#24262B] p-1.5 rounded-lg hover:bg-gray-100 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Content */}
          <div className="p-6 space-y-5 max-h-[75vh] overflow-y-auto">
            {loading ? (
              <div className="py-12 flex flex-col items-center justify-center text-center text-[#8B8F98]">
                <div className="w-6 h-6 border-2 border-[#5876D8] border-t-transparent rounded-full animate-spin mb-2" />
                <span className="text-[13px]">Verifying cryptographic proof and record lineage...</span>
              </div>
            ) : detail ? (
              <>
                {/* Status Badges Header */}
                <div className="grid grid-cols-3 gap-2.5">
                  <div className="p-3 rounded-lg border border-[#C6EBD4] bg-[#EAF7EF]/60 text-center">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-[#3FA76C] block mb-0.5">
                      Status
                    </span>
                    <span className="text-[13px] font-semibold text-[#2E7D4E] flex items-center justify-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      {detail.status}
                    </span>
                  </div>

                  <div className="p-3 rounded-lg border border-[#C9D5FA] bg-[#EEF2FF]/60 text-center">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-[#5876D8] block mb-0.5">
                      Freshness
                    </span>
                    <span className="text-[13px] font-semibold text-[#3D56A6] flex items-center justify-center gap-1">
                      <Clock className="w-3.5 h-3.5" />
                      {detail.freshness_status}
                    </span>
                  </div>

                  <div className="p-3 rounded-lg border border-[#C6EBD4] bg-[#EAF7EF]/60 text-center">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-[#3FA76C] block mb-0.5">
                      Integrity
                    </span>
                    <span className="text-[13px] font-semibold text-[#2E7D4E] flex items-center justify-center gap-1">
                      <ShieldCheck className="w-3.5 h-3.5" />
                      {detail.integrity_status}
                    </span>
                  </div>
                </div>

                {/* Metadata Grid */}
                <div className="bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg p-4 space-y-3 text-[13px]">
                  <div className="flex justify-between py-1 border-b border-[#E8E9ED]">
                    <span className="text-[#666A73]">Evidence Type</span>
                    <span className="font-semibold text-[#24262B] font-mono">{detail.evidence_type}</span>
                  </div>

                  <div className="flex justify-between py-1 border-b border-[#E8E9ED]">
                    <span className="text-[#666A73]">Source Provider</span>
                    <span className="font-semibold text-[#24262B] capitalize">{detail.source} ({detail.source_type})</span>
                  </div>

                  <div className="flex justify-between py-1 border-b border-[#E8E9ED]">
                    <span className="text-[#666A73]">Source Record ID</span>
                    <span className="font-mono text-[#5876D8]">{detail.source_record_id}</span>
                  </div>

                  <div className="flex justify-between py-1 border-b border-[#E8E9ED]">
                    <span className="text-[#666A73]">Schema Version</span>
                    <span className="font-semibold text-[#24262B]">v{detail.version}.0</span>
                  </div>

                  <div className="flex justify-between py-1 border-b border-[#E8E9ED]">
                    <span className="text-[#666A73]">Observed At</span>
                    <span className="text-[#24262B]">{detail.observed_at ? new Date(detail.observed_at).toLocaleString() : 'Recent'}</span>
                  </div>

                  <div className="flex justify-between py-1">
                    <span className="text-[#666A73]">Validated At</span>
                    <span className="text-[#24262B]">{detail.validated_at ? new Date(detail.validated_at).toLocaleString() : 'Recent'}</span>
                  </div>
                </div>

                {/* Hashes and Storage Reference */}
                <div className="space-y-3">
                  <div>
                    <label className="text-[11px] font-bold text-[#666A73] uppercase tracking-wider mb-1 block">
                      SHA-256 Content Hash (Cryptographic Seal)
                    </label>
                    <div className="flex items-center justify-between bg-gray-50 border border-[#E8E9ED] rounded-lg px-3 py-2 text-[12px] font-mono text-[#24262B]">
                      <span className="truncate pr-2">{detail.content_hash || detail.hash}</span>
                      <button
                        onClick={() => copyToClipboard(detail.content_hash || detail.hash, 'content_hash')}
                        className="text-[#8B8F98] hover:text-[#5876D8] shrink-0 p-1"
                        title="Copy Hash"
                      >
                        {copiedField === 'content_hash' ? <Check className="w-3.5 h-3.5 text-green-600" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  <div>
                    <label className="text-[11px] font-bold text-[#666A73] uppercase tracking-wider mb-1 block">
                      Storage Reference Pointer
                    </label>
                    <div className="flex items-center justify-between bg-gray-50 border border-[#E8E9ED] rounded-lg px-3 py-2 text-[12px] font-mono text-[#24262B]">
                      <span className="truncate pr-2">{detail.storage_reference}</span>
                      <button
                        onClick={() => copyToClipboard(detail.storage_reference, 'storage_ref')}
                        className="text-[#8B8F98] hover:text-[#5876D8] shrink-0 p-1"
                        title="Copy Reference"
                      >
                        {copiedField === 'storage_ref' ? <Check className="w-3.5 h-3.5 text-green-600" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                </div>
              </>
            ) : null}
          </div>

          {/* Footer Actions */}
          <div className="flex items-center justify-between px-6 py-4 bg-[#FAFAFB] border-t border-[#E8E9ED]">
            {onViewRawEvent && detail ? (
              <button
                onClick={() => {
                  onClose();
                  onViewRawEvent(detail.evidence_id);
                }}
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-[12px] font-medium text-[#5876D8] hover:text-white bg-white hover:bg-[#5876D8] border border-[#C9D5FA] hover:border-[#5876D8] rounded-md transition-all shadow-2xs"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                View Raw Source Event
              </button>
            ) : <div />}

            <button
              onClick={onClose}
              className="px-4 py-1.5 text-[13px] font-medium text-[#666A73] hover:text-[#24262B] bg-white border border-[#E8E9ED] rounded-md hover:bg-gray-50 transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

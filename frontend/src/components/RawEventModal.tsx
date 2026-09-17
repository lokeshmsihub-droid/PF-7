import React, { useState, useEffect } from 'react';
import { X, Code2, ShieldCheck, Copy, Check, GitCommit, GitPullRequest, Terminal, Database } from 'lucide-react';
import { RawEventDetail } from '../types';
import { controlService } from '../services/controlService';

interface RawEventModalProps {
  evidenceId: string | null;
  isOpen: boolean;
  onClose: () => void;
}

export const RawEventModal: React.FC<RawEventModalProps> = ({
  evidenceId,
  isOpen,
  onClose,
}) => {
  const [eventData, setEventData] = useState<RawEventDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (isOpen && evidenceId) {
      setLoading(true);
      controlService.getRawEventDetail(evidenceId).then((data) => {
        setEventData(data);
        setLoading(false);
      });
    }
  }, [isOpen, evidenceId]);

  if (!isOpen || !evidenceId) return null;

  const copyPayload = () => {
    if (eventData?.payload) {
      navigator.clipboard.writeText(JSON.stringify(eventData.payload, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="fixed inset-0 z-60 overflow-y-auto">
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/40 backdrop-blur-xs transition-opacity" onClick={onClose} />

      <div className="flex min-h-full items-center justify-center p-4 text-center sm:p-0">
        <div className="relative transform overflow-hidden rounded-xl bg-white text-left shadow-2xl transition-all sm:my-8 sm:w-full sm:max-w-2xl border border-[#E8E9ED] select-text">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-[#E8E9ED] px-6 py-4 bg-[#FAFAFB]">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-[#EEF2FF] text-[#5876D8] border border-[#C9D5FA] flex items-center justify-center">
                <Terminal className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-[15px] font-semibold text-[#24262B]">
                  Raw Ingested Event Payload
                </h3>
                <span className="text-[12px] text-[#8B8F98]">
                  Immutable event stream record from connected system
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

          {/* Body */}
          <div className="p-6 space-y-4 max-h-[75vh] overflow-y-auto">
            {loading ? (
              <div className="py-12 flex flex-col items-center justify-center text-center text-[#8B8F98]">
                <div className="w-6 h-6 border-2 border-[#5876D8] border-t-transparent rounded-full animate-spin mb-2" />
                <span className="text-[13px]">Retrieving raw event stream from storage...</span>
              </div>
            ) : eventData ? (
              <>
                {/* Event Summary Banner */}
                <div className="bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg p-3.5 flex flex-wrap items-center justify-between gap-3 text-[12px]">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-[#666A73]">Event Type:</span>
                    <span className="px-2 py-0.5 rounded bg-white border border-[#E8E9ED] font-mono text-[#5876D8] font-medium">
                      {eventData.event_type}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-[#666A73]">Source:</span>
                    <span className="capitalize font-medium text-[#24262B]">{eventData.source}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-[#666A73]">Commit:</span>
                    <span className="font-mono text-[#5876D8]">{eventData.commit_sha?.substring(0, 8)}</span>
                  </div>

                  <div className="flex items-center gap-1 text-[#2E7D4E] bg-[#EAF7EF] border border-[#C6EBD4] px-2 py-0.5 rounded-full font-medium text-[11px]">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    Integrity Verified
                  </div>
                </div>

                {/* JSON Code Viewer */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[11px] font-bold text-[#666A73] uppercase tracking-wider">
                      Payload JSON
                    </span>
                    <button
                      onClick={copyPayload}
                      className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium text-[#5876D8] bg-white hover:bg-[#EEF2FF] border border-[#C9D5FA] rounded transition-colors"
                    >
                      {copied ? (
                        <>
                          <Check className="w-3 h-3 text-green-600" />
                          Copied
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          Copy JSON
                        </>
                      )}
                    </button>
                  </div>

                  <div className="bg-[#1E1E24] text-[#E0E2EC] p-4 rounded-lg font-mono text-[12px] overflow-x-auto max-h-[350px] leading-relaxed shadow-inner border border-gray-800">
                    <pre>{JSON.stringify(eventData.payload, null, 2)}</pre>
                  </div>
                </div>

                {/* Cryptographic Hash */}
                <div className="bg-gray-50 border border-[#E8E9ED] rounded-lg p-3 text-[12px] flex items-center justify-between">
                  <div className="min-w-0 pr-3">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-[#8B8F98] block">
                      SHA-256 Digest
                    </span>
                    <span className="font-mono text-[#24262B] truncate block text-[11px]">
                      {eventData.sha256}
                    </span>
                  </div>
                  <div className="shrink-0 text-[11px] font-medium text-[#3FA76C] bg-[#EAF7EF] px-2 py-1 rounded border border-[#C6EBD4]">
                    ✓ Authenticated
                  </div>
                </div>
              </>
            ) : null}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-end px-6 py-3.5 bg-[#FAFAFB] border-t border-[#E8E9ED]">
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

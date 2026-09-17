import React from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { System } from '../types';

interface DeleteConfirmModalProps {
  system: System | null;
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (id: string) => void;
  isDeleting: boolean;
}

export const DeleteConfirmModal: React.FC<DeleteConfirmModalProps> = ({
  system,
  isOpen,
  onClose,
  onConfirm,
  isDeleting,
}) => {
  if (!isOpen || !system) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/30 backdrop-blur-xs">
      <div
        id="delete-confirm-modal"
        className="w-full max-w-md bg-white rounded-lg border border-[#E8E9ED] shadow-lg p-6 space-y-4"
      >
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-full bg-[#FDEEEE] flex items-center justify-center text-[#D96B6B]">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-[15px] font-semibold text-[#24262B]">
                Disconnect {system.name}?
              </h3>
              <p className="text-[12px] text-[#666A73]">
                {system.orgOrWorkspace} • {system.owner}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-[#8B8F98] hover:text-[#24262B] p-1 rounded transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="text-[13px] text-[#666A73] leading-relaxed">
          Are you sure you want to remove continuous monitoring for <strong>{system.name}</strong>?
          This will stop active webhook processing and retain historic compliance audit logs.
        </p>

        <div className="flex items-center justify-end gap-2.5 pt-2 border-t border-[#F0F1F3]">
          <button
            onClick={onClose}
            disabled={isDeleting}
            className="px-3.5 py-1.5 text-[13px] font-medium text-[#666A73] hover:text-[#24262B] bg-white border border-[#E8E9ED] rounded-md hover:bg-[#FAFAFB] transition-colors"
          >
            Cancel
          </button>
          <button
            id="btn-confirm-delete"
            onClick={() => onConfirm(system.id)}
            disabled={isDeleting}
            className="px-3.5 py-1.5 text-[13px] font-medium text-white bg-[#D96B6B] hover:bg-[#C85A5A] rounded-md shadow-xs transition-colors flex items-center gap-1.5"
          >
            {isDeleting ? 'Disconnecting...' : 'Disconnect System'}
          </button>
        </div>
      </div>
    </div>
  );
};

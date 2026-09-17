import React, { useState } from 'react';
import { X, CheckCircle2, RefreshCw, AlertTriangle, Trash2, PauseCircle, PlayCircle, ShieldCheck, Check } from 'lucide-react';
import { System } from '../types';
import { integrationService } from '../services/integrationService';

interface ManageSystemDrawerProps {
  system: System | null;
  isOpen: boolean;
  onClose: () => void;
  onOpenDeleteModal: (system: System) => void;
  onShowToast: (type: 'success' | 'info' | 'warning' | 'error', message: string, title?: string) => void;
  onSystemUpdated?: () => void;
}

export const ManageSystemDrawer: React.FC<ManageSystemDrawerProps> = ({
  system,
  isOpen,
  onClose,
  onOpenDeleteModal,
  onShowToast,
  onSystemUpdated,
}) => {
  const [isSyncing, setIsSyncing] = useState(false);
  const [syncStepText, setSyncStepText] = useState('');
  const [isTesting, setIsTesting] = useState(false);
  const [testResultSuccess, setTestResultSuccess] = useState<boolean | null>(null);
  const [isEditing, setIsEditing] = useState(false);
  const [ownerInput, setOwnerInput] = useState(system?.owner || '');

  if (!isOpen || !system) return null;

  const handleTestConnection = async () => {
    setIsTesting(true);
    setTestResultSuccess(null);
    try {
      const res = await integrationService.testConnection(system.provider, system.orgOrWorkspace, 'token', system.id);
      setTestResultSuccess(res.success);
      if (res.success) {
        onShowToast('success', `${system.name} connection credentials and scopes verified.`);
      }
    } catch {
      setTestResultSuccess(false);
      onShowToast('error', `Connection test failed for ${system.name}.`);
    } finally {
      setIsTesting(false);
    }
  };

  const handleSyncNow = async () => {
    setIsSyncing(true);
    setSyncStepText('Connecting...');
    await new Promise((r) => setTimeout(r, 400));
    setSyncStepText('Fetching repositories & branches...');
    await new Promise((r) => setTimeout(r, 500));
    setSyncStepText('Fetching pull requests & reviews...');
    await new Promise((r) => setTimeout(r, 600));
    setSyncStepText('Fetching CI/CD pipeline runs...');
    await new Promise((r) => setTimeout(r, 500));
    setSyncStepText('Updating change-control monitoring state...');
    await new Promise((r) => setTimeout(r, 400));

    await integrationService.syncSystem(system.id);
    setIsSyncing(false);
    setSyncStepText('');
    onShowToast('success', `${system.name} synchronization completed.`, 'Sync Completed');
    if (onSystemUpdated) onSystemUpdated();
  };

  const handleToggleMonitoring = async () => {
    const updated = await integrationService.toggleMonitoring(system.id);
    if (updated) {
      if (updated.monitoringStatus === 'active') {
        onShowToast('success', `Continuous monitoring resumed for ${system.name}.`);
      } else {
        onShowToast('warning', `Continuous monitoring paused for ${system.name}.`);
      }
      if (onSystemUpdated) onSystemUpdated();
    }
  };

  const handleSaveEdit = async () => {
    await integrationService.updateSystem(system.id, { owner: ownerInput });
    setIsEditing(false);
    onShowToast('success', 'System configuration saved.');
    if (onSystemUpdated) onSystemUpdated();
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/25 backdrop-blur-xs transition-opacity"
        onClick={onClose}
      />

      <div className="fixed inset-y-0 right-0 max-w-full flex pl-10">
        <div
          id="manage-system-drawer"
          className="w-[460px] max-w-md bg-white border-l border-[#E8E9ED] shadow-xl flex flex-col justify-between overflow-hidden"
        >
          {/* Header */}
          <div className="px-6 py-5 border-b border-[#E8E9ED] flex items-center justify-between">
            <div>
              <h3 className="text-[16px] font-semibold text-[#24262B] leading-tight">
                Manage {system.name}
              </h3>
              <p className="text-[12px] text-[#8B8F98] leading-tight mt-0.5">
                System parameters, authentication, and continuous sync
              </p>
            </div>
            <button
              onClick={onClose}
              className="text-[#8B8F98] hover:text-[#24262B] p-1.5 rounded transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Body */}
          <div className="flex-1 overflow-y-auto p-6 space-y-6">
            {/* Sync Progress Status Banner */}
            {isSyncing && (
              <div className="p-3.5 bg-[#EEF2FF] border border-[#C9D5FA] rounded-lg flex items-center gap-3">
                <RefreshCw className="w-4 h-4 text-[#5876D8] animate-spin shrink-0" />
                <div className="min-w-0">
                  <p className="text-[12px] font-semibold text-[#24262B] truncate">
                    Syncing {system.name}...
                  </p>
                  <p className="text-[11px] text-[#5876D8] truncate">{syncStepText}</p>
                </div>
              </div>
            )}

            {/* Section 1: Overview Summary */}
            <div className="bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg p-4 space-y-3 text-[12px]">
              <div className="flex justify-between items-center py-1 border-b border-[#F0F1F3]">
                <span className="text-[#666A73]">Connection</span>
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium bg-[#EAF7EF] text-[#3FA76C]">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#3FA76C]" />
                  Connected
                </span>
              </div>

              <div className="flex justify-between items-center py-1 border-b border-[#F0F1F3]">
                <span className="text-[#666A73]">Organization</span>
                <span className="font-semibold text-[#24262B]">{system.orgOrWorkspace}</span>
              </div>

              <div className="flex justify-between items-center py-1 border-b border-[#F0F1F3]">
                <span className="text-[#666A73]">System Owner</span>
                {isEditing ? (
                  <div className="flex items-center gap-1">
                    <input
                      type="text"
                      value={ownerInput}
                      onChange={(e) => setOwnerInput(e.target.value)}
                      className="px-2 py-1 text-[11px] bg-white border border-[#5876D8] rounded text-[#24262B] w-28"
                    />
                    <button
                      onClick={handleSaveEdit}
                      className="p-1 bg-[#5876D8] text-white rounded hover:bg-[#4965C5]"
                    >
                      <Check className="w-3 h-3" />
                    </button>
                  </div>
                ) : (
                  <span className="font-medium text-[#24262B]">{system.owner}</span>
                )}
              </div>

              <div className="flex justify-between items-center py-1 border-b border-[#F0F1F3]">
                <span className="text-[#666A73]">Authentication</span>
                <div className="text-right">
                  <span className="font-medium text-[#24262B] block">Personal Access Token</span>
                  <span className="font-mono text-[10px] text-[#8B8F98]">{system.tokenPreview}</span>
                </div>
              </div>

              <div className="flex justify-between items-center py-1 border-b border-[#F0F1F3]">
                <span className="text-[#666A73]">Repositories</span>
                <span className="font-semibold text-[#24262B]">{system.repoCount} monitored</span>
              </div>

              <div className="flex justify-between items-center py-1 border-b border-[#F0F1F3]">
                <span className="text-[#666A73]">Monitoring</span>
                <span
                  className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium ${
                    system.monitoringStatus === 'active'
                      ? 'bg-[#EEF2FF] text-[#5876D8]'
                      : 'bg-[#FFF7E6] text-[#C99532]'
                  }`}
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      system.monitoringStatus === 'active' ? 'bg-[#5876D8]' : 'bg-[#C99532]'
                    }`}
                  />
                  {system.monitoringStatus === 'active' ? 'Active' : 'Paused'}
                </span>
              </div>

              <div className="flex justify-between items-center py-1">
                <span className="text-[#666A73]">Last sync</span>
                <span className="text-[#24262B] font-medium">{system.lastSyncTime}</span>
              </div>
            </div>

            {/* Test Connection Banner if run */}
            {testResultSuccess !== null && (
              <div
                className={`p-3 rounded-lg border text-[12px] flex items-center gap-2 ${
                  testResultSuccess
                    ? 'bg-[#EAF7EF] border-[#C6EBD4] text-[#3FA76C]'
                    : 'bg-[#FDEEEE] border-[#F9CACA] text-[#D96B6B]'
                }`}
              >
                {testResultSuccess ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 shrink-0" />
                    <span>Connection and credentials verified.</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    <span>Connection verification check failed.</span>
                  </>
                )}
              </div>
            )}

            {/* Section 2: Management Actions */}
            <div className="space-y-2.5">
              <span className="text-[12px] font-semibold text-[#666A73] uppercase tracking-wider block">
                Actions
              </span>

              {/* Sync Now */}
              <button
                id="btn-drawer-sync-now"
                onClick={handleSyncNow}
                disabled={isSyncing}
                className="w-full flex items-center justify-between px-3.5 py-2.5 rounded-md border border-[#E8E9ED] bg-white hover:bg-[#FAFAFB] hover:border-[#5876D8] text-[13px] font-medium text-[#24262B] transition-all group"
              >
                <div className="flex items-center gap-2.5">
                  <RefreshCw className={`w-4 h-4 text-[#5876D8] ${isSyncing ? 'animate-spin' : ''}`} />
                  <span>Sync now</span>
                </div>
                <span className="text-[11px] text-[#8B8F98] group-hover:text-[#5876D8]">
                  Fetch latest PRs & CI runs
                </span>
              </button>

              {/* Test Connection */}
              <button
                id="btn-drawer-test-connection"
                onClick={handleTestConnection}
                disabled={isTesting}
                className="w-full flex items-center justify-between px-3.5 py-2.5 rounded-md border border-[#E8E9ED] bg-white hover:bg-[#FAFAFB] hover:border-[#5876D8] text-[13px] font-medium text-[#24262B] transition-all group"
              >
                <div className="flex items-center gap-2.5">
                  <ShieldCheck className="w-4 h-4 text-[#5876D8]" />
                  <span>{isTesting ? 'Testing connection...' : 'Test connection'}</span>
                </div>
                <span className="text-[11px] text-[#8B8F98] group-hover:text-[#5876D8]">
                  Verify PAT token
                </span>
              </button>

              {/* Edit Configuration */}
              <button
                id="btn-drawer-edit-config"
                onClick={() => {
                  setOwnerInput(system.owner);
                  setIsEditing(!isEditing);
                }}
                className="w-full flex items-center justify-between px-3.5 py-2.5 rounded-md border border-[#E8E9ED] bg-white hover:bg-[#FAFAFB] text-[13px] font-medium text-[#24262B] transition-all"
              >
                <span>{isEditing ? 'Cancel editing' : 'Edit configuration'}</span>
                <span className="text-[11px] text-[#8B8F98]">Modify owner & scopes</span>
              </button>

              {/* Pause / Resume Monitoring */}
              <button
                id="btn-drawer-toggle-monitoring"
                onClick={handleToggleMonitoring}
                className="w-full flex items-center justify-between px-3.5 py-2.5 rounded-md border border-[#E8E9ED] bg-white hover:bg-[#FAFAFB] text-[13px] font-medium text-[#24262B] transition-all"
              >
                <div className="flex items-center gap-2.5">
                  {system.monitoringStatus === 'active' ? (
                    <PauseCircle className="w-4 h-4 text-[#C99532]" />
                  ) : (
                    <PlayCircle className="w-4 h-4 text-[#3FA76C]" />
                  )}
                  <span>
                    {system.monitoringStatus === 'active' ? 'Pause monitoring' : 'Resume monitoring'}
                  </span>
                </div>
                <span className="text-[11px] text-[#8B8F98]">
                  {system.monitoringStatus === 'active' ? 'Temporarily halt sync' : 'Resume live evaluation'}
                </span>
              </button>

              {/* Delete System */}
              <button
                id="btn-drawer-delete-system"
                onClick={() => {
                  onClose();
                  onOpenDeleteModal(system);
                }}
                className="w-full flex items-center justify-between px-3.5 py-2.5 rounded-md border border-[#FDEEEE] bg-white hover:bg-[#FDEEEE] text-[13px] font-medium text-[#D96B6B] transition-all group"
              >
                <div className="flex items-center gap-2.5">
                  <Trash2 className="w-4 h-4 text-[#D96B6B]" />
                  <span>Delete system</span>
                </div>
                <span className="text-[11px] text-[#D96B6B]">Disconnect provider</span>
              </button>
            </div>
          </div>

          {/* Footer */}
          <div className="px-6 py-3.5 bg-[#FAFAFB] border-t border-[#E8E9ED] flex items-center justify-end">
            <button
              onClick={onClose}
              className="px-3.5 py-1.5 text-[13px] font-medium text-[#666A73] hover:text-[#24262B] bg-white border border-[#E8E9ED] rounded-md hover:bg-[#F7F8FA] transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

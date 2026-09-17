import React, { useState, useEffect } from 'react';
import { X, Sliders, Bell, Shield, Check, Flame, MessageSquare, Lock } from 'lucide-react';
import { api } from '../api';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSaveNotification?: (msg: string) => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({ isOpen, onClose, onSaveNotification }) => {
  const [syncInterval, setSyncInterval] = useState('10');
  const [slaDays, setSlaDays] = useState('2');
  const [autoRecheck, setAutoRecheck] = useState(true);
  const [enableEmailAlerts, setEnableEmailAlerts] = useState(true);
  const [enableSlackAlerts, setEnableSlackAlerts] = useState(true);
  const [slackChannel, setSlackChannel] = useState('#compliance-advisory');
  const [emergencyBypass, setEmergencyBypass] = useState(true);
  const [requireGPG, setRequireGPG] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [savedToast, setSavedToast] = useState(false);

  useEffect(() => {
    if (isOpen) {
      api.get('/settings').then((res) => {
        if (res.data) {
          const d = res.data;
          if (d.polling_interval_minutes !== undefined) setSyncInterval(String(d.polling_interval_minutes));
          if (d.finding_sla_days !== undefined) setSlaDays(String(d.finding_sla_days));
          if (d.auto_recheck_on_events !== undefined) setAutoRecheck(d.auto_recheck_on_events);
          if (d.email_breach_alerts !== undefined) setEnableEmailAlerts(d.email_breach_alerts);
          if (d.slack_breach_alerts !== undefined) setEnableSlackAlerts(d.slack_breach_alerts);
          if (d.slack_channel !== undefined) setSlackChannel(d.slack_channel);
          if (d.emergency_hotfix_bypass !== undefined) setEmergencyBypass(d.emergency_hotfix_bypass);
          if (d.require_gpg_signatures !== undefined) setRequireGPG(d.require_gpg_signatures);
        }
      }).catch((e) => console.error('Error loading settings:', e));
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleSave = async () => {
    setIsSaving(true);
    try {
      await api.post('/settings', {
        polling_interval_minutes: parseInt(syncInterval, 10),
        finding_sla_days: parseInt(slaDays, 10),
        auto_recheck_on_events: autoRecheck,
        email_breach_alerts: enableEmailAlerts,
        slack_breach_alerts: enableSlackAlerts,
        slack_channel: slackChannel,
        emergency_hotfix_bypass: emergencyBypass,
        require_gpg_signatures: requireGPG,
      });

      setSavedToast(true);
      if (onSaveNotification) {
        onSaveNotification('Change management & compliance preferences saved.');
      }
      setTimeout(() => {
        setSavedToast(false);
        onClose();
      }, 600);
    } catch (e) {
      console.error('Error saving settings:', e);
      if (onSaveNotification) {
        onSaveNotification('Failed to save settings to backend.');
      }
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/35 backdrop-blur-xs">
      <div
        id="settings-modal"
        className="w-full max-w-lg bg-white rounded-xl border border-[#E8E9ED] shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-[#E8E9ED] flex items-center justify-between bg-[#FAFAFB]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-[#EEF2FF] border border-[#C9D5FA] text-[#5876D8] flex items-center justify-center">
              <Sliders className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-[15px] font-semibold text-[#24262B]">
                Change Management Settings
              </h3>
              <p className="text-[11px] text-[#8B8F98]">
                Continuous monitoring thresholds, SLA policies & alerting
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-[#8B8F98] hover:text-[#24262B] p-1.5 rounded-md hover:bg-gray-100 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-5 overflow-y-auto">
          {/* Sync Frequency */}
          <div>
            <label className="block text-[13px] font-medium text-[#24262B] mb-1">
              Continuous Polling & Webhook Re-sync Interval
            </label>
            <select
              value={syncInterval}
              onChange={(e) => setSyncInterval(e.target.value)}
              className="w-full text-[13px] text-[#24262B] bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg px-3 py-2 focus:outline-none focus:border-[#5876D8]"
            >
              <option value="5">Every 5 minutes (High Assurance Continuous Polling)</option>
              <option value="10">Every 10 minutes (Standard Default)</option>
              <option value="30">Every 30 minutes</option>
              <option value="60">Hourly</option>
            </select>
            <p className="text-[11px] text-[#8B8F98] mt-1">
              Periodic sync automatically polls GitHub APIs in addition to real-time webhook triggers.
            </p>
          </div>

          {/* Finding Remediation SLA */}
          <div>
            <label className="block text-[13px] font-medium text-[#24262B] mb-1">
              Default Non-Compliant Finding SLA (Days)
            </label>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min="1"
                max="30"
                value={slaDays}
                onChange={(e) => setSlaDays(e.target.value)}
                className="w-28 text-[13px] text-[#24262B] bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg px-3 py-2 focus:outline-none focus:border-[#5876D8]"
              />
              <span className="text-[12px] text-[#666A73]">days to remediate before flagged as Overdue</span>
            </div>
            <p className="text-[11px] text-[#8B8F98] mt-1">
              Updating this recalculates resolution deadlines across all active findings.
            </p>
          </div>

          {/* Automated Rechecks */}
          <div className="pt-3 border-t border-[#F0F1F3]">
            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={autoRecheck}
                onChange={(e) => setAutoRecheck(e.target.checked)}
                className="mt-0.5 rounded text-[#5876D8] focus:ring-[#5876D8]"
              />
              <div>
                <span className="text-[13px] font-medium text-[#24262B]">
                  Auto-recheck controls on webhook events
                </span>
                <p className="text-[11px] text-[#8B8F98]">
                  Automatically re-evaluates controls (CM-001 - CM-015) when PRs are approved or CI passes.
                </p>
              </div>
            </label>
          </div>

          {/* Emergency Hotfix Policy (SOC 2 CC8.1) */}
          <div className="pt-3 border-t border-[#F0F1F3]">
            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={emergencyBypass}
                onChange={(e) => setEmergencyBypass(e.target.checked)}
                className="mt-0.5 rounded text-[#5876D8] focus:ring-[#5876D8]"
              />
              <div>
                <div className="flex items-center gap-1.5">
                  <span className="text-[13px] font-medium text-[#24262B]">
                    Emergency Hotfix Exception Rule (SOC 2 CC8.1)
                  </span>
                  <Flame className="w-3.5 h-3.5 text-[#E67E22]" />
                </div>
                <p className="text-[11px] text-[#8B8F98]">
                  Allows accelerated deployment for branches tagged with <code className="bg-gray-100 px-1 py-0.5 rounded font-mono text-[10px]">hotfix/*</code> with mandatory retrospective review within 24 hours.
                </p>
              </div>
            </label>
          </div>

          {/* Cryptographic Commit Signing (GPG) */}
          <div className="pt-3 border-t border-[#F0F1F3]">
            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={requireGPG}
                onChange={(e) => setRequireGPG(e.target.checked)}
                className="mt-0.5 rounded text-[#5876D8] focus:ring-[#5876D8]"
              />
              <div>
                <div className="flex items-center gap-1.5">
                  <span className="text-[13px] font-medium text-[#24262B]">
                    Enforce GPG Commit Signature Verification
                  </span>
                  <Lock className="w-3.5 h-3.5 text-[#5876D8]" />
                </div>
                <p className="text-[11px] text-[#8B8F98]">
                  Requires all commits to be cryptographically signed with verified developer GPG keys.
                </p>
              </div>
            </label>
          </div>

          {/* Notifications */}
          <div className="pt-3 border-t border-[#F0F1F3] space-y-2.5">
            <span className="text-[13px] font-medium text-[#24262B] block">
              Control Breach & Audit Notifications
            </span>
            <label className="flex items-center gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={enableEmailAlerts}
                onChange={(e) => setEnableEmailAlerts(e.target.checked)}
                className="rounded text-[#5876D8] focus:ring-[#5876D8]"
              />
              <span className="text-[12px] text-[#666A73]">
                Email repository owners upon unapproved direct merges or pipeline failures
              </span>
            </label>
            <label className="flex items-center gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={enableSlackAlerts}
                onChange={(e) => setEnableSlackAlerts(e.target.checked)}
                className="rounded text-[#5876D8] focus:ring-[#5876D8]"
              />
              <span className="text-[12px] text-[#666A73]">
                Send instant alerts to Slack change advisory channel
              </span>
            </label>

            {enableSlackAlerts && (
              <div className="pl-6 pt-1">
                <div className="flex items-center gap-2">
                  <MessageSquare className="w-3.5 h-3.5 text-[#8B8F98]" />
                  <input
                    type="text"
                    value={slackChannel}
                    onChange={(e) => setSlackChannel(e.target.value)}
                    placeholder="#compliance-alerts"
                    className="w-64 text-[12px] text-[#24262B] bg-[#FAFAFB] border border-[#E8E9ED] rounded-md px-2.5 py-1.5 focus:outline-none focus:border-[#5876D8]"
                  />
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-[#FAFAFB] border-t border-[#E8E9ED] flex items-center justify-end gap-2.5">
          <button
            onClick={onClose}
            className="px-4 py-2 text-[13px] font-medium text-[#666A73] hover:text-[#24262B] bg-white border border-[#E8E9ED] rounded-lg hover:bg-[#F7F8FA] transition-colors"
          >
            Cancel
          </button>
          <button
            id="btn-save-settings"
            onClick={handleSave}
            disabled={isSaving}
            className="px-4 py-2 text-[13px] font-medium text-white bg-[#5876D8] hover:bg-[#4965C5] rounded-lg shadow-xs transition-colors flex items-center gap-1.5 disabled:opacity-50"
          >
            {savedToast ? <Check className="w-3.5 h-3.5" /> : null}
            <span>{isSaving ? 'Saving...' : 'Save Preferences'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};

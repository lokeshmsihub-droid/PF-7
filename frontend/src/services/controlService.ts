import { Control, ControlEvidence } from '../types';
import { api } from '../api';

const listeners: (() => void)[] = [];

function notifyListeners() {
  listeners.forEach((listener) => listener());
}

export const controlService = {
  subscribe(listener: () => void) {
    listeners.push(listener);
    return () => {
      const idx = listeners.indexOf(listener);
      if (idx !== -1) listeners.splice(idx, 1);
    };
  },

  async getControls(systemId?: string): Promise<Control[]> {
    try {
      const url = systemId ? `/controls/overview?system_id=${systemId}` : '/controls/overview';
      const res = await api.get(url);
      const data = res.data;

      return (data || []).map((c: any) => ({
        id: c.check_id,
        systemId: systemId || 'sys-github',
        controlCode: c.check_id,
        title: c.name,
        description: `Category: ${c.category} | Severity: ${c.severity}`,
        status: c.status === 'NOT_EVALUATED' ? 'INSUFFICIENT_DATA' : c.status,
        pendingCount: c.pending_count || 0,
        requirementText: c.expected || 'Maintain compliance according to policy.',
        observedText: c.observed || 'No observations recorded.',
        relatedChange: {
          changeId: c.related_change?.change_id || 'N/A',
          title: c.related_change?.title || c.name,
          repoName: c.related_change?.repo_name || 'Monitored Repository',
          prNumber: c.related_change?.pr_number || 'N/A',
          commitSha: c.related_change?.commit_sha || 'N/A',
          ciPipelineId: c.related_change?.ci_pipeline_id || 'N/A',
          deploymentId: c.related_change?.deployment_id || 'N/A',
        },
        evidenceItems: (c.evidence_items || []).map((e: any) => ({
          type: e.evidence_type,
          title: e.source_record_id || e.evidence_id,
          status: e.status || 'verified',
          details: e.details || `Storage Reference: ${e.storage_reference}`,
        })),
        findingSummary: c.finding_summary || 'No active findings.',
        remediation: {
          title: c.remediation?.title || '',
          steps: c.remediation?.steps || [],
          owner: c.remediation?.owner || '',
          slaDaysRemaining: c.remediation?.sla_days_remaining || 0,
          slaDate: c.remediation?.sla_date || '',
        },
        lastEvaluated: c.last_evaluated || 'Recently',
      }));
    } catch (error) {
      console.error('Error fetching controls overview:', error);
      return [];
    }
  },

  async getControl(id: string): Promise<Control | undefined> {
    const controls = await this.getControls();
    return controls.find(c => c.id === id || c.controlCode === id);
  },

  async recheckControl(id: string): Promise<{ success: boolean; control: Control }> {
    try {
      // First, get the control to find if there's a finding
      const controls = await this.getControls();
      const control = controls.find(c => c.id === id || c.controlCode === id);

      if (!control) throw new Error('Control not found');

      // The backend expects a finding_id for recheck.
      // We need to fetch findings to get the finding_id for this check
      const findingsRes = await api.get('/findings');
      const finding = findingsRes.data.find((f: any) => f.check_id === id && f.status === 'OPEN');

      if (finding) {
        await api.post('/remediation/recheck', {
          finding_id: finding.finding_id
        });
      } else {
        // Alternatively, trigger evaluate for the change
        if (control.relatedChange?.changeId && control.relatedChange.changeId !== 'N/A') {
          await api.post(`/changes/${control.relatedChange.changeId}/evaluate`);
        }
      }

      notifyListeners();
      
      // Fetch the updated control
      const updatedControls = await this.getControls();
      const updatedControl = updatedControls.find(c => c.id === id || c.controlCode === id) || control;

      return { success: true, control: updatedControl };
    } catch (error) {
      console.error('Error rechecking control:', error);
      throw error;
    }
  },

  async getCheckExplanation(changeId: string, checkId: string): Promise<any> {
    try {
      const res = await api.get(`/changes/${changeId}/checks/${checkId}/explanation`);
      return res.data;
    } catch (error) {
      console.error('Error fetching check explanation:', error);
      return null;
    }
  },

  async getEvidenceDetail(evidenceId: string): Promise<any> {
    try {
      const res = await api.get(`/evidence/${evidenceId}`);
      return res.data;
    } catch (error) {
      console.error('Error fetching evidence detail:', error);
      return null;
    }
  },

  async getRawEventDetail(evidenceId: string): Promise<any> {
    try {
      const res = await api.get(`/evidence/${evidenceId}/source`);
      return res.data;
    } catch (error) {
      console.error('Error fetching raw event detail:', error);
      return null;
    }
  },
};

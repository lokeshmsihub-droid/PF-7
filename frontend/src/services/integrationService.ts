import { System, ProviderType } from '../types';
import { api } from '../api';

const listeners: (() => void)[] = [];

function notifyListeners() {
  listeners.forEach((listener) => listener());
}

export const integrationService = {
  subscribe(listener: () => void) {
    listeners.push(listener);
    return () => {
      const idx = listeners.indexOf(listener);
      if (idx !== -1) listeners.splice(idx, 1);
    };
  },

  async getSystems(): Promise<System[]> {
    try {
      let integrations: any[] = [];
      let summaries: any[] = [];
      
      try {
        const intRes = await api.get('/integrations');
        integrations = intRes.data || [];
      } catch (e) {
        console.error('Error fetching /integrations', e);
      }

      try {
        const sumRes = await api.get('/systems/summary');
        summaries = sumRes.data || [];
      } catch (e) {
        console.error('Error fetching /systems/summary', e);
      }

      if (!integrations || integrations.length === 0) {
        return [];
      }

      return integrations.map((integration) => {
        const providerName = (integration.connector_type || integration.connector_id || 'github').toLowerCase();
        const summary = summaries.find(s => (s.provider || '').toLowerCase() === providerName) || {};
        const isTicketing = providerName === 'jira';

        const rawStatus = (integration.status || 'ACTIVE').toUpperCase();
        const isConnected = rawStatus === 'ACTIVE' || rawStatus === 'CONNECTED';

        // Format clean site domain for Jira (e.g. acme.atlassian.net)
        let displayDomain = integration.config?.organization || summary.organization || 'Test_Engineering';
        if (isTicketing) {
          if (integration.config?.site_url) {
            try {
              const u = new URL(integration.config.site_url);
              displayDomain = u.hostname;
            } catch {
              displayDomain = integration.config.site_url.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
            }
          } else if (integration.config?.site_name) {
            displayDomain = `${integration.config.site_name.toLowerCase().replace(/\s+/g, '-')}.atlassian.net`;
          } else {
            displayDomain = 'acme.atlassian.net';
          }
        }

        const projectsCount = isTicketing ? (integration.config?.projects?.length || 2) : undefined;
        const changeRequestsCount = isTicketing ? (summary.changes || 12) : undefined;
        const approvalsCount = isTicketing ? 12 : undefined;

        return {
          id: integration.account_id,
          name: integration.name || (isTicketing ? 'Jira - Engineering Change Management' : (providerName === 'github' ? 'GitHub' : 'Jira')),
          provider: providerName as ProviderType,
          category: isTicketing ? 'ticketing' : 'repo',
          owner: integration.config?.owner || summary.owner || (isTicketing ? 'Engineering' : 'Vetri'),
          orgOrWorkspace: displayDomain,
          siteUrl: integration.config?.site_url || (isTicketing ? 'https://snsgroups-team-ldh2bqa5.atlassian.net' : undefined),
          projectsCount,
          changeRequestsCount,
          approvalsCount,
          repoCount: isTicketing ? (projectsCount || 2) : (integration.config?.repositories ? integration.config.repositories.length : (summary.repos !== '--' ? (summary.repos || 5) : 5)),
          pullRequestCount: isTicketing ? (changeRequestsCount || 12) : (summary.prs || 1),
          pendingTaskCount: summary.pending_tasks || (isTicketing ? 3 : 3),
          failingTaskCount: 0,
          criticalTaskCount: 0,
          dueTaskCount: 0,
          connectionStatus: isConnected ? 'connected' : 'error',
          monitoringStatus: isConnected ? 'active' : 'paused',
          lastSyncTime: 'Recently',
          nextSyncTime: '10 minutes',
          tokenPreview: '••••••••••••••••••••••••••••••••',
          isContinuousMonitoring: integration.config?.monitor_prs ?? true,
          monitorPRs: integration.config?.monitor_prs ?? true,
          monitorReviews: integration.config?.monitor_reviews ?? true,
          monitorCICD: integration.config?.monitor_ci ?? true,
          monitorDeployments: integration.config?.monitor_deployments ?? true,
          repoScope: integration.config?.repository_scope || 'all',
          selectedReposList: integration.config?.repositories || [],
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
      });
    } catch (error) {
      console.error('Error fetching systems:', error);
      return [];
    }
  },

  async getSystem(id: string): Promise<System | undefined> {
    const systems = await this.getSystems();
    return systems.find(s => s.id === id);
  },

  async testConnection(provider: ProviderType, org: string, token: string, systemId?: string): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      if (systemId) {
        const res = await api.post(`/integrations/${systemId}/test`);
        if (res.data.status === 'connected') {
          return {
            success: true,
            data: {
              organization: res.data.details?.organization || org || 'Test_Engineering',
              repositories: res.data.details?.repositories ?? 5,
              pullRequests: res.data.details?.pullRequests ?? 1,
              workflowAccess: res.data.details?.workflowAccess || 'Available',
              deploymentAccess: res.data.details?.deploymentAccess || 'Available',
            }
          };
        } else {
          return { success: false, error: res.data.message || 'Connection failed' };
        }
      }

      const tempId = `temp-${Date.now()}`;
      await api.post('/integrations', {
        account_id: tempId,
        name: 'Test Connection',
        auth_type: 'token',
        config: { organization: org, token, mock: false },
        connector_type: provider
      });

      const res = await api.post(`/integrations/${tempId}/test`);
      
      // Cleanup temp
      await api.delete(`/integrations/${tempId}`);

      if (res.data.status === 'connected') {
         return {
            success: true,
            data: {
              organization: res.data.details?.organization || org || 'Test_Engineering',
              repositories: res.data.details?.repositories ?? 0,
              pullRequests: res.data.details?.pullRequests ?? 0,
              workflowAccess: res.data.details?.workflowAccess || 'Available',
              deploymentAccess: res.data.details?.deploymentAccess || 'Available',
            }
         };
      } else {
         return { success: false, error: res.data.message || 'Connection failed' };
      }
    } catch (error: any) {
      return { success: false, error: error.response?.data?.detail || error.message || 'Error testing connection' };
    }
  },

  async discoverRepositories(params: {
    provider: ProviderType;
    token?: string;
    organization?: string;
  }): Promise<Array<{ id: number | string; name: string; full_name: string; private: boolean; html_url?: string }>> {
    try {
      const res = await api.post('/integrations/discover-repositories', params);
      return res.data?.repositories || [];
    } catch (e) {
      console.error('Error discovering repositories:', e);
      return [];
    }
  },

  async createSystem(payload: {
    name: string;
    provider: ProviderType;
    orgOrWorkspace: string;
    owner: string;
    repoScope: 'all' | 'selected';
    selectedRepos?: string[];
    isContinuousMonitoring: boolean;
    monitorPRs: boolean;
    monitorReviews: boolean;
    monitorCICD: boolean;
    monitorDeployments: boolean;
    token?: string;
    directRepoUrl?: string;
  }): Promise<System> {
    const accountId = `sys-${payload.provider}-${Date.now()}`;
    const allRepos = [...(payload.selectedRepos || [])];
    if (payload.directRepoUrl && !allRepos.includes(payload.directRepoUrl)) {
      allRepos.push(payload.directRepoUrl);
    }
    const config = {
      organization: payload.orgOrWorkspace,
      owner: payload.owner,
      repository_scope: payload.repoScope,
      repositories: allRepos,
      direct_repo_url: payload.directRepoUrl,
      monitor_prs: payload.monitorPRs,
      monitor_reviews: payload.monitorReviews,
      monitor_ci: payload.monitorCICD,
      monitor_deployments: payload.monitorDeployments,
      token: payload.token
    };

    await api.post('/integrations', {
      account_id: accountId,
      name: payload.name,
      auth_type: 'token',
      config,
      connector_type: payload.provider
    });

    // Also trigger initial sync immediately after creation
    try {
      await api.post(`/integrations/${accountId}/sync`, {});
    } catch(e) {
      console.error('Initial sync failed', e);
    }

    notifyListeners();
    // Return a dummy system, the real one will be fetched on next getSystems
    return {
      id: accountId,
      name: payload.name,
      provider: payload.provider,
      category: payload.provider === 'jira' ? 'ticketing' : 'repo',
      owner: payload.owner,
      orgOrWorkspace: payload.orgOrWorkspace,
      repoCount: 0,
      pullRequestCount: 0,
      pendingTaskCount: 0,
      failingTaskCount: 0,
      criticalTaskCount: 0,
      dueTaskCount: 0,
      connectionStatus: 'connected',
      monitoringStatus: 'active',
      lastSyncTime: 'Just now',
      nextSyncTime: '10 minutes',
      tokenPreview: '••••••••••••••••••••••••••••••••',
      isContinuousMonitoring: payload.isContinuousMonitoring,
      monitorPRs: payload.monitorPRs,
      monitorReviews: payload.monitorReviews,
      monitorCICD: payload.monitorCICD,
      monitorDeployments: payload.monitorDeployments,
      repoScope: payload.repoScope,
      selectedReposList: payload.selectedRepos,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
  },

  async updateSystem(id: string, updates: Partial<System>): Promise<System | null> {
    // We would need to fetch the current config, update it, and PUT it back
    // For simplicity, just notify listeners so they refetch
    // This is a partial implementation since the original mock just updated memory
    notifyListeners();
    const system = await this.getSystem(id);
    return system || null;
  },

  async deleteSystem(id: string): Promise<boolean> {
    try {
      await api.delete(`/integrations/${id}`);
      notifyListeners();
      return true;
    } catch (e) {
      return false;
    }
  },

  async syncSystem(id: string): Promise<{ success: boolean; lastSync: string }> {
    try {
      await api.post(`/integrations/${id}/sync`, {});
      notifyListeners();
      return { success: true, lastSync: 'Just now' };
    } catch (e) {
      return { success: false, lastSync: 'Failed' };
    }
  },

  async toggleMonitoring(id: string): Promise<System | null> {
    notifyListeners();
    return this.getSystem(id);
  },

  // Jira OAuth & Configuration API methods
  async startJiraOAuth(redirectUrl: string = '/systems'): Promise<{ authorization_url: string; state: string; mock: boolean }> {
    const res = await api.post('/integrations/jira/oauth/start', { redirect_url: redirectUrl });
    return res.data;
  },

  async getJiraSites(accountId: string): Promise<any[]> {
    const res = await api.get(`/integrations/${accountId}/jira/sites`);
    return res.data || [];
  },

  async getJiraProjects(accountId: string): Promise<any[]> {
    const res = await api.get(`/integrations/${accountId}/jira/projects`);
    return res.data || [];
  },

  async getJiraIssueTypes(accountId: string, projectKey?: string): Promise<any[]> {
    const res = await api.get(`/integrations/${accountId}/jira/issue-types`, {
      params: { project_key: projectKey }
    });
    return res.data || [];
  },

  async getJiraFields(accountId: string): Promise<any[]> {
    const res = await api.get(`/integrations/${accountId}/jira/fields`);
    return res.data || [];
  },

  async getJiraConfig(accountId: string): Promise<any> {
    const res = await api.get(`/integrations/${accountId}/jira/config`);
    return res.data;
  },

  async updateJiraConfig(accountId: string, config: any): Promise<any> {
    const res = await api.put(`/integrations/${accountId}/jira/config`, config);
    notifyListeners();
    return res.data;
  },

  // Jira Compliance, Data Lineage & Evidence APIs
  async getJiraSummary(systemId: string): Promise<any> {
    const res = await api.get(`/systems/${systemId}/jira/summary`);
    return res.data;
  },

  async getJiraCoverage(systemId: string): Promise<any> {
    const res = await api.get(`/systems/${systemId}/jira/coverage`);
    return res.data;
  },

  async getJiraChanges(systemId: string, filters?: any): Promise<any[]> {
    const res = await api.get(`/systems/${systemId}/jira/changes`, { params: filters });
    return res.data || [];
  },

  async getJiraChangeDetails(systemId: string, changeId: string): Promise<any> {
    const res = await api.get(`/systems/${systemId}/jira/changes/${changeId}`);
    return res.data;
  },

  async getJiraChangelog(systemId: string, changeId: string): Promise<any[]> {
    const res = await api.get(`/systems/${systemId}/jira/changes/${changeId}/changelog`);
    return res.data || [];
  },

  async getJiraTimeline(systemId: string, changeId: string): Promise<any[]> {
    const res = await api.get(`/systems/${systemId}/jira/changes/${changeId}/timeline`);
    return res.data || [];
  },

  async getJiraApprovals(systemId: string): Promise<any[]> {
    const res = await api.get(`/systems/${systemId}/jira/approvals`);
    return res.data || [];
  },

  async getJiraTraceability(systemId: string): Promise<any[]> {
    const res = await api.get(`/systems/${systemId}/jira/traceability`);
    return res.data || [];
  },

  async getJiraMonitoring(systemId: string): Promise<any> {
    const res = await api.get(`/systems/${systemId}/jira/monitoring`);
    return res.data;
  },

  async getJiraEvents(systemId: string, filters?: any): Promise<any[]> {
    const res = await api.get(`/systems/${systemId}/jira/events`, { params: filters });
    return res.data || [];
  },

  async getJiraFieldMappings(systemId: string): Promise<any[]> {
    const res = await api.get(`/systems/${systemId}/jira/field-mappings`);
    return res.data || [];
  },

  async getRawEvidence(evidenceId: string): Promise<any> {
    const res = await api.get(`/evidence/${evidenceId}/raw`);
    return res.data;
  },
};


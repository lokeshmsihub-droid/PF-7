import { Repository, PullRequest, Pipeline } from '../types';
import { api } from '../api';

export const changeService = {
  async getRepositories(systemId?: string): Promise<Repository[]> {
    if (!systemId || systemId === 'sys-jira') return [];
    
    try {
      const res = await api.get(`/integrations/${systemId}/repositories`);
      return res.data || [];
    } catch (e) {
      console.error('Error fetching repositories', e);
      return [];
    }
  },

  async getPullRequests(systemId?: string): Promise<PullRequest[]> {
    if (systemId && systemId.startsWith('sys-github')) {
      try {
        const res = await api.get(`/integrations/${systemId}/pull-requests`);
        if (res.data && res.data.length > 0) {
          return res.data;
        }
      } catch (e) {
        console.error('Error fetching integration PRs:', e);
      }
    }

    try {
      const res = await api.get('/changes');
      const changes = res.data;
      const prChanges = changes.filter((c: any) => c.change_id.startsWith('chg-pr-'));
      const listToMap = prChanges.length > 0 ? prChanges : changes;

      return listToMap.map((c: any) => {
        return {
          id: c.change_id,
          systemId: systemId || 'sys-github',
          repoId: c.application_id || 'repo-1',
          repoName: c.application_id || 'Unknown Repo',
          prNumber: (c.change_id || '').split('-').pop() || '0',
          title: c.title || 'Untitled Change',
          author: c.requester_id || 'Unknown',
          reviewers: c.owner_id ? [
            { name: c.owner_id, approved: c.status === 'APPROVED' || c.status === 'CLOSED' }
          ] : [],
          approvalStatus: c.status === 'APPROVED' || c.status === 'CLOSED' ? 'Approved' : 'Pending Review',
          ciStatus: c.compliance_status === 'COMPLIANT' ? 'PASS' : (c.compliance_status === 'NON_COMPLIANT' ? 'FAIL' : 'PENDING'),
          branch: c.source_branch || 'main',
          targetBranch: c.target_branch || 'main',
          updatedTime: c.last_evaluated_at || c.implemented_at || new Date().toISOString(),
          linkedJiraIssue: c.source === 'jira' ? c.change_id : undefined
        };
      });
    } catch (error) {
      console.error('Error fetching changes/pull requests:', error);
      return [];
    }
  },

  async getPipelines(systemId?: string): Promise<Pipeline[]> {
    if (systemId === 'sys-jira') return [];
    try {
      const targetId = systemId || 'sys-github-1788179572727';
      const response = await api.get(`/integrations/${targetId}/pipelines`);
      return response.data;
    } catch (error) {
      console.error('Error fetching pipelines:', error);
      return [];
    }
  },

  async getChanges(): Promise<any[]> {
    try {
      const response = await api.get('/changes');
      return response.data || [];
    } catch (error) {
      console.error('Error fetching changes:', error);
      return [];
    }
  },
};

import React, { useState } from 'react';
import { RefreshCw, Activity, CheckCircle2, AlertTriangle, AlertCircle, GitPullRequest, Play, ShieldAlert, Clock, Search } from 'lucide-react';
import { MonitoringEvent, MonitoringOverview } from '../types';

interface SystemMonitoringGlobalTabProps {
  overview: MonitoringOverview;
  events: MonitoringEvent[];
  onRefresh: () => void;
  isRefreshing?: boolean;
}

export const SystemMonitoringGlobalTab: React.FC<SystemMonitoringGlobalTabProps> = ({
  overview,
  events,
  onRefresh,
  isRefreshing = false,
}) => {
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const filteredEvents = events.filter((evt) => {
    if (filterCategory !== 'all' && evt.category !== filterCategory) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        evt.title.toLowerCase().includes(q) ||
        (evt.description && evt.description.toLowerCase().includes(q)) ||
        evt.timeString.includes(q)
      );
    }
    return true;
  });

  return (
    <div id="monitoring-global-view" className="space-y-6">
      {/* Top Health & Sync Card */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Continuous Webhooks */}
        <div className="bg-white border border-[#E8E9ED] rounded-lg p-4 space-y-1.5 shadow-2xs">
          <div className="flex items-center justify-between">
            <span className="text-[12px] font-semibold text-[#666A73]">Continuous Webhooks</span>
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium bg-[#EAF7EF] text-[#3FA76C]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#3FA76C]" />
              Active
            </span>
          </div>
          <p className="text-[18px] font-bold text-[#24262B]">
            {overview.activeSystems} providers listening
          </p>
          <p className="text-[11px] text-[#8B8F98]">
            GitHub, GitLab, Bitbucket & Jira real-time payload listener
          </p>
        </div>

        {/* Periodic Sync */}
        <div className="bg-white border border-[#E8E9ED] rounded-lg p-4 space-y-1.5 shadow-2xs">
          <div className="flex items-center justify-between">
            <span className="text-[12px] font-semibold text-[#666A73]">Periodic Reconciliation</span>
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium bg-[#EEF2FF] text-[#5876D8]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#5876D8]" />
              Scheduled
            </span>
          </div>
          <p className="text-[18px] font-bold text-[#24262B]">
            Every 10 min
          </p>
          <p className="text-[11px] text-[#8B8F98]">
            Last sync {overview.lastSync} • Next sync in {overview.nextSync}
          </p>
        </div>

        {/* Monitoring Health */}
        <div className="bg-white border border-[#E8E9ED] rounded-lg p-4 space-y-1.5 shadow-2xs">
          <div className="flex items-center justify-between">
            <span className="text-[12px] font-semibold text-[#666A73]">Compliance Assurance</span>
            <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium ${
              overview.pendingTasks === 0 ? 'bg-[#EAF7EF] text-[#3FA76C]' : 'bg-[#FFF7E6] text-[#C99532]'
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${overview.pendingTasks === 0 ? 'bg-[#3FA76C]' : 'bg-[#C99532]'}`} />
              {overview.pendingTasks === 0 ? '0 Pending Tasks' : `${overview.pendingTasks} Pending Tasks`}
            </span>
          </div>
          <p className="text-[18px] font-bold text-[#24262B]">
            {overview.pendingTasks === 0 ? '100% Passing' : '94.2% Passing'}
          </p>
          <p className="text-[11px] text-[#8B8F98]">
            {overview.pendingTasks === 0
              ? 'All 15 change controls verified compliant'
              : `${overview.pendingTasks} pending tasks across ${overview.activeSystems || 2} connected systems (GitHub & Jira)`}
          </p>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg p-3 text-center">
          <span className="text-[11px] font-medium text-[#666A73] uppercase tracking-wider block">
            Events Processed
          </span>
          <span className="text-[20px] font-bold text-[#24262B] mt-1 block">
            {overview.eventsProcessed.toLocaleString()}
          </span>
        </div>
        <div className="bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg p-3 text-center">
          <span className="text-[11px] font-medium text-[#666A73] uppercase tracking-wider block">
            Changes Detected
          </span>
          <span className="text-[20px] font-bold text-[#24262B] mt-1 block">
            {overview.changesDetected}
          </span>
        </div>
        <div className="bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg p-3 text-center">
          <span className="text-[11px] font-medium text-[#666A73] uppercase tracking-wider block">
            Re-evaluations
          </span>
          <span className="text-[20px] font-bold text-[#24262B] mt-1 block">
            {overview.reEvaluations}
          </span>
        </div>
        <div className="bg-[#FAFAFB] border border-[#E8E9ED] rounded-lg p-3 text-center">
          <span className="text-[11px] font-medium text-[#666A73] uppercase tracking-wider block">
            Pending Tasks
          </span>
          <span className={`text-[20px] font-bold mt-1 block ${overview.pendingTasks === 0 ? 'text-[#3FA76C]' : 'text-[#C99532]'}`}>
            {overview.pendingTasks}
          </span>
        </div>
      </div>

      {/* Monitoring Activity Timeline */}
      <div className="bg-white border border-[#E8E9ED] rounded-lg p-5 shadow-2xs space-y-4">
        {/* Timeline Header & Filter Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#F0F1F3]">
          <div>
            <h3 className="text-[15px] font-semibold text-[#24262B]">
              Monitoring Activity Log
            </h3>
            <p className="text-[12px] text-[#8B8F98] mt-0.5">
              Live chronological stream of pull requests, CI pipeline outcomes, and control evaluations.
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-[#8B8F98] absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search events..."
                className="text-[12px] pl-8 pr-2.5 py-1.5 w-40 bg-[#FAFAFB] border border-[#E8E9ED] rounded-md focus:outline-none focus:border-[#5876D8] text-[#24262B]"
              />
            </div>

            <select
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value)}
              className="text-[12px] bg-[#FAFAFB] border border-[#E8E9ED] rounded-md px-2 py-1.5 text-[#24262B]"
            >
              <option value="all">All event categories</option>
              <option value="pr">Pull requests</option>
              <option value="ci">CI pipelines</option>
              <option value="evaluation">Evaluations</option>
              <option value="finding">Findings</option>
              <option value="remediation">Remediations</option>
            </select>

            <button
              onClick={onRefresh}
              className="p-1.5 text-[#666A73] hover:text-[#24262B] bg-white border border-[#E8E9ED] rounded-md hover:bg-[#FAFAFB] transition-colors"
              title="Refresh timeline"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-[#5876D8]' : ''}`} />
            </button>
          </div>
        </div>

        {/* Timeline Events List */}
        <div className="relative pl-6 space-y-5 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-[1.5px] before:bg-[#E8E9ED]">
          {filteredEvents.map((evt) => {
            let icon = <GitPullRequest className="w-3.5 h-3.5 text-[#5876D8]" />;
            let dotColor = 'bg-[#EEF2FF] border-[#C9D5FA]';

            if (evt.category === 'ci') {
              icon = <Play className="w-3 h-3 text-[#5876D8]" />;
            } else if (evt.category === 'finding' || evt.status === 'error') {
              icon = <AlertCircle className="w-3.5 h-3.5 text-[#D96B6B]" />;
              dotColor = 'bg-[#FDEEEE] border-[#F9CACA]';
            } else if (evt.category === 'remediation' || evt.status === 'warning') {
              icon = <ShieldAlert className="w-3.5 h-3.5 text-[#C99532]" />;
              dotColor = 'bg-[#FFF7E6] border-[#FFE7BA]';
            } else if (evt.category === 'sync') {
              icon = <RefreshCw className="w-3 h-3 text-[#3FA76C]" />;
              dotColor = 'bg-[#EAF7EF] border-[#C6EBD4]';
            }

            return (
              <div key={evt.id} className="relative group">
                {/* Timeline Icon Node */}
                <div
                  className={`absolute -left-6 top-0.5 w-5 h-5 rounded-full border flex items-center justify-center ${dotColor} shadow-2xs`}
                >
                  {icon}
                </div>

                <div className="text-[13px] space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[11px] font-semibold text-[#8B8F98]">
                      {evt.timeString}
                    </span>
                    <span className="font-semibold text-[#24262B]">{evt.title}</span>
                  </div>
                  {evt.description && (
                    <p className="text-[12px] text-[#666A73] leading-relaxed">
                      {evt.description}
                    </p>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

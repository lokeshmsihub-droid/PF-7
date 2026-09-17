import React, { useState, useMemo } from 'react';
import { Search, Filter, RefreshCw, Columns, ChevronDown, ChevronLeft, ChevronRight, CheckCircle2, AlertCircle } from 'lucide-react';
import { System, SystemCategory } from '../types';
import { ProviderIcon } from './ProviderIcon';

interface SystemTableProps {
  systems: System[];
  onViewDetails: (system: System) => void;
  onRefresh: () => void;
  isRefreshing?: boolean;
}

export const SystemTable: React.FC<SystemTableProps> = ({
  systems,
  onViewDetails,
  onRefresh,
  isRefreshing = false,
}) => {
  // Category sub-tabs: All systems vs Repo providers vs Ticketing providers
  const [activeCategory, setActiveCategory] = useState<SystemCategory>('all');

  const repoCount = systems.filter((s) => s.category === 'repo').length;
  const ticketingCount = systems.filter((s) => s.category === 'ticketing').length;

  // Search & Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'connected' | 'paused' | 'warning'>('all');
  const [isFilterOpen, setIsFilterOpen] = useState(false);
  const [viewDropdownOpen, setViewDropdownOpen] = useState(false);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [currentPage, setCurrentPage] = useState(1);

  // Filtered list
  const filteredSystems = useMemo(() => {
    return systems.filter((sys) => {
      // Category match
      if (activeCategory !== 'all' && sys.category !== activeCategory) return false;

      // Status filter
      if (statusFilter !== 'all' && sys.connectionStatus !== statusFilter) return false;

      // Search match
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesName = sys.name.toLowerCase().includes(query);
        const matchesOrg = sys.orgOrWorkspace.toLowerCase().includes(query);
        const matchesOwner = sys.owner.toLowerCase().includes(query);
        if (!matchesName && !matchesOrg && !matchesOwner) return false;
      }

      return true;
    });
  }, [systems, activeCategory, statusFilter, searchQuery]);

  const totalCount = filteredSystems.length;
  const startIndex = (currentPage - 1) * rowsPerPage;
  const paginatedSystems = filteredSystems.slice(startIndex, startIndex + rowsPerPage);

  return (
    <div id="systems-table-container" className="space-y-4">
      {/* Category Tabs: [ All systems ] [ Repo providers ] [ Ticketing providers ] */}
      <div className="flex items-center space-x-1.5 border-b border-[#F0F1F3] pb-3">
        <button
          id="tab-all-systems"
          onClick={() => {
            setActiveCategory('all');
            setCurrentPage(1);
          }}
          className={`px-3 py-1.5 rounded-md text-[13px] font-medium transition-all flex items-center gap-1.5 ${
            activeCategory === 'all'
              ? 'bg-[#EEF2FF] text-[#5876D8] border border-[#C9D5FA]'
              : 'text-[#666A73] hover:text-[#24262B] hover:bg-[#FAFAFB]'
          }`}
        >
          <span>All systems</span>
          <span className="text-[11px] px-1.5 py-0.2 rounded-full bg-white/70 border border-black/10">
            {systems.length}
          </span>
        </button>
        <button
          id="tab-repo-providers"
          onClick={() => {
            setActiveCategory('repo');
            setCurrentPage(1);
          }}
          className={`px-3 py-1.5 rounded-md text-[13px] font-medium transition-all flex items-center gap-1.5 ${
            activeCategory === 'repo'
              ? 'bg-[#EEF2FF] text-[#5876D8] border border-[#C9D5FA]'
              : 'text-[#666A73] hover:text-[#24262B] hover:bg-[#FAFAFB]'
          }`}
        >
          <span>Repo providers</span>
          <span className="text-[11px] px-1.5 py-0.2 rounded-full bg-white/70 border border-black/10">
            {repoCount}
          </span>
        </button>
        <button
          id="tab-ticketing-providers"
          onClick={() => {
            setActiveCategory('ticketing');
            setCurrentPage(1);
          }}
          className={`px-3 py-1.5 rounded-md text-[13px] font-medium transition-all flex items-center gap-1.5 ${
            activeCategory === 'ticketing'
              ? 'bg-[#EEF2FF] text-[#5876D8] border border-[#C9D5FA]'
              : 'text-[#666A73] hover:text-[#24262B] hover:bg-[#FAFAFB]'
          }`}
        >
          <span>Ticketing providers</span>
          <span className="text-[11px] px-1.5 py-0.2 rounded-full bg-white/70 border border-black/10">
            {ticketingCount}
          </span>
        </button>
      </div>

      {/* Control Bar (View dropdown, Filter, Search, Refresh, Column settings) */}
      <div className="flex items-center justify-between gap-3 text-[13px] pt-1">
        {/* Left: View selector */}
        <div className="relative">
          <button
            id="btn-view-dropdown"
            onClick={() => setViewDropdownOpen(!viewDropdownOpen)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-[12px] font-medium text-[#24262B] bg-[#FFFFFF] border border-[#E8E9ED] rounded-md hover:bg-[#FAFAFB] transition-colors"
          >
            <span className="text-[#666A73]">View:</span>
            <span className="capitalize">{statusFilter === 'all' ? 'All Systems' : statusFilter}</span>
            <ChevronDown className="w-3.5 h-3.5 text-[#8B8F98]" />
          </button>

          {viewDropdownOpen && (
            <div className="absolute left-0 mt-1 w-40 bg-white border border-[#E8E9ED] rounded-md shadow-md py-1 z-30">
              <button
                onClick={() => {
                  setStatusFilter('all');
                  setViewDropdownOpen(false);
                }}
                className={`w-full text-left px-3 py-1.5 text-[12px] hover:bg-[#F7F8FA] ${
                  statusFilter === 'all' ? 'text-[#5876D8] font-semibold' : 'text-[#24262B]'
                }`}
              >
                All Systems
              </button>
              <button
                onClick={() => {
                  setStatusFilter('connected');
                  setViewDropdownOpen(false);
                }}
                className={`w-full text-left px-3 py-1.5 text-[12px] hover:bg-[#F7F8FA] ${
                  statusFilter === 'connected' ? 'text-[#5876D8] font-semibold' : 'text-[#24262B]'
                }`}
              >
                Connected
              </button>
              <button
                onClick={() => {
                  setStatusFilter('paused');
                  setViewDropdownOpen(false);
                }}
                className={`w-full text-left px-3 py-1.5 text-[12px] hover:bg-[#F7F8FA] ${
                  statusFilter === 'paused' ? 'text-[#5876D8] font-semibold' : 'text-[#24262B]'
                }`}
              >
                Paused
              </button>
            </div>
          )}
        </div>

        {/* Right Controls */}
        <div className="flex items-center space-x-2">
          {/* Search Field */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-[#8B8F98] absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setCurrentPage(1);
              }}
              placeholder="Search systems..."
              className="text-[12px] pl-8 pr-2.5 py-1.5 w-44 bg-[#FAFAFB] border border-[#E8E9ED] rounded-md focus:outline-none focus:border-[#5876D8] focus:bg-white text-[#24262B] transition-all"
            />
          </div>

          {/* Filter Button */}
          <div className="relative">
            <button
              id="btn-table-filter"
              onClick={() => setIsFilterOpen(!isFilterOpen)}
              className={`flex items-center gap-1 px-2.5 py-1.5 text-[12px] font-medium rounded-md border transition-colors ${
                statusFilter !== 'all'
                  ? 'bg-[#EEF2FF] text-[#5876D8] border-[#C9D5FA]'
                  : 'bg-white text-[#666A73] border-[#E8E9ED] hover:bg-[#FAFAFB]'
              }`}
            >
              <Filter className="w-3.5 h-3.5" />
              <span>Filter</span>
            </button>

            {isFilterOpen && (
              <div className="absolute right-0 mt-1 w-52 bg-white border border-[#E8E9ED] rounded-lg shadow-lg p-3 z-30 space-y-3">
                <div className="flex items-center justify-between pb-2 border-b border-[#F0F1F3]">
                  <span className="text-[12px] font-semibold text-[#24262B]">Filter Systems</span>
                  <button
                    onClick={() => {
                      setStatusFilter('all');
                      setSearchQuery('');
                      setIsFilterOpen(false);
                    }}
                    className="text-[11px] text-[#5876D8] hover:underline"
                  >
                    Reset
                  </button>
                </div>

                <div>
                  <label className="block text-[11px] font-medium text-[#666A73] mb-1">
                    Connection Status
                  </label>
                  <select
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value as any)}
                    className="w-full text-[12px] bg-[#FAFAFB] border border-[#E8E9ED] rounded px-2 py-1"
                  >
                    <option value="all">All statuses</option>
                    <option value="connected">Connected</option>
                    <option value="paused">Paused</option>
                  </select>
                </div>
              </div>
            )}
          </div>

          {/* Refresh Button */}
          <button
            id="btn-table-refresh"
            onClick={onRefresh}
            title="Refresh systems"
            className="p-1.5 text-[#666A73] hover:text-[#24262B] bg-white border border-[#E8E9ED] rounded-md hover:bg-[#FAFAFB] transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-[#5876D8]' : ''}`} />
          </button>

          {/* Column Settings Icon */}
          <button
            id="btn-table-columns"
            title="Column visibility"
            className="p-1.5 text-[#666A73] hover:text-[#24262B] bg-white border border-[#E8E9ED] rounded-md hover:bg-[#FAFAFB] transition-colors"
          >
            <Columns className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Main Table */}
      <div className="border border-[#E8E9ED] rounded-lg overflow-hidden bg-white shadow-2xs">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-[#E8E9ED] bg-[#FAFAFB] text-[12px] font-semibold text-[#666A73]">
              <th className="py-3 px-5 font-semibold">Provider</th>
              <th className="py-3 px-4 font-semibold">System owner</th>
              <th className="py-3 px-4 font-semibold">Workspace / Domain</th>
              <th className="py-3 px-4 font-semibold">Scope / Projects</th>
              <th className="py-3 px-4 font-semibold">Activity / Changes</th>
              <th className="py-3 px-4 font-semibold">Pending Tasks</th>
              <th className="py-3 px-5 font-semibold text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#F0F1F3] text-[13px]">
            {paginatedSystems.length > 0 ? (
              paginatedSystems.map((system) => {
                const isTicketing = system.category === 'ticketing' || system.provider === 'jira';

                return (
                  <tr
                    key={system.id}
                    className="h-[60px] hover:bg-[#FAFAFB] transition-colors group cursor-pointer"
                    onClick={() => onViewDetails(system)}
                  >
                    {/* Provider */}
                    <td className="py-3 px-5">
                      <div className="flex items-center gap-3">
                        <div className="w-7 h-7 rounded-md bg-[#FAFAFB] border border-[#E8E9ED] flex items-center justify-center">
                          <ProviderIcon provider={system.provider} size={18} />
                        </div>
                        <div>
                          <span className="font-semibold text-[#24262B] group-hover:text-[#5876D8] transition-colors block">
                            {system.name}
                          </span>
                          <span className="text-[11px] text-[#8B8F98] flex items-center gap-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-[#3FA76C]" />
                            {system.lastSyncTime}
                          </span>
                        </div>
                      </div>
                    </td>

                    {/* System owner */}
                    <td className="py-3 px-4 text-[#24262B]">
                      <span className="font-normal">{system.owner}</span>
                    </td>

                    {/* Workspace / Domain */}
                    <td className="py-3 px-4 text-[#24262B]">
                      <span className="font-normal font-mono text-[12px] text-[#475569]">
                        {system.orgOrWorkspace}
                      </span>
                    </td>

                    {/* Scope / Projects */}
                    <td className="py-3 px-4 text-[#24262B]">
                      <span className="font-medium text-[#334155]">
                        {isTicketing
                          ? `${system.projectsCount || 3} projects`
                          : `${system.repoCount} repos`}
                      </span>
                    </td>

                    {/* Activity / Changes */}
                    <td className="py-3 px-4 text-[#24262B]">
                      <span className="font-medium text-[#334155]">
                        {isTicketing
                          ? `${system.changeRequestsCount || 12} change requests`
                          : `${system.pullRequestCount} pull requests`}
                      </span>
                    </td>

                    {/* Pending Tasks */}
                    <td className="py-3 px-4">
                      {system.pendingTaskCount > 0 ? (
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[12px] font-medium bg-[#FFF7E6] text-[#C99532] border border-[#FFE7BA]">
                          <span className="w-1.5 h-1.5 rounded-full bg-[#C99532]" />
                          {system.pendingTaskCount}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[12px] font-medium text-[#3FA76C]">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          0
                        </span>
                      )}
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-5 text-right" onClick={(e) => e.stopPropagation()}>
                      <button
                        id={`btn-view-details-${system.id}`}
                        onClick={() => onViewDetails(system)}
                        className="px-2.5 py-1 text-[12px] font-medium text-[#5876D8] hover:text-[#4965C5] bg-white border border-[#C9D5FA] hover:border-[#5876D8] hover:bg-[#EEF2FF] rounded-md transition-colors shadow-2xs"
                      >
                        View details
                      </button>
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan={7} className="py-12 text-center text-[#8B8F98]">
                  <p className="text-[13px] font-medium">No systems found</p>
                  <p className="text-[11px] mt-0.5">
                    Try adjusting your filters or connecting a new change management system.
                  </p>
                </td>
              </tr>
            )}
          </tbody>
        </table>

        {/* Compact Pagination Bar */}
        <div className="px-5 py-3 border-t border-[#E8E9ED] bg-white flex items-center justify-between text-[12px] text-[#666A73]">
          {/* Bottom Left: Rows per page */}
          <div className="flex items-center space-x-2">
            <span>Rows per page</span>
            <select
              value={rowsPerPage}
              onChange={(e) => {
                setRowsPerPage(Number(e.target.value));
                setCurrentPage(1);
              }}
              className="bg-[#FAFAFB] border border-[#E8E9ED] rounded px-1.5 py-0.5 text-[11px] focus:outline-none focus:border-[#5876D8]"
            >
              <option value="5">5</option>
              <option value="10">10</option>
              <option value="25">25</option>
            </select>
          </div>

          {/* Bottom Right: Page counts & Prev/Next */}
          <div className="flex items-center space-x-3">
            <span>
              {totalCount === 0
                ? '0 of 0'
                : `${startIndex + 1}–${Math.min(startIndex + rowsPerPage, totalCount)} of ${totalCount}`}
            </span>
            <div className="flex items-center space-x-1">
              <button
                onClick={() => setCurrentPage((p) => Math.max(p - 1, 1))}
                disabled={currentPage <= 1}
                className="p-1 rounded border border-[#E8E9ED] disabled:opacity-40 hover:bg-[#FAFAFB] text-[#24262B] transition-colors"
                aria-label="Previous page"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() =>
                  setCurrentPage((p) => (p * rowsPerPage < totalCount ? p + 1 : p))
                }
                disabled={currentPage * rowsPerPage >= totalCount}
                className="p-1 rounded border border-[#E8E9ED] disabled:opacity-40 hover:bg-[#FAFAFB] text-[#24262B] transition-colors"
                aria-label="Next page"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

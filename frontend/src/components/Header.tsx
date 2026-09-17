import React from 'react';
import { ChevronRight, RefreshCw, Bell, HelpCircle } from 'lucide-react';

interface HeaderProps {
  breadcrumbs: { label: string; onClick?: () => void }[];
  onRefreshAll?: () => void;
  isRefreshing?: boolean;
}

export const Header: React.FC<HeaderProps> = ({ breadcrumbs, onRefreshAll, isRefreshing = false }) => {
  return (
    <header
      id="app-header"
      className="h-[64px] min-h-[64px] bg-[#FFFFFF] border-b border-[#E8E9ED] px-8 flex items-center justify-between sticky top-0 z-10"
    >
      {/* Breadcrumbs */}
      <nav aria-label="Breadcrumb" className="flex items-center space-x-2 text-[13px]">
        {breadcrumbs.map((crumb, idx) => {
          const isLast = idx === breadcrumbs.length - 1;
          return (
            <React.Fragment key={idx}>
              {idx > 0 && <ChevronRight className="w-3.5 h-3.5 text-[#8B8F98] shrink-0" />}
              {crumb.onClick && !isLast ? (
                <button
                  id={`breadcrumb-${idx}`}
                  onClick={crumb.onClick}
                  className="text-[#666A73] hover:text-[#5876D8] font-normal transition-colors"
                >
                  {crumb.label}
                </button>
              ) : (
                <span
                  className={`${
                    isLast ? 'text-[#24262B] font-medium' : 'text-[#666A73]'
                  }`}
                >
                  {crumb.label}
                </span>
              )}
            </React.Fragment>
          );
        })}
      </nav>

      {/* Right Actions */}
      <div className="flex items-center space-x-3">
        {onRefreshAll && (
          <button
            id="btn-global-refresh"
            onClick={onRefreshAll}
            title="Refresh continuous monitoring data"
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-[12px] font-medium text-[#666A73] hover:text-[#24262B] hover:bg-[#F7F8FA] rounded-md border border-[#E8E9ED] transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-[#5876D8]' : ''}`} />
            <span>Sync</span>
          </button>
        )}

        <div className="h-4 w-[1px] bg-[#E8E9ED]" />

        <button
          id="btn-help"
          title="Change management compliance guide"
          className="p-1.5 text-[#8B8F98] hover:text-[#24262B] hover:bg-[#F7F8FA] rounded-md transition-colors"
        >
          <HelpCircle className="w-4 h-4" />
        </button>

        <button
          id="btn-notifications"
          title="System notifications"
          className="p-1.5 text-[#8B8F98] hover:text-[#24262B] hover:bg-[#F7F8FA] rounded-md transition-colors relative"
        >
          <Bell className="w-4 h-4" />
          <span className="absolute top-1 right-1 w-2 h-2 bg-[#E89562] rounded-full ring-2 ring-white" />
        </button>
      </div>
    </header>
  );
};

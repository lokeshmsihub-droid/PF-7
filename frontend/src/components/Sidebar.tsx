import React from 'react';
import { GitBranch, Settings, ShieldCheck, ShieldAlert, ChevronRight } from 'lucide-react';

export type NavItem = 'change-management' | 'vulnerabilities' | 'settings';

interface SidebarProps {
  activeNav: NavItem;
  onSelectNav: (nav: NavItem) => void;
  onOpenSettings: () => void;
  vulnerabilityCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeNav, onSelectNav, onOpenSettings, vulnerabilityCount }) => {
  return (
    <aside
      id="app-sidebar"
      className="w-[230px] min-w-[230px] h-screen bg-[#FFFFFF] border-r border-[#E8E9ED] flex flex-col justify-between select-none z-20"
    >
      {/* Top Header & Navigation */}
      <div>
        {/* Platform Brand / Logo */}
        <div className="h-[64px] px-5 flex items-center border-b border-[#F0F1F3]">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-md bg-[#24262B] flex items-center justify-center text-white shadow-xs">
              <ShieldCheck className="w-4 h-4 text-white" />
            </div>
            <div className="flex flex-col">
              <span className="text-[14px] font-semibold text-[#24262B] tracking-tight leading-none">
                Compliance
              </span>
              <span className="text-[11px] text-[#8B8F98] font-normal leading-tight mt-0.5">
                Enterprise Assurance
              </span>
            </div>
          </div>
        </div>

        {/* Primary Navigation */}
        <div className="py-4 px-2 space-y-1">
          {/* Change Management Item */}
          <button
            id="nav-change-management"
            onClick={() => onSelectNav('change-management')}
            className={`w-full relative flex items-center gap-3 px-3.5 py-2.5 rounded-md text-[13px] font-medium transition-colors text-left ${activeNav === 'change-management'
              ? 'bg-[#F7F8FA] text-[#24262B] font-semibold'
              : 'text-[#666A73] hover:bg-[#FAFAFB] hover:text-[#24262B]'
              }`}
          >
            {/* Orange Active Indicator */}
            {activeNav === 'change-management' && (
              <span className="absolute left-0 top-1.5 bottom-1.5 w-[3px] bg-[#E89562] rounded-r" />
            )}
            <GitBranch
              className={`w-4 h-4 shrink-0 ${activeNav === 'change-management' ? 'text-[#5876D8]' : 'text-[#8B8F98]'
                }`}
            />
            <span className="truncate">Change Management</span>
          </button>

          {/* Vulnerabilities Item */}
          <button
            id="nav-vulnerabilities"
            onClick={() => onSelectNav('vulnerabilities')}
            className={`w-full relative flex items-center justify-between px-3.5 py-2.5 rounded-md text-[13px] font-medium transition-colors text-left ${activeNav === 'vulnerabilities'
              ? 'bg-[#F7F8FA] text-[#24262B] font-semibold'
              : 'text-[#666A73] hover:bg-[#FAFAFB] hover:text-[#24262B]'
              }`}
          >
            {/* Orange Active Indicator */}
            {activeNav === 'vulnerabilities' && (
              <span className="absolute left-0 top-1.5 bottom-1.5 w-[3px] bg-[#E89562] rounded-r" />
            )}
            <div className="flex items-center gap-3 min-w-0">
              <ShieldAlert
                className={`w-4 h-4 shrink-0 ${activeNav === 'vulnerabilities' ? 'text-[#DC2626]' : 'text-[#8B8F98]'
                  }`}
              />
              <span className="truncate">Vulnerabilities</span>
            </div>
            {typeof vulnerabilityCount === 'number' && vulnerabilityCount > 0 && (
              <span className="px-1.5 py-0.5 text-[10px] font-semibold rounded-full bg-[#FEF2F2] text-[#DC2626] border border-[#FCA5A5] leading-none">
                {vulnerabilityCount}
              </span>
            )}
          </button>

          {/* Settings Utility Item */}
          <button
            id="nav-settings"
            onClick={() => {
              onSelectNav('settings');
              onOpenSettings();
            }}
            className={`w-full relative flex items-center gap-3 px-3.5 py-2.5 rounded-md text-[13px] font-medium transition-colors text-left ${activeNav === 'settings'
              ? 'bg-[#F7F8FA] text-[#24262B] font-semibold'
              : 'text-[#666A73] hover:bg-[#FAFAFB] hover:text-[#24262B]'
              }`}
          >
            {activeNav === 'settings' && (
              <span className="absolute left-0 top-1.5 bottom-1.5 w-[3px] bg-[#E89562] rounded-r" />
            )}
            <Settings
              className={`w-4 h-4 shrink-0 ${activeNav === 'settings' ? 'text-[#5876D8]' : 'text-[#8B8F98]'
                }`}
            />
            <span className="truncate">Settings</span>
          </button>
        </div>
      </div>

      {/* Footer Profile / Workspace Info */}
      <div className="p-3 border-t border-[#F0F1F3]">
        <div className="flex items-center justify-between p-2 rounded-md bg-[#FAFAFB] border border-[#E8E9ED]">
          <div className="flex items-center gap-2 min-w-0">
            <div className="w-6 h-6 rounded-full bg-[#EEF2FF] border border-[#C9D5FA] text-[#5876D8] text-[11px] font-semibold flex items-center justify-center">
              LK
            </div>
            <div className="min-w-0">
              <p className="text-[12px] font-medium text-[#24262B] truncate leading-none">
                Production Space
              </p>
              <p className="text-[10px] text-[#8B8F98] truncate leading-tight mt-0.5">
                SOC2 / ISO27001
              </p>
            </div>
          </div>
          <ChevronRight className="w-3.5 h-3.5 text-[#8B8F98] shrink-0" />
        </div>
      </div>
    </aside>
  );
};

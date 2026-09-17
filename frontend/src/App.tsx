import React, { useState, useEffect, useCallback } from 'react';
import { Plus, RefreshCw, GitBranch } from 'lucide-react';
import { System, Control, ToastNotification, MonitoringOverview, MonitoringEvent } from './types';
import { integrationService } from './services/integrationService';
import { monitoringService } from './services/monitoringService';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { SystemTable } from './components/SystemTable';
import { SystemDetailsPage } from './components/SystemDetailsPage';
import { SystemMonitoringGlobalTab } from './components/SystemMonitoringGlobalTab';
import { AddSystemDrawer } from './components/AddSystemDrawer';
import { ManageSystemDrawer } from './components/ManageSystemDrawer';
import { ViewFixDrawer } from './components/ViewFixDrawer';
import { DeleteConfirmModal } from './components/DeleteConfirmModal';
import { SettingsModal } from './components/SettingsModal';
import { ToastContainer } from './components/ToastContainer';
import { VulnerabilityPage } from './components/VulnerabilityPage';
import { vulnerabilityService } from './services/vulnerabilityService';
import { NavItem } from './components/Sidebar';

type MainTopTab = 'systems' | 'monitoring';

export default function App() {
  // Navigation & View State
  const [activeNav, setActiveNav] = useState<NavItem>('change-management');
  const [activeTopTab, setActiveTopTab] = useState<MainTopTab>('systems');
  const [selectedRepoForVulns, setSelectedRepoForVulns] = useState<string | null>(null);
  const [vulnerabilityCount, setVulnerabilityCount] = useState<number>(0);
  const [selectedSystemId, setSelectedSystemId] = useState<string | null>(() => {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get('system_id') || null;
  });

  const handleSelectSystemId = (id: string | null) => {
    setSelectedSystemId(id);
    if (id) {
      localStorage.setItem('active_system_id', id);
    } else {
      localStorage.removeItem('active_system_id');
    }
  };

  // Data Store State
  const [systems, setSystems] = useState<System[]>([]);
  const [monitoringOverview, setMonitoringOverview] = useState<MonitoringOverview | null>(null);
  const [monitoringEvents, setMonitoringEvents] = useState<MonitoringEvent[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Drawers & Modals
  const [isAddDrawerOpen, setIsAddDrawerOpen] = useState(false);
  const [manageSystem, setManageSystem] = useState<System | null>(null);
  const [viewFixControl, setViewFixControl] = useState<Control | null>(null);
  const [deleteTargetSystem, setDeleteTargetSystem] = useState<System | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);

  // Toast System
  const [toasts, setToasts] = useState<ToastNotification[]>([]);

  const addToast = useCallback(
    (type: 'success' | 'info' | 'warning' | 'error', message: string, title?: string) => {
      const id = `toast-${Date.now()}-${Math.random()}`;
      const newToast: ToastNotification = { id, type, message, title };
      setToasts((prev) => [...prev, newToast]);

      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, 4000);
    },
    []
  );

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  // Fetch initial data
  const loadInitialData = useCallback(async () => {
    setIsRefreshing(true);
    const [sysList, ov, evts, findings] = await Promise.all([
      integrationService.getSystems(),
      monitoringService.getMonitoringOverview(),
      monitoringService.getMonitoringActivity(),
      vulnerabilityService.getFindings(),
    ]);
    setSystems(sysList);
    setMonitoringOverview({
      ...ov,
      activeSystems: ov.activeSystems > 0 ? ov.activeSystems : (sysList.length || 3),
    });
    setMonitoringEvents(evts);
    setVulnerabilityCount(findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH').length);
    setIsRefreshing(false);
  }, []);

  useEffect(() => {
    loadInitialData();

    // Subscribe to system store changes
    const unsubSystem = integrationService.subscribe(() => {
      integrationService.getSystems().then(setSystems);
      vulnerabilityService.getFindings().then((f) => {
        setVulnerabilityCount(f.filter((item) => item.severity === 'CRITICAL' || item.severity === 'HIGH').length);
      });
    });

    // Subscribe to continuous live monitoring events from SSE & backend
    const unsubMonitoring = monitoringService.subscribe(() => {
      integrationService.getSystems().then(setSystems);
      monitoringService.getMonitoringOverview().then(setMonitoringOverview);
      monitoringService.getMonitoringActivity().then(setMonitoringEvents);
      vulnerabilityService.getFindings().then((f) => {
        setVulnerabilityCount(f.filter((item) => item.severity === 'CRITICAL' || item.severity === 'HIGH').length);
      });
    });

    // Continuous background sync interval (polls every 10 seconds for real-time monitoring)
    const intervalId = setInterval(() => {
      integrationService.getSystems().then(setSystems);
      monitoringService.getMonitoringOverview().then(setMonitoringOverview);
    }, 10000);

    return () => {
      unsubSystem();
      unsubMonitoring();
      clearInterval(intervalId);
    };
  }, [loadInitialData]);

  // Selected system object
  const activeSystem = selectedSystemId
    ? systems.find((s) => s.id === selectedSystemId) || null
    : null;

  // Header Breadcrumbs calculation
  const breadcrumbs = activeNav === 'vulnerabilities'
    ? [
        {
          label: 'Vulnerability Management',
          onClick: () => setSelectedRepoForVulns(null),
        },
        ...(selectedRepoForVulns ? [{ label: selectedRepoForVulns }] : []),
      ]
    : activeSystem
    ? [
      {
        label: 'Change Management',
        onClick: () => {
          handleSelectSystemId(null);
          setActiveTopTab('systems');
        },
      },
      {
        label: 'Change management systems',
        onClick: () => {
          handleSelectSystemId(null);
          setActiveTopTab('systems');
        },
      },
      { label: `${activeSystem.name} (${activeSystem.orgOrWorkspace})` },
    ]
    : [
      { label: 'Change Management' },
      ...(activeTopTab === 'monitoring' ? [{ label: 'Monitoring' }] : []),
    ];

  // System deletion handler
  const handleConfirmDelete = async (systemId: string) => {
    setIsDeleting(true);
    const name = deleteTargetSystem?.name || 'System';
    await integrationService.deleteSystem(systemId);
    setIsDeleting(false);
    setDeleteTargetSystem(null);
    if (selectedSystemId === systemId) {
      handleSelectSystemId(null);
    }
    addToast('info', `${name} has been disconnected.`, 'System Disconnected');
  };

  return (
    <div className="flex h-screen w-screen bg-[#FFFFFF] overflow-hidden">
      {/* Toast Notifications */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {/* Fixed Left Sidebar */}
      <Sidebar
        activeNav={activeNav}
        onSelectNav={(nav) => {
          setActiveNav(nav);
          if (nav !== 'vulnerabilities') {
            setSelectedRepoForVulns(null);
          }
        }}
        onOpenSettings={() => setIsSettingsOpen(true)}
        vulnerabilityCount={vulnerabilityCount}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col h-screen min-w-0 bg-[#FFFFFF] overflow-hidden">
        {/* Top Header */}
        <Header
          breadcrumbs={breadcrumbs}
          onRefreshAll={async () => {
            setIsRefreshing(true);
            await loadInitialData();
            addToast('success', 'Synchronized change-control status and repository security posture.');
          }}
          isRefreshing={isRefreshing}
        />

        {/* Scrollable Main Body */}
        <main className="flex-1 overflow-y-auto px-8 py-6">
          <div className="max-w-[1240px] mx-auto space-y-6">
            {/* View Switching */}
            {activeNav === 'vulnerabilities' ? (
              <VulnerabilityPage
                onShowToast={addToast}
                filterRepoName={selectedRepoForVulns}
                onOpenAddSystem={() => setIsAddDrawerOpen(true)}
              />
            ) : activeSystem ? (
              <SystemDetailsPage
                system={activeSystem}
                allSystems={systems}
                onSelectSystem={(sysId) => handleSelectSystemId(sysId)}
                onOpenManage={() => setManageSystem(activeSystem)}
                onOpenViewFix={(ctrl) => setViewFixControl(ctrl)}
                onBackToSystems={() => handleSelectSystemId(null)}
                onNavigateToVulnerabilities={(repoName) => {
                  setActiveNav('vulnerabilities');
                  setSelectedRepoForVulns(repoName || null);
                }}
              />
            ) : (
              /* Change Management List & Overview */
              <div className="space-y-6">
                {/* Page Title & Add System Action Bar */}
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                  <div>
                    <h1 className="text-[24px] font-semibold text-[#24262B] tracking-tight">
                      Change Management
                    </h1>
                    <p className="text-[13px] text-[#666A73] mt-1 max-w-2xl leading-relaxed">
                      Continuously monitor your change management systems to identify change risks,
                      track approvals, and maintain controlled deployments.
                    </p>
                  </div>

                  {/* Add System Button */}
                  <button
                    id="btn-add-system"
                    onClick={() => setIsAddDrawerOpen(true)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[13px] font-medium text-[#24262B] hover:text-[#5876D8] bg-white border border-[#E8E9ED] hover:border-[#5876D8] hover:bg-[#FAFAFB] rounded-md transition-colors shadow-2xs shrink-0 self-start"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>Add system</span>
                  </button>
                </div>

                {/* Top Horizontal Tabs: [ Change management systems ] [ Monitoring ] */}
                <div className="border-b border-[#E8E9ED] flex space-x-6">
                  <button
                    id="tab-change-management-systems"
                    onClick={() => setActiveTopTab('systems')}
                    className={`pb-2.5 text-[13px] font-medium transition-colors relative ${activeTopTab === 'systems'
                      ? 'text-[#24262B] font-semibold'
                      : 'text-[#666A73] hover:text-[#5876D8]'
                      }`}
                  >
                    Change management systems
                    {activeTopTab === 'systems' && (
                      <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#E89562] rounded-t" />
                    )}
                  </button>

                  <button
                    id="tab-monitoring-global"
                    onClick={() => setActiveTopTab('monitoring')}
                    className={`pb-2.5 text-[13px] font-medium transition-colors relative ${activeTopTab === 'monitoring'
                      ? 'text-[#24262B] font-semibold'
                      : 'text-[#666A73] hover:text-[#5876D8]'
                      }`}
                  >
                    Monitoring
                    {activeTopTab === 'monitoring' && (
                      <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#E89562] rounded-t" />
                    )}
                  </button>
                </div>

                {/* Tab Content */}
                {activeTopTab === 'systems' ? (
                  <SystemTable
                    systems={systems}
                    onViewDetails={(sys) => handleSelectSystemId(sys.id)}
                    onRefresh={loadInitialData}
                    isRefreshing={isRefreshing}
                  />
                ) : (
                  monitoringOverview && (
                    <SystemMonitoringGlobalTab
                      overview={monitoringOverview}
                      events={monitoringEvents}
                      onRefresh={loadInitialData}
                      isRefreshing={isRefreshing}
                    />
                  )
                )}
              </div>
            )}
          </div>
        </main>
      </div>

      {/* Add System Right-Side Drawer */}
      <AddSystemDrawer
        isOpen={isAddDrawerOpen}
        onClose={() => setIsAddDrawerOpen(false)}
        onSystemCreated={async (newSysId, name) => {
          addToast('success', `Connected and enabled continuous monitoring for ${name}.`, 'System Connected');
          if (activeNav === 'change-management') {
            setSelectedSystemId(newSysId);
          }
          await loadInitialData();
        }}
      />

      {/* Manage System Right-Side Drawer */}
      <ManageSystemDrawer
        system={manageSystem}
        isOpen={!!manageSystem}
        onClose={() => setManageSystem(null)}
        onOpenDeleteModal={(sys) => setDeleteTargetSystem(sys)}
        onShowToast={addToast}
        onSystemUpdated={() => {
          integrationService.getSystems().then(setSystems);
        }}
      />

      {/* View & Fix Control Right-Side Drawer */}
      <ViewFixDrawer
        control={viewFixControl}
        isOpen={!!viewFixControl}
        onClose={() => setViewFixControl(null)}
        onControlUpdated={() => {
          integrationService.getSystems().then(setSystems);
        }}
        onShowToast={addToast}
      />

      {/* Delete System Confirmation Modal */}
      <DeleteConfirmModal
        system={deleteTargetSystem}
        isOpen={!!deleteTargetSystem}
        onClose={() => setDeleteTargetSystem(null)}
        onConfirm={handleConfirmDelete}
        isDeleting={isDeleting}
      />

      {/* Settings Modal */}
      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        onSaveNotification={(msg) => addToast('success', msg)}
      />
    </div>
  );
}

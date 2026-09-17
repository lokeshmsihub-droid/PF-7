import { MonitoringEvent, MonitoringOverview } from '../types';
import { api } from '../api';

let eventsStore: MonitoringEvent[] = [];
let overviewStore: MonitoringOverview = { 
  activeSystems: 0, 
  eventsProcessed: 0, 
  changesDetected: 0, 
  pendingTasks: 0,
  reEvaluations: 0,
  webhookStatus: 'inactive',
  periodicSyncStatus: 'paused',
  lastSync: 'Never',
  nextSync: 'Never'
};
const listeners: (() => void)[] = [];
let eventSource: EventSource | null = null;

function notifyListeners() {
  listeners.forEach((listener) => listener());
}

export const monitoringService = {
  subscribe(listener: () => void) {
    listeners.push(listener);
    
    // Start SSE on first subscription
    if (!eventSource && listeners.length === 1) {
      this.startSSE();
    }
    
    return () => {
      const idx = listeners.indexOf(listener);
      if (idx !== -1) listeners.splice(idx, 1);
      
      // Close SSE if no listeners
      if (listeners.length === 0 && eventSource) {
        eventSource.close();
        eventSource = null;
      }
    };
  },

  startSSE() {
    // Connect to backend SSE endpoint
    // We send X-Tenant-ID via query param since EventSource doesn't support headers natively
    eventSource = new EventSource('/api/compliance/events?tenant_id=tenant-acme-corp');
    
    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        let category: MonitoringEvent['category'] = 'sync';
        let status: MonitoringEvent['status'] = 'info';
        
        // Map backend event types to frontend categories
        if (data.event_type.includes('CHANGE')) category = 'pr';
        else if (data.event_type.includes('COMPLIANCE_EVALUATED') || data.event_type.includes('DECISION')) category = 'evaluation';
        else if (data.event_type.includes('FINDING')) category = 'finding';
        else if (data.event_type.includes('REMEDIATION')) category = 'remediation';
        
        if (data.event_type.includes('FAILED')) status = 'error';
        else if (data.event_type.includes('CREATED') || data.event_type.includes('COMPLETED') || data.event_type.includes('CONNECTED')) status = 'success';
        
        const newEvent: MonitoringEvent = {
          id: `evt-${Date.now()}-${Math.random()}`,
          timestamp: new Date().toISOString(),
          timeString: 'Just now',
          title: data.event_type.replace(/_/g, ' '),
          category,
          status,
          description: JSON.stringify(data.data),
          systemId: data.data?.account_id
        };
        
        eventsStore = [newEvent, ...eventsStore].slice(0, 100); // Keep last 100
        overviewStore.eventsProcessed += 1;
        if (category === 'pr') overviewStore.changesDetected += 1;
        
        notifyListeners();
      } catch (err) {
        console.error('Error parsing SSE event', err);
      }
    };
    
    eventSource.onerror = (err) => {
      console.error('SSE connection error:', err);
      overviewStore.webhookStatus = 'degraded';
      notifyListeners();
    };
  },

  async getMonitoringOverview(systemId?: string): Promise<MonitoringOverview> {
    try {
      const targetId = systemId || 'sys-github-1788179572727';
      const res = await api.get(`/systems/${targetId}/monitoring`);
      const data = res.data;
      
      overviewStore = {
        ...overviewStore,
        activeSystems: data.active_systems ?? (overviewStore.activeSystems || 3),
        eventsProcessed: data.events_processed,
        changesDetected: data.changes_detected,
        reEvaluations: data.re_evaluations,
        pendingTasks: data.pending_tasks,
        webhookStatus: 'active',
        periodicSyncStatus: 'active',
        lastSync: data.last_sync,
        nextSync: data.next_sync
      };
      
      if (data.activity_timeline && data.activity_timeline.length > 0) {
        eventsStore = data.activity_timeline;
      }
      
      return { ...overviewStore };
    } catch (e) {
      return { ...overviewStore };
    }
  },

  async getMonitoringActivity(systemId?: string): Promise<MonitoringEvent[]> {
    try {
      const targetId = systemId || 'sys-github-1788179572727';
      const res = await api.get(`/systems/${targetId}/monitoring`);
      if (res.data?.activity_timeline) {
        eventsStore = res.data.activity_timeline;
      }
      return [...eventsStore];
    } catch (e) {
      return [...eventsStore];
    }
  },

  async addEvent(event: Omit<MonitoringEvent, 'id' | 'timestamp'>): Promise<MonitoringEvent> {
    // Only used locally by some components
    const newEvent: MonitoringEvent = {
      ...event,
      id: `evt-${Date.now()}`,
      timestamp: new Date().toISOString(),
    };
    eventsStore = [newEvent, ...eventsStore];
    overviewStore.eventsProcessed += 1;
    notifyListeners();
    return Promise.resolve(newEvent);
  },
};

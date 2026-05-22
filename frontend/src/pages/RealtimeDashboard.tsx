import React, { useEffect, useState } from 'react';
import { useAuth } from '../contexts/AuthContext';

// We'll use SSE for telemetry
export const RealtimeDashboard: React.FC = () => {
  const { user } = useAuth();
  const [telemetry, setTelemetry] = useState<any>({
    activeScans: 0,
    queuedJobs: 0,
    activeWorkers: 0,
    events: []
  });

  useEffect(() => {
    // Connect to SSE endpoint (we need to ensure this is implemented in backend)
    const token = localStorage.getItem('vulnforge_token');
    const base = (import.meta as any).env.VITE_API_BASE_URL || 'http://localhost:4000';
    const evtSource = new EventSource(`${base}/telemetry/stream?token=${token}`);

    evtSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'telemetry_update') {
          setTelemetry((prev: any) => ({
            ...prev,
            activeScans: data.activeScans ?? prev.activeScans,
            queuedJobs: data.queuedJobs ?? prev.queuedJobs,
            activeWorkers: data.activeWorkers ?? prev.activeWorkers,
          }));
        } else if (data.type === 'system_event') {
          setTelemetry((prev: any) => ({
            ...prev,
            events: [data.event, ...prev.events].slice(0, 50)
          }));
        }
      } catch (e) {
        console.error('Failed to parse SSE data', e);
      }
    };

    return () => {
      evtSource.close();
    };
  }, []);

  return (
    <div className="flex flex-col gap-6">
      <header>
        <h1 className="text-2xl font-bold">Realtime Telemetry</h1>
        <p className="text-textMuted text-sm">System-wide performance and worker health.</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="panel p-6 bg-surface border border-border rounded-lg shadow-sm">
          <h3 className="text-sm font-semibold text-textMuted mb-2">Active Scans</h3>
          <div className="text-4xl font-bold text-primary">{telemetry.activeScans}</div>
        </div>
        <div className="panel p-6 bg-surface border border-border rounded-lg shadow-sm">
          <h3 className="text-sm font-semibold text-textMuted mb-2">Queued Jobs</h3>
          <div className="text-4xl font-bold text-warning">{telemetry.queuedJobs}</div>
        </div>
        <div className="panel p-6 bg-surface border border-border rounded-lg shadow-sm">
          <h3 className="text-sm font-semibold text-textMuted mb-2">Active Workers</h3>
          <div className="text-4xl font-bold text-success">{telemetry.activeWorkers}</div>
        </div>
      </div>

      <div className="panel p-0 bg-surface border border-border rounded-lg shadow-sm overflow-hidden flex flex-col h-[400px]">
        <div className="p-4 border-b border-border bg-[#0D1117]/50 font-semibold text-sm">
          System Event Log
        </div>
        <div className="flex-1 overflow-auto p-4 font-mono text-xs">
          {telemetry.events.length === 0 ? (
            <div className="text-textMuted h-full flex items-center justify-center">Waiting for telemetry events...</div>
          ) : (
            telemetry.events.map((evt: any, i: number) => (
              <div key={i} className="mb-2 pb-2 border-b border-border/50 flex gap-4">
                <span className="text-textMuted shrink-0">{new Date(evt.timestamp || Date.now()).toLocaleTimeString()}</span>
                <span className={`${evt.level === 'error' ? 'text-danger' : evt.level === 'warn' ? 'text-warning' : 'text-textMain'}`}>
                  {evt.message}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

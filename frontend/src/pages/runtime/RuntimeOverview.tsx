import React, { useEffect, useState } from 'react';
import { PageHeader, StatCard, EmptyState } from '../../components/ui';

interface SystemEvent {
  id: string;
  timestamp: number;
  level: 'info' | 'warn' | 'error';
  message: string;
}

export const RuntimeOverview: React.FC = () => {
  const [telemetry, setTelemetry] = useState({ activeScans: 0, queuedJobs: 0, activeWorkers: 0 });
  const [events, setEvents] = useState<SystemEvent[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem('vulnforge_token');
    const base = (import.meta as any).env.VITE_API_BASE_URL || 'http://localhost:4000';
    const es = new EventSource(`${base}/telemetry/stream?token=${token}`);

    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data.type === 'telemetry_update') {
          setTelemetry(prev => ({ ...prev, ...data }));
        } else if (data.type === 'system_event') {
          setEvents(prev => [{ id: Math.random().toString(), ...data.event }, ...prev].slice(0, 100));
        }
      } catch {}
    };

    return () => es.close();
  }, []);

  const LEVEL_COLOR: Record<string, string> = { error: 'var(--color-danger)', warn: 'var(--color-warning)', info: 'var(--color-text-muted)' };

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <div className="flex items-center justify-between">
        <PageHeader title="Runtime Overview" subtitle="Distributed scan engine health and telemetry" />
        <span className={`text-xs px-2 py-1 rounded flex items-center gap-1.5 ${connected ? 'badge-completed' : 'badge-pending'}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-success animate-pulse' : 'bg-textSubtle'}`} />
          {connected ? 'Live' : 'Connecting...'}
        </span>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <StatCard label="Active Scans" value={telemetry.activeScans} color="warning" icon="⬢" />
        <StatCard label="Queued Jobs" value={telemetry.queuedJobs} icon="⊞" />
        <StatCard label="Active Workers" value={telemetry.activeWorkers} color="success" icon="▣" />
      </div>

      <div className="card" style={{ height: '400px', display: 'flex', flexDirection: 'column' }}>
        <div className="card-header">System Event Log</div>
        <div className="flex-1 overflow-y-auto p-3 font-mono text-xs">
          {events.length === 0 ? (
            <div className="h-full flex items-center justify-center" style={{ color: 'var(--color-text-subtle)' }}>
              Waiting for telemetry events...
            </div>
          ) : events.map(ev => (
            <div key={ev.id} className="flex gap-3 py-1.5 border-b" style={{ borderColor: 'var(--color-border)', color: LEVEL_COLOR[ev.level] }}>
              <span className="flex-shrink-0" style={{ color: 'var(--color-text-subtle)' }}>{new Date(ev.timestamp).toLocaleTimeString()}</span>
              <span>[{ev.level.toUpperCase()}]</span>
              <span style={{ color: 'var(--color-text-muted)' }}>{ev.message}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

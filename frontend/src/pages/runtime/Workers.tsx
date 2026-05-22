import React, { useEffect, useState } from 'react';
import { PageHeader } from '../../components/ui';

const WORKERS = [
  { id: 'worker-1', status: 'busy', scan: 'juice-shop.example.com', jobs: 47, uptime: '2h 14m', heartbeat: '1s ago' },
  { id: 'worker-2', status: 'idle', scan: '—', jobs: 23, uptime: '2h 14m', heartbeat: '2s ago' },
  { id: 'worker-3', status: 'busy', scan: 'dvwa.example.com', jobs: 11, uptime: '1h 03m', heartbeat: '1s ago' },
];

const STATUS_COLORS: Record<string, string> = { busy: 'badge-running', idle: 'badge-completed', crashed: 'badge-failed' };

export const Workers: React.FC = () => {
  const [workers, setWorkers] = useState(WORKERS);

  useEffect(() => {
    const iv = setInterval(() => setWorkers([...workers]), 5000);
    return () => clearInterval(iv);
  }, []);

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="Workers" subtitle="Distributed browser worker instances processing scan jobs" />

      <div className="card overflow-x-auto">
        <div className="card-header">Worker Status ({workers.length} workers)</div>
        <table className="data-table">
          <thead>
            <tr><th>Worker ID</th><th>Status</th><th>Current Scan</th><th>Jobs Processed</th><th>Uptime</th><th>Last Heartbeat</th></tr>
          </thead>
          <tbody>
            {workers.map(w => (
              <tr key={w.id}>
                <td className="font-mono text-xs" style={{ color: 'var(--color-primary)' }}>{w.id}</td>
                <td><span className={STATUS_COLORS[w.status]}>{w.status}</span></td>
                <td className="font-mono text-xs" style={{ color: 'var(--color-text-muted)' }}>{w.scan}</td>
                <td className="font-semibold">{w.jobs}</td>
                <td className="text-xs" style={{ color: 'var(--color-text-muted)' }}>{w.uptime}</td>
                <td className="text-xs" style={{ color: 'var(--color-success)' }}>{w.heartbeat}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="p-3 rounded text-xs" style={{ background: 'var(--color-surface-2)', color: 'var(--color-text-muted)', border: '1px solid var(--color-border)' }}>
        ℹ Workers auto-recycle after crash or memory exhaustion. Poison jobs are quarantined and removed from the queue automatically.
      </div>
    </div>
  );
};

import React, { useEffect, useState } from 'react';
import { PageHeader, LoadingSpinner, ErrorBanner } from '../../components/ui';
import { getSystemWorkers } from '../../api';

interface WorkerDto {
  id: string;
  status: 'idle' | 'busy' | 'crashed';
  currentScan?: string;
  jobsProcessed: number;
  uptime: number;
  lastHeartbeat: number;
}

const STATUS_COLORS: Record<string, string> = { busy: 'badge-running', idle: 'badge-completed', crashed: 'badge-failed' };

export const Workers: React.FC = () => {
  const [workers, setWorkers] = useState<WorkerDto[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    const loadWorkers = async () => {
      try {
        const data = await getSystemWorkers();
        if (mounted) {
          const allWorkers: WorkerDto[] = [];
          Object.values(data).forEach((queueWorkers: any) => {
            if (Array.isArray(queueWorkers)) {
              allWorkers.push(...queueWorkers);
            }
          });
          setWorkers(allWorkers);
        }
      } catch (err: any) {
        if (mounted) setError(err.message);
      } finally {
        if (mounted) setLoading(false);
      }
    };

    loadWorkers();
    const iv = setInterval(loadWorkers, 5000);
    return () => {
      mounted = false;
      clearInterval(iv);
    };
  }, []);

  if (loading && workers.length === 0) return <LoadingSpinner fullHeight />;

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="Workers" subtitle="Distributed browser worker instances processing scan jobs" />

      {error && <ErrorBanner message={error} />}

      <div className="card overflow-x-auto">
        <div className="card-header">Worker Status ({workers.length} workers)</div>
        <table className="data-table">
          <thead>
            <tr><th>Worker ID</th><th>Status</th><th>Jobs Processed</th><th>Uptime</th><th>Last Heartbeat</th></tr>
          </thead>
          <tbody>
            {workers.map(w => (
              <tr key={w.id}>
                <td className="font-mono text-xs" style={{ color: 'var(--color-primary)' }}>{w.id}</td>
                <td><span className={STATUS_COLORS[w.status] || STATUS_COLORS['idle']}>{w.status}</span></td>
                <td className="font-semibold">{w.jobsProcessed || 0}</td>
                <td className="text-xs" style={{ color: 'var(--color-text-muted)' }}>{Math.floor((w.uptime || 0) / 60)}m</td>
                <td className="text-xs" style={{ color: 'var(--color-success)' }}>
                  {Math.floor((Date.now() - (w.lastHeartbeat || Date.now())) / 1000)}s ago
                </td>
              </tr>
            ))}
            {workers.length === 0 && (
              <tr>
                <td colSpan={5} className="text-center py-8 text-textMuted text-sm">No active workers found. Ensure BullMQ workers are running.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="p-3 rounded text-xs" style={{ background: 'var(--color-surface-2)', color: 'var(--color-text-muted)', border: '1px solid var(--color-border)' }}>
        ℹ Workers auto-recycle after crash or memory exhaustion. Poison jobs are quarantined and removed from the queue automatically.
      </div>
    </div>
  );
};

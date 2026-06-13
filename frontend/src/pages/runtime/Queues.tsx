import React, { useEffect, useState } from 'react';
import { PageHeader, StatCard, LoadingSpinner, ErrorBanner } from '../../components/ui';
import { getSystemQueues } from '../../api';

export const Queues: React.FC = () => {
  const [queues, setQueues] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    const loadQueues = async () => {
      try {
        const data = await getSystemQueues();
        if (mounted) setQueues(data);
      } catch (err: any) {
        if (mounted) setError(err.message);
      } finally {
        if (mounted) setLoading(false);
      }
    };

    loadQueues();
    const interval = setInterval(loadQueues, 5000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  if (loading && !queues) return <LoadingSpinner fullHeight />;

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="Queue Telemetry" subtitle="Distributed job queue health and throughput metrics" />

      {error && <ErrorBanner message={error} />}

      <div className="grid grid-cols-3 gap-4">
        <StatCard label="Queued" value={queues?.totalWaiting || 0} icon="⊞" />
        <StatCard label="Processing" value={queues?.totalActive || 0} color="warning" icon="◎" />
        <StatCard label="Completed" value={queues?.totalCompleted || 0} color="success" icon="✓" />
      </div>

      <div className="card">
        <div className="card-header">
          <span>Queue Health</span>
          <span className={queues?.healthy ? 'badge-completed' : 'badge-failed'}>
            {queues?.healthy ? 'Healthy' : 'Degraded'}
          </span>
        </div>
        <div className="card-body flex flex-col gap-2 text-sm" style={{ color: 'var(--color-text-muted)' }}>
          <div className="flex justify-between py-2 border-b" style={{ borderColor: 'var(--color-border)' }}>
            <span>Failed Jobs</span><span style={{ color: 'var(--color-danger)' }}>{queues?.totalFailed || 0}</span>
          </div>
          <div className="flex justify-between py-2 border-b" style={{ borderColor: 'var(--color-border)' }}>
            <span>Delayed Jobs</span><span style={{ color: 'var(--color-warning)' }}>{queues?.totalDelayed || 0}</span>
          </div>
          {queues?.queues?.map((q: any) => (
            <div key={q.name} className="flex justify-between py-2 border-b" style={{ borderColor: 'var(--color-border)' }}>
              <span>{q.name}</span>
              <div className="flex gap-4">
                <span style={{ color: 'var(--color-text-main)' }}>Wait: {q.waiting}</span>
                <span style={{ color: 'var(--color-warning)' }}>Active: {q.active}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

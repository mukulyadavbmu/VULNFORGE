import React from 'react';
import { PageHeader, StatCard } from '../../components/ui';

export const Queues: React.FC = () => {
  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="Queue Telemetry" subtitle="Distributed job queue health and throughput metrics" />

      <div className="grid grid-cols-3 gap-4">
        <StatCard label="Queued" value={0} icon="⊞" />
        <StatCard label="Processing" value={0} color="warning" icon="◎" />
        <StatCard label="Completed" value={143} color="success" icon="✓" />
      </div>

      <div className="card">
        <div className="card-header">
          <span>Queue Health</span>
          <span className="badge-completed">Healthy</span>
        </div>
        <div className="card-body flex flex-col gap-2 text-sm" style={{ color: 'var(--color-text-muted)' }}>
          <div className="flex justify-between py-2 border-b" style={{ borderColor: 'var(--color-border)' }}>
            <span>Throughput</span><span style={{ color: 'var(--color-text-main)' }}>~12 jobs/min</span>
          </div>
          <div className="flex justify-between py-2 border-b" style={{ borderColor: 'var(--color-border)' }}>
            <span>Avg. Processing Time</span><span style={{ color: 'var(--color-text-main)' }}>4.2s</span>
          </div>
          <div className="flex justify-between py-2 border-b" style={{ borderColor: 'var(--color-border)' }}>
            <span>Failed Jobs (24h)</span><span style={{ color: 'var(--color-danger)' }}>2</span>
          </div>
          <div className="flex justify-between py-2">
            <span>Dead Letter Queue</span><span style={{ color: 'var(--color-warning)' }}>0</span>
          </div>
        </div>
      </div>
    </div>
  );
};

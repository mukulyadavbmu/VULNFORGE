import React, { useEffect, useState } from 'react';
import { PageHeader, EmptyState, LoadingSpinner } from '../components/ui';

const SAMPLE_EVENTS = [
  { id: '1', time: new Date(Date.now() - 2000).toISOString(), type: 'recon', message: 'Crawl completed for https://juice-shop.example.com', target: 'juice-shop.example.com' },
  { id: '2', time: new Date(Date.now() - 15000).toISOString(), type: 'attack', message: 'SQL injection payload triggered 500 response on /login', target: 'juice-shop.example.com' },
  { id: '3', time: new Date(Date.now() - 45000).toISOString(), type: 'success', message: 'Critical: IDOR vulnerability confirmed at /api/users/1337', target: 'juice-shop.example.com' },
  { id: '4', time: new Date(Date.now() - 120000).toISOString(), type: 'info', message: 'Scan started for https://dvwa.example.com', target: 'dvwa.example.com' },
  { id: '5', time: new Date(Date.now() - 300000).toISOString(), type: 'warning', message: 'Rate limiting detected — backing off 10s', target: 'dvwa.example.com' },
];

const TYPE_COLORS: Record<string, string> = {
  recon: 'var(--color-primary)',
  attack: 'var(--color-warning)',
  success: 'var(--color-success)',
  warning: 'var(--color-warning)',
  info: 'var(--color-text-muted)',
};

export const ActivityPage: React.FC = () => {
  const [filter, setFilter] = useState('all');
  const events = filter === 'all' ? SAMPLE_EVENTS : SAMPLE_EVENTS.filter(e => e.type === filter);

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="Activity Log" subtitle="Recent scan events and system activity" />

      <div className="card">
        <div className="card-header">
          <span>Events ({events.length})</span>
          <div className="flex gap-2">
            {['all', 'recon', 'attack', 'success', 'warning', 'info'].map(t => (
              <button
                key={t}
                onClick={() => setFilter(t)}
                className={`text-xs px-3 py-1 rounded-md transition-colors ${filter === t ? 'btn-primary' : 'btn-ghost'}`}
              >
                {t.charAt(0).toUpperCase() + t.slice(1)}
              </button>
            ))}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Type</th>
                <th>Message</th>
                <th>Target</th>
              </tr>
            </thead>
            <tbody>
              {events.map(evt => (
                <tr key={evt.id}>
                  <td className="text-xs font-mono whitespace-nowrap" style={{ color: 'var(--color-text-muted)' }}>
                    {new Date(evt.time).toLocaleTimeString()}
                  </td>
                  <td>
                    <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded" style={{ color: TYPE_COLORS[evt.type], background: TYPE_COLORS[evt.type] + '20' }}>
                      {evt.type}
                    </span>
                  </td>
                  <td className="text-sm">{evt.message}</td>
                  <td className="text-xs font-mono" style={{ color: 'var(--color-text-muted)' }}>{evt.target}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {events.length === 0 && <div className="card-body"><EmptyState icon="◎" title="No events" description="Activity will appear here during active scans." /></div>}
        </div>
      </div>
    </div>
  );
};

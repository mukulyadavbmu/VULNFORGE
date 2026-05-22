import React from 'react';
import { PageHeader, EmptyState } from '../../components/ui';
import { ScanSelector } from '../../components/ScanSelector';

const SAMPLE_SINKS = [
  { sink: 'innerHTML', url: '/dashboard', count: 12, severity: 'high' },
  { sink: 'eval()', url: '/admin/editor', count: 3, severity: 'critical' },
  { sink: 'document.write()', url: '/search', count: 7, severity: 'high' },
  { sink: 'location.href = ...', url: '/profile', count: 21, severity: 'medium' },
  { sink: 'setTimeout(string)', url: '/widgets', count: 2, severity: 'medium' },
];

const SEV_COLOR: Record<string, string> = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium' };

export const DomSinks: React.FC = () => {
  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="DOM Sinks" subtitle="Potentially dangerous JavaScript sink invocations detected during browser crawl" />
      <ScanSelector value="" onChange={() => {}} />

      <div className="p-3 rounded text-sm" style={{ background: 'rgba(210,153,34,0.08)', border: '1px solid rgba(210,153,34,0.2)', color: 'var(--color-warning)' }}>
        ⚠ DOM sinks indicate potential XSS and injection vectors. These require manual validation before reporting.
      </div>

      <div className="card overflow-x-auto">
        <div className="card-header">
          <span>DOM Sinks ({SAMPLE_SINKS.length})</span>
          <span className="text-xs" style={{ color: 'var(--color-text-subtle)' }}>Sample data — select a scan</span>
        </div>
        <table className="data-table">
          <thead><tr><th>Sink Type</th><th>URL</th><th>Invocations</th><th>Risk</th></tr></thead>
          <tbody>
            {SAMPLE_SINKS.map((s, i) => (
              <tr key={i}>
                <td className="font-mono text-xs text-danger">{s.sink}</td>
                <td className="font-mono text-xs" style={{ color: 'var(--color-text-muted)' }}>{s.url}</td>
                <td className="font-bold">{s.count}</td>
                <td><span className={SEV_COLOR[s.severity] || 'badge-info'}>{s.severity}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

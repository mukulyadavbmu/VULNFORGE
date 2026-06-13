import React, { useEffect, useState } from 'react';
import { PageHeader, EmptyState, LoadingSpinner, ErrorBanner } from '../components/ui';
import { useAuth } from '../contexts/AuthContext';
import { getOrgAuditLogs, listScans, getScanProgress } from '../api';

const TYPE_COLORS: Record<string, string> = {
  recon: 'var(--color-primary)',
  attack: 'var(--color-danger)',
  success: 'var(--color-success)',
  warning: 'var(--color-warning)',
  info: 'var(--color-text-muted)',
  audit: 'var(--color-primary)',
  critical: 'var(--color-danger)'
};

interface AggregatedEvent {
  id: string;
  time: number;
  type: string;
  message: string;
  target: string;
}

export const ActivityPage: React.FC = () => {
  const { user } = useAuth();
  const [filter, setFilter] = useState('all');
  const [events, setEvents] = useState<AggregatedEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    const fetchTimeline = async () => {
      try {
        setLoading(true);
        const allEvents: AggregatedEvent[] = [];
        
        // 1. Fetch Org Audit Logs
        const orgId = user?.memberships?.[0]?.orgId;
        if (orgId) {
          try {
            const auditLogs = await getOrgAuditLogs(orgId);
            auditLogs.forEach(log => {
              allEvents.push({
                id: log.id,
                time: new Date(log.createdAt).getTime(),
                type: 'audit',
                message: `[${log.action}] ${log.details}`,
                target: 'System'
              });
            });
          } catch (err) {
            console.warn('Failed to fetch org audit logs', err);
          }
        }

        // 2. Fetch Scan Events
        try {
          const scans = await listScans();
          // Fetch progress for up to 5 most recent active scans
          for (const scan of scans.slice(0, 5)) {
            try {
              const progress = await getScanProgress(scan.id);
              if (progress && progress.events) {
                progress.events.forEach((evt, idx) => {
                  allEvents.push({
                    id: `${scan.id}-evt-${idx}`,
                    time: evt.timestamp,
                    type: evt.type,
                    message: evt.message,
                    target: scan.targetUrl
                  });
                });
              }
              // Also add a synthetic event for scan creation
              allEvents.push({
                id: `${scan.id}-start`,
                time: new Date(scan.createdAt).getTime(),
                type: 'info',
                message: `Scan started for ${scan.targetUrl}`,
                target: scan.targetUrl
              });
            } catch (err) {
              console.warn(`Failed to fetch progress for scan ${scan.id}`, err);
            }
          }
        } catch (err) {
          console.warn('Failed to fetch scan list', err);
        }

        // Sort by time descending
        allEvents.sort((a, b) => b.time - a.time);

        if (mounted) {
          setEvents(allEvents);
        }
      } catch (err: any) {
        if (mounted) setError(err.message || 'Failed to load timeline');
      } finally {
        if (mounted) setLoading(false);
      }
    };

    fetchTimeline();
    return () => { mounted = false; };
  }, [user]);

  const filteredEvents = filter === 'all' ? events : events.filter(e => e.type === filter || (filter === 'audit' && e.type === 'audit'));

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="Operational Timeline" subtitle="Centralized activity feed across all scans, workers, and organizations" />
      {error && <ErrorBanner message={error} />}

      <div className="card">
        <div className="card-header flex justify-between items-center">
          <span>Events ({filteredEvents.length})</span>
          <div className="flex gap-2">
            {['all', 'recon', 'attack', 'success', 'warning', 'audit'].map(t => (
              <button
                key={t}
                onClick={() => setFilter(t)}
                className={`text-xs px-3 py-1 rounded-md transition-colors ${filter === t ? 'bg-primary/20 text-primary border border-primary/50' : 'bg-surface-2 hover:bg-surface-2/80 text-textMuted border border-border'}`}
              >
                {t.charAt(0).toUpperCase() + t.slice(1)}
              </button>
            ))}
          </div>
        </div>
        <div className="overflow-x-auto min-h-[400px]">
          {loading ? (
            <div className="h-full w-full flex items-center justify-center p-12">
              <LoadingSpinner />
            </div>
          ) : filteredEvents.length === 0 ? (
            <div className="p-8">
              <EmptyState icon="◎" title="No events found" description="Operational activity will appear here." />
            </div>
          ) : (
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
                {filteredEvents.map(evt => (
                  <tr key={evt.id} className="hover:bg-surface-2/30 transition-colors">
                    <td className="text-xs font-mono whitespace-nowrap" style={{ color: 'var(--color-text-muted)' }}>
                      {new Date(evt.time).toLocaleString()}
                    </td>
                    <td>
                      <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded border" style={{ 
                        color: TYPE_COLORS[evt.type] || TYPE_COLORS['info'], 
                        borderColor: `${TYPE_COLORS[evt.type] || TYPE_COLORS['info']}40`,
                        background: `${TYPE_COLORS[evt.type] || TYPE_COLORS['info']}10` 
                      }}>
                        {evt.type}
                      </span>
                    </td>
                    <td className="text-sm font-medium" style={{ color: 'var(--color-text-main)' }}>{evt.message}</td>
                    <td className="text-xs font-mono" style={{ color: 'var(--color-text-subtle)' }}>{evt.target}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
};

import React, { useEffect, useState } from 'react';
import { getOrgAuditLogs } from '../../api';
import { useAuth } from '../../contexts/AuthContext';
import { PageHeader, LoadingSpinner, EmptyState, ErrorBanner } from '../../components/ui';

export const OrgAuditLogs: React.FC = () => {
  const { user, isLoading: authLoading } = useAuth();
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [filter, setFilter] = useState('');

  const orgId = user?.memberships?.[0]?.orgId;
  const role = user?.memberships?.[0]?.role;
  const canView = role === 'admin' || role === 'owner';

  useEffect(() => {
    if (authLoading || !orgId || !canView) return;
    setLoading(true);
    getOrgAuditLogs(orgId).then(setLogs).catch(e => setError(e.message)).finally(() => setLoading(false));
  }, [orgId, authLoading, canView]);

  if (authLoading) return <LoadingSpinner fullHeight />;

  const filtered = logs.filter(l => !filter || JSON.stringify(l).toLowerCase().includes(filter.toLowerCase()));

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="Audit Logs" subtitle="User action history for compliance and security monitoring" />

      {!orgId && <EmptyState icon="⊠" title="No organization" />}

      {orgId && !canView && (
        <div className="p-4 rounded text-sm" style={{ background: 'rgba(248,81,73,0.08)', border: '1px solid rgba(248,81,73,0.2)', color: 'var(--color-danger)' }}>
          🔒 Audit log access requires Admin or Owner role. Current role: <strong>{role || 'viewer'}</strong>
        </div>
      )}

      {canView && (
        <>
          {error && <ErrorBanner message={error} />}
          {loading && <LoadingSpinner />}

          {!loading && (
            <input type="text" placeholder="Filter logs..." value={filter} onChange={e => setFilter(e.target.value)} className="input max-w-xs" />
          )}

          {!loading && filtered.length === 0 && !error && (
            <EmptyState icon="⊠" title="No audit logs" description="Audit events will appear here as users perform actions." />
          )}

          {filtered.length > 0 && (
            <div className="card overflow-x-auto">
              <div className="card-header">
                <span>Audit Events</span>
                <span className="badge-info">{filtered.length}</span>
              </div>
              <table className="data-table">
                <thead><tr><th>Time</th><th>Action</th><th>User</th><th>Details</th></tr></thead>
                <tbody>
                  {filtered.map((log: any) => (
                    <tr key={log.id} className="cursor-pointer" onClick={() => setExpanded(expanded === log.id ? null : log.id)}>
                      <td className="text-xs font-mono whitespace-nowrap" style={{ color: 'var(--color-text-muted)' }}>
                        {new Date(log.createdAt || log.timestamp).toLocaleString()}
                      </td>
                      <td><span className="badge-info">{log.action}</span></td>
                      <td className="text-xs" style={{ color: 'var(--color-text-muted)' }}>{log.userEmail || log.userId}</td>
                      <td className="text-xs max-w-xs">
                        {expanded === log.id
                          ? <pre className="text-[10px] whitespace-pre-wrap" style={{ color: 'var(--color-text-muted)' }}>{JSON.stringify(log.metadata || {}, null, 2)}</pre>
                          : <span style={{ color: 'var(--color-text-subtle)' }}>{log.detail || 'Click to expand'}</span>
                        }
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
};

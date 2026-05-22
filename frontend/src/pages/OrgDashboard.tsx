import React, { useEffect, useState } from 'react';
import { getOrgMetrics, getOrgAuditLogs, getOrgMembers } from '../api';
import { useAuth } from '../contexts/AuthContext';
import { PageHeader, StatCard, LoadingSpinner, EmptyState, ErrorBanner } from '../components/ui';

export const OrgDashboard: React.FC = () => {
  const { user, isLoading: authLoading } = useAuth();
  const [metrics, setMetrics] = useState<any>(null);
  const [members, setMembers] = useState<any[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const orgId = user?.memberships?.[0]?.orgId;

  useEffect(() => {
    if (authLoading || !orgId) return;
    
    const loadData = async () => {
      setLoading(true);
      setError(null);
      try {
        const [m, mems, logs] = await Promise.all([
          getOrgMetrics(orgId).catch(() => ({ totalScans: 0, totalFindings: 0 })), // Provide fallback if API is stubbed
          getOrgMembers(orgId).catch(() => []),
          getOrgAuditLogs(orgId).catch(() => [])
        ]);
        setMetrics(m);
        setMembers(mems);
        setAuditLogs(logs);
      } catch (err: any) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    
    void loadData();
  }, [orgId, authLoading]);

  if (authLoading || loading) return <LoadingSpinner fullHeight />;

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader
        title="Organization Dashboard"
        subtitle="Manage members, view quotas, and inspect audit logs."
      />

      {error && <ErrorBanner message={error} />}

      {!orgId && !error && (
        <EmptyState icon="◑" title="No organization" description="You are not a member of any organization." />
      )}

      {orgId && (
        <>
          {/* Quotas & Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <StatCard label="Total Scans" value={metrics?.totalScans || 0} icon="⬢" />
            <StatCard label="Findings Discovered" value={metrics?.totalFindings || 0} icon="◈" />
            <StatCard label="Active Members" value={members.length} icon="◑" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Members Table */}
            <div className="card">
              <div className="card-header">
                <span>Members & Roles</span>
                <span className="badge-info">{members.length}</span>
              </div>
              <div className="overflow-x-auto max-h-80">
                <table className="data-table">
                  <thead className="sticky top-0 z-10" style={{ background: 'var(--color-surface)' }}>
                    <tr>
                      <th>Name</th>
                      <th>Email</th>
                      <th>Role</th>
                    </tr>
                  </thead>
                  <tbody>
                    {members.map(m => (
                      <tr key={m.id || m.userId}>
                        <td className="font-medium text-sm">{m.name || m.user?.name || '—'}</td>
                        <td className="text-xs" style={{ color: 'var(--color-text-muted)' }}>{m.email || m.user?.email || '—'}</td>
                        <td>
                          <span className="badge-primary uppercase">{m.role}</span>
                        </td>
                      </tr>
                    ))}
                    {members.length === 0 && (
                      <tr>
                        <td colSpan={3} className="text-center text-sm" style={{ color: 'var(--color-text-muted)' }}>No members found.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Audit Logs */}
            <div className="card">
              <div className="card-header">
                <span>Recent Audit Logs</span>
                <span className="badge-info">{auditLogs.length}</span>
              </div>
              <div className="overflow-x-auto max-h-80">
                <table className="data-table">
                  <thead className="sticky top-0 z-10" style={{ background: 'var(--color-surface)' }}>
                    <tr>
                      <th>Timestamp</th>
                      <th>Action</th>
                      <th>User</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLogs.map(log => (
                      <tr key={log.id}>
                        <td className="whitespace-nowrap text-xs font-mono" style={{ color: 'var(--color-text-muted)' }}>
                          {new Date(log.createdAt).toLocaleString()}
                        </td>
                        <td className="font-medium text-xs">
                          <span className="badge-warning">{log.action}</span>
                        </td>
                        <td className="text-xs">{log.user?.email || 'System'}</td>
                      </tr>
                    ))}
                    {auditLogs.length === 0 && (
                      <tr>
                        <td colSpan={3} className="text-center text-sm" style={{ color: 'var(--color-text-muted)' }}>No audit logs found.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

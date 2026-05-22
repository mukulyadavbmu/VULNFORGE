import React, { useEffect, useState } from 'react';
import { getOrgMembers } from '../../api';
import { useAuth } from '../../contexts/AuthContext';
import { PageHeader, LoadingSpinner, EmptyState, ErrorBanner } from '../../components/ui';

const ROLE_BADGE: Record<string, string> = {
  owner: 'badge-critical',
  admin: 'badge-running',
  analyst: 'badge-completed',
  viewer: 'badge-info',
};

export const OrgMembers: React.FC = () => {
  const { user, isLoading: authLoading } = useAuth();
  const [members, setMembers] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const orgId = user?.memberships?.[0]?.orgId;

  useEffect(() => {
    if (authLoading || !orgId) return;
    setLoading(true);
    getOrgMembers(orgId).then(setMembers).catch(e => setError(e.message)).finally(() => setLoading(false));
  }, [orgId, authLoading]);

  if (authLoading) return <LoadingSpinner fullHeight />;

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader
        title="Members"
        subtitle="Organization member management and role assignments"
        actions={<span className="badge-info">{members.length} members</span>}
      />

      {!orgId && <EmptyState icon="◑" title="No organization" description="You are not a member of any organization." />}
      {error && <ErrorBanner message={error} />}
      {loading && <LoadingSpinner />}

      {!loading && members.length > 0 && (
        <div className="card overflow-x-auto">
          <table className="data-table">
            <thead><tr><th>Member</th><th>Email</th><th>Role</th></tr></thead>
            <tbody>
              {members.map((m: any) => (
                <tr key={m.id}>
                  <td>
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0"
                        style={{ background: 'var(--color-primary-dim)', color: 'var(--color-primary)' }}>
                        {(m.name || m.email || '?')[0].toUpperCase()}
                      </div>
                      <span className="font-medium text-sm">{m.name || '—'}</span>
                    </div>
                  </td>
                  <td className="text-sm" style={{ color: 'var(--color-text-muted)' }}>{m.email}</td>
                  <td><span className={ROLE_BADGE[m.role] || 'badge-info'}>{m.role}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!loading && orgId && members.length === 0 && !error && (
        <EmptyState icon="◑" title="No members found" description="Organization membership data could not be loaded." />
      )}
    </div>
  );
};

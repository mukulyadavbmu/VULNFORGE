import React from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { PageHeader, InfoRow } from '../../components/ui';

export const Settings: React.FC = () => {
  const { user } = useAuth();

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="Settings" subtitle="Account and platform configuration" />

      <div className="card">
        <div className="card-header">Profile</div>
        <div className="card-body">
          <InfoRow label="Name" value={user?.name || '—'} />
          <InfoRow label="Email" value={user?.email || '—'} />
          <InfoRow label="User ID" value={<code className="text-xs font-mono">{user?.id || '—'}</code>} />
          <div className="mt-3 text-xs" style={{ color: 'var(--color-text-subtle)' }}>
            To update your profile, contact your organization administrator.
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">Preferences</div>
        <div className="card-body flex flex-col gap-3">
          {[
            { label: 'Dark Mode', value: 'Always On' },
            { label: 'Language', value: 'English' },
            { label: 'Timezone', value: Intl.DateTimeFormat().resolvedOptions().timeZone },
          ].map(p => (
            <div key={p.label} className="flex items-center justify-between py-1.5">
              <span className="text-sm" style={{ color: 'var(--color-text-muted)' }}>{p.label}</span>
              <span className="text-sm font-medium">{p.value}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <div className="card-header">Organization Memberships</div>
        <div className="card-body">
          {(user?.memberships || []).map(m => (
            <div key={m.orgId} className="flex items-center justify-between py-2 border-b" style={{ borderColor: 'var(--color-border)' }}>
              <code className="text-xs font-mono">{m.orgId}</code>
              <span className="capitalize text-sm" style={{ color: 'var(--color-primary)' }}>{m.role}</span>
            </div>
          ))}
          {(user?.memberships || []).length === 0 && (
            <div className="text-sm" style={{ color: 'var(--color-text-subtle)' }}>No organization memberships found.</div>
          )}
        </div>
      </div>
    </div>
  );
};

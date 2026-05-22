import React from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { PageHeader, InfoRow } from '../../components/ui';

export const OrgSettings: React.FC = () => {
  const { user } = useAuth();
  const membership = user?.memberships?.[0];

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="Organization Settings" subtitle="Organization configuration and plan management" />

      <div className="card">
        <div className="card-header">Organization Info</div>
        <div className="card-body">
          <InfoRow label="Organization ID" value={<code className="text-xs font-mono">{membership?.orgId || 'N/A'}</code>} />
          <InfoRow label="Your Role" value={<span className="capitalize">{membership?.role || 'N/A'}</span>} />
          <InfoRow label="Plan" value="Standard" />
          <InfoRow label="Data Retention" value="90 days" />
        </div>
      </div>

      <div className="card">
        <div className="card-header">Limits & Quotas</div>
        <div className="card-body">
          <InfoRow label="Max Concurrent Scans" value="5" />
          <InfoRow label="Max Pages per Scan" value="100" />
          <InfoRow label="Findings Retention" value="90 days" />
          <InfoRow label="Members" value="Unlimited" />
        </div>
      </div>

      <div className="card" style={{ borderColor: 'rgba(248,81,73,0.2)' }}>
        <div className="card-header" style={{ color: 'var(--color-danger)' }}>Danger Zone</div>
        <div className="card-body text-sm" style={{ color: 'var(--color-text-muted)' }}>
          Organization settings can only be modified by the Organization Owner. Contact your administrator to change organization name, billing, or to delete the organization.
        </div>
      </div>
    </div>
  );
};

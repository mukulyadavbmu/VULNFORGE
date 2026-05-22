import React from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';
import { PageHeader } from '../components/ui';

export const OrgLayout: React.FC = () => {
  const location = useLocation();

  const TABS = [
    { name: 'Dashboard', path: '/org' },
    { name: 'Members', path: '/org/members' },
    { name: 'Quotas', path: '/org/quotas' },
    { name: 'Audit Logs', path: '/org/audit' },
    { name: 'Settings', path: '/org/settings' },
  ];

  return (
    <div className="flex flex-col h-full animate-fadeInUp">
      <PageHeader title="Organization" subtitle="Manage your team and resources" />
      
      <div className="flex items-center gap-1 overflow-x-auto border-b" style={{ borderColor: 'var(--color-border)', marginBottom: '1.5rem' }}>
        {TABS.map(tab => {
          const isActive = location.pathname === tab.path;
          return (
            <Link
              key={tab.path}
              to={tab.path}
              className={`px-4 py-2 text-sm font-medium whitespace-nowrap border-b-2 transition-colors ${
                isActive 
                  ? 'border-primary text-primary' 
                  : 'border-transparent text-textMuted hover:text-textMain hover:border-border'
              }`}
            >
              {tab.name}
            </Link>
          );
        })}
      </div>

      <div className="flex-1 overflow-auto">
        <Outlet />
      </div>
    </div>
  );
};

import React from 'react';
import { Outlet, useParams, Link, useLocation } from 'react-router-dom';
import { ScanProvider, useScanContext } from '../contexts/ScanContext';
import { PageHeader, LoadingSpinner, ErrorBanner } from '../components/ui';

const ScanNavTabs = () => {
  const { scanId, scanData } = useScanContext();
  const location = useLocation();

  if (!scanId) return null;

  const TABS = [
    { name: 'Overview', path: `/scans/${scanId}` },
    { name: 'Findings', path: `/scans/${scanId}/findings` },
    { name: 'Replays', path: `/scans/${scanId}/replays` },
    { name: 'Attack Paths', path: `/scans/${scanId}/attack-paths` },
    { name: 'Routes', path: `/scans/${scanId}/routes` },
    { name: 'Browser', path: `/scans/${scanId}/browser` },
    { name: 'Intelligence', path: `/scans/${scanId}/intelligence` },
    { name: 'Runtime', path: `/scans/${scanId}/runtime` },
  ];

  return (
    <div className="flex items-center gap-1 overflow-x-auto border-b" style={{ borderColor: 'var(--color-border)', marginBottom: '1.5rem' }}>
      {TABS.map(tab => {
        const isActive = location.pathname === tab.path || (tab.path !== `/scans/${scanId}` && location.pathname.startsWith(tab.path));
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
  );
};

const ScanLayoutInner: React.FC = () => {
  const { scanId, scanData, isLoading, error } = useScanContext();

  if (isLoading) return <LoadingSpinner fullHeight text="Loading scan workspace..." />;
  if (error) return <ErrorBanner message={error} />;
  if (!scanData) return <ErrorBanner message="Scan not found." />;

  return (
    <div className="flex flex-col h-full animate-fadeInUp">
      <div className="mb-2 text-xs font-mono" style={{ color: 'var(--color-text-subtle)' }}>
        <Link to="/scans" className="hover:text-primary">Scans</Link> &gt; {scanId}
      </div>
      <PageHeader 
        title={scanData.targetUrl} 
        subtitle={`Scan Workspace • Status: ${scanData.status}`} 
        actions={<span className={`badge-${scanData.status === 'completed' ? 'completed' : 'running'}`}>{scanData.status}</span>}
      />
      <ScanNavTabs />
      <div className="flex-1 overflow-auto">
        <Outlet />
      </div>
    </div>
  );
};

export const ScanLayout: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  if (!id) return <div>Invalid scan ID</div>;

  return (
    <ScanProvider scanId={id}>
      <ScanLayoutInner />
    </ScanProvider>
  );
};

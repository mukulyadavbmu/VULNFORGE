import React, { useEffect, useState } from 'react';
import { getScanSurface, DiscoveredRoute } from '../../api';
import { PageHeader, LoadingSpinner, EmptyState, ErrorBanner } from '../../components/ui';
import { ScanSelector } from '../../components/ScanSelector';

export const SurfaceApis: React.FC = () => {
  const [scanId, setScanId] = useState('');
  const [apis, setApis] = useState<DiscoveredRoute[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = async (id: string) => {
    if (!id) { setApis([]); return; }
    setLoading(true); setError(null);
    try { const routes = await getScanSurface(id); setApis(routes.filter(r => r.type === 'api')); }
    catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(scanId); }, [scanId]);

  const grouped = apis.reduce<Record<string, DiscoveredRoute[]>>((acc, r) => {
    const method = r.method || 'GET';
    if (!acc[method]) acc[method] = [];
    acc[method].push(r);
    return acc;
  }, {});

  const METHOD_COLORS: Record<string, string> = {
    GET: 'var(--color-success)', POST: 'var(--color-warning)',
    PUT: 'var(--color-primary)', DELETE: 'var(--color-danger)',
    PATCH: '#8b5cf6',
  };

  return (
    <div className="flex flex-col gap-4 animate-fadeInUp">
      <PageHeader title="API Endpoints" subtitle={`${apis.length} API endpoints discovered`} />
      <ScanSelector value={scanId} onChange={setScanId} />
      {error && <ErrorBanner message={error} />}
      {loading && <LoadingSpinner />}
      {!scanId && !loading && <EmptyState icon="⊡" title="Select a scan" />}
      {scanId && !loading && apis.length === 0 && <EmptyState icon="⊡" title="No API endpoints" description="No API routes were discovered in this scan." />}

      {Object.entries(grouped).map(([method, routes]) => (
        <div key={method} className="card">
          <div className="card-header">
            <span style={{ color: METHOD_COLORS[method] || 'var(--color-text-main)' }} className="font-bold">{method}</span>
            <span className="badge-info">{routes.length}</span>
          </div>
          <div className="divide-y" style={{ borderColor: 'var(--color-border)' }}>
            {routes.map((r, i) => (
              <div key={i} className="px-4 py-3 flex items-center gap-3">
                <code className="text-xs flex-1 truncate" style={{ color: 'var(--color-text-main)' }}>{r.url}</code>
                {r.authRequired && <span className="text-[10px] font-semibold" style={{ color: 'var(--color-warning)' }}>🔒 Auth</span>}
                {(r.tags || []).slice(0, 2).map(t => <span key={t} className="badge-info">{t}</span>)}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
};

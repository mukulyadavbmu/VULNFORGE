import React, { useEffect, useState } from 'react';
import { getScanSurface, DiscoveredRoute } from '../../api';
import { PageHeader, LoadingSpinner, EmptyState, ErrorBanner, RouteTypeBadge } from '../../components/ui';
import { ScanSelector } from '../../components/ScanSelector';

export const SurfaceRoutes: React.FC = () => {
  const [scanId, setScanId] = useState('');
  const [routes, setRoutes] = useState<DiscoveredRoute[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [authFilter, setAuthFilter] = useState('all');
  const [page, setPage] = useState(0);
  const PER_PAGE = 50;

  const load = async (id: string) => {
    if (!id) { setRoutes([]); return; }
    setLoading(true); setError(null);
    try { setRoutes(await getScanSurface(id)); setPage(0); }
    catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(scanId); }, [scanId]);

  const filtered = routes.filter(r => {
    const ok1 = !search || r.url.toLowerCase().includes(search.toLowerCase());
    const ok2 = typeFilter === 'all' || r.type === typeFilter;
    const ok3 = authFilter === 'all' || (authFilter === 'auth' ? r.authRequired : !r.authRequired);
    return ok1 && ok2 && ok3;
  });
  const paginated = filtered.slice(page * PER_PAGE, (page + 1) * PER_PAGE);
  const totalPages = Math.ceil(filtered.length / PER_PAGE);

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = `surface-routes-${scanId}.json`; a.click();
  };

  return (
    <div className="flex flex-col gap-4 animate-fadeInUp">
      <PageHeader title="Surface Routes" subtitle="All routes discovered across the target application" />

      <div className="flex flex-wrap gap-3 items-center">
        <ScanSelector value={scanId} onChange={setScanId} />
        <input type="text" placeholder="Search URLs..." value={search} onChange={e => { setSearch(e.target.value); setPage(0); }} className="input max-w-xs" />
        <select value={typeFilter} onChange={e => { setTypeFilter(e.target.value); setPage(0); }} className="input max-w-[150px]">
          <option value="all">All Types</option>
          <option value="page">Page</option>
          <option value="api">API</option>
          <option value="admin">Admin</option>
          <option value="security_file">Security File</option>
          <option value="spa_route">SPA Route</option>
          <option value="websocket">WebSocket</option>
        </select>
        <select value={authFilter} onChange={e => { setAuthFilter(e.target.value); setPage(0); }} className="input max-w-[150px]">
          <option value="all">All</option>
          <option value="public">Public</option>
          <option value="auth">Auth Required</option>
        </select>
        {routes.length > 0 && (
          <button onClick={handleExport} className="btn-ghost text-xs ml-auto">⬇ Export JSON</button>
        )}
      </div>

      {error && <ErrorBanner message={error} />}
      {loading && <LoadingSpinner />}

      {!loading && !scanId && <EmptyState icon="⊞" title="Select a scan" description="Choose a scan to explore its routes." />}

      {!loading && scanId && filtered.length === 0 && (
        <EmptyState icon="⊞" title="No routes found" description={routes.length === 0 ? "This scan has no route data." : "No routes match your filters."} />
      )}

      {!loading && paginated.length > 0 && (
        <>
          <div className="text-xs mb-1" style={{ color: 'var(--color-text-muted)' }}>Showing {page * PER_PAGE + 1}–{Math.min((page + 1) * PER_PAGE, filtered.length)} of {filtered.length} routes</div>
          <div className="card overflow-x-auto">
            <table className="data-table">
              <thead><tr><th>URL</th><th>Method</th><th>Type</th><th>Auth</th><th>Sensitivity</th><th>Source</th></tr></thead>
              <tbody>
                {paginated.map((r, i) => (
                  <tr key={r.id || i}>
                    <td className="font-mono text-xs max-w-xs truncate" title={r.url}>{r.url}</td>
                    <td className="text-xs font-bold" style={{ color: r.method === 'GET' ? 'var(--color-success)' : 'var(--color-warning)' }}>{r.method || 'GET'}</td>
                    <td><RouteTypeBadge type={r.type} /></td>
                    <td><span style={{ color: r.authRequired ? 'var(--color-warning)' : 'var(--color-success)' }} className="text-xs">{r.authRequired ? '🔒' : '🌐'}</span></td>
                    <td className="text-xs capitalize" style={{ color: r.sensitivity === 'admin' ? 'var(--color-danger)' : r.sensitivity === 'sensitive' ? 'var(--color-warning)' : 'var(--color-text-muted)' }}>{r.sensitivity}</td>
                    <td className="text-xs" style={{ color: 'var(--color-text-subtle)' }}>{r.discoverySource}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {totalPages > 1 && (
            <div className="flex gap-2 justify-center items-center">
              <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0} className="btn-ghost text-sm px-3 py-1">← Prev</button>
              <span className="text-sm" style={{ color: 'var(--color-text-muted)' }}>Page {page + 1}/{totalPages}</span>
              <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1} className="btn-ghost text-sm px-3 py-1">Next →</button>
            </div>
          )}
        </>
      )}
    </div>
  );
};

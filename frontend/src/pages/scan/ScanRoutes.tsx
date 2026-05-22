import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { getScanSurface, DiscoveredRoute } from '../../api';
import { PageHeader, LoadingSpinner, EmptyState, ErrorBanner, RouteTypeBadge } from '../../components/ui';

const SENSITIVITY_COLORS: Record<string, string> = {
  public: 'var(--color-success)',
  sensitive: 'var(--color-warning)',
  admin: 'var(--color-danger)',
  unknown: 'var(--color-text-subtle)',
};

export const ScanRoutes: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [routes, setRoutes] = useState<DiscoveredRoute[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [authFilter, setAuthFilter] = useState('all');
  const [page, setPage] = useState(0);
  const PER_PAGE = 50;

  useEffect(() => {
    if (!id) return;
    getScanSurface(id).then(setRoutes).catch(e => setError(e.message)).finally(() => setLoading(false));
  }, [id]);

  const filtered = routes.filter(r => {
    const searchOk = !search || r.url.includes(search) || r.type.includes(search);
    const typeOk = typeFilter === 'all' || r.type === typeFilter;
    const authOk = authFilter === 'all' || (authFilter === 'auth' ? r.authRequired : !r.authRequired);
    return searchOk && typeOk && authOk;
  });

  const paginated = filtered.slice(page * PER_PAGE, (page + 1) * PER_PAGE);
  const totalPages = Math.ceil(filtered.length / PER_PAGE);

  if (loading) return <LoadingSpinner fullHeight />;

  return (
    <div className="flex flex-col gap-4 animate-fadeInUp">
      <PageHeader title="Discovered Routes" subtitle={`${routes.length} routes found — ${filtered.length} matching filters`} />
      {error && <ErrorBanner message={error} />}

      <div className="flex flex-wrap gap-3">
        <input type="text" placeholder="Search URLs..." value={search} onChange={e => { setSearch(e.target.value); setPage(0); }} className="input max-w-xs" />
        <select value={typeFilter} onChange={e => { setTypeFilter(e.target.value); setPage(0); }} className="input max-w-[160px]">
          <option value="all">All Types</option>
          <option value="page">Page</option>
          <option value="api">API</option>
          <option value="admin">Admin</option>
          <option value="security_file">Security File</option>
          <option value="spa_route">SPA Route</option>
          <option value="websocket">WebSocket</option>
        </select>
        <select value={authFilter} onChange={e => { setAuthFilter(e.target.value); setPage(0); }} className="input max-w-[160px]">
          <option value="all">All Auth</option>
          <option value="public">Public</option>
          <option value="auth">Auth Required</option>
        </select>
      </div>

      {filtered.length === 0 ? (
        <EmptyState icon="◉" title="No routes" description={routes.length === 0 ? "Run a scan to discover routes." : "No routes match your filters."} />
      ) : (
        <>
          <div className="card overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>URL</th>
                  <th>Type</th>
                  <th>Auth</th>
                  <th>Sensitivity</th>
                  <th>Source</th>
                  <th>Tags</th>
                </tr>
              </thead>
              <tbody>
                {paginated.map((r, i) => (
                  <tr key={r.id || i}>
                    <td className="font-mono text-xs max-w-[300px] truncate" title={r.url}>{r.url}</td>
                    <td><RouteTypeBadge type={r.type} /></td>
                    <td>
                      <span className="text-[10px] font-semibold" style={{ color: r.authRequired ? 'var(--color-warning)' : 'var(--color-success)' }}>
                        {r.authRequired ? '🔒 Auth' : '🌐 Public'}
                      </span>
                    </td>
                    <td>
                      <span className="text-[10px] font-semibold uppercase" style={{ color: SENSITIVITY_COLORS[r.sensitivity] || 'var(--color-text-muted)' }}>
                        {r.sensitivity}
                      </span>
                    </td>
                    <td className="text-xs" style={{ color: 'var(--color-text-muted)' }}>{r.discoverySource}</td>
                    <td className="flex flex-wrap gap-1">
                      {(r.tags || []).slice(0, 3).map(tag => (
                        <span key={tag} className="badge-info">{tag}</span>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="flex items-center gap-2 justify-center">
              <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0} className="btn-ghost text-sm px-3 py-1.5">← Prev</button>
              <span className="text-sm" style={{ color: 'var(--color-text-muted)' }}>Page {page + 1} / {totalPages}</span>
              <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1} className="btn-ghost text-sm px-3 py-1.5">Next →</button>
            </div>
          )}
        </>
      )}
    </div>
  );
};

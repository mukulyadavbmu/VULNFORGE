import React, { useEffect, useState } from 'react';
import { getScanSurface } from '../../api';
import { PageHeader, LoadingSpinner, EmptyState, ErrorBanner } from '../../components/ui';
import { ScanSelector } from '../../components/ScanSelector';

export const SurfaceWebSockets: React.FC = () => {
  const [scanId, setScanId] = useState('');
  const [ws, setWs] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = async (id: string) => {
    if (!id) { setWs([]); return; }
    setLoading(true); setError(null);
    try { const routes = await getScanSurface(id); setWs(routes.filter(r => r.type === 'websocket')); }
    catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(scanId); }, [scanId]);

  return (
    <div className="flex flex-col gap-4 animate-fadeInUp">
      <PageHeader title="WebSocket Endpoints" subtitle="Discovered WebSocket connections and channels" />
      <ScanSelector value={scanId} onChange={setScanId} />
      {error && <ErrorBanner message={error} />}
      {loading && <LoadingSpinner />}
      {!scanId && !loading && <EmptyState icon="⇄" title="Select a scan" />}
      {scanId && !loading && ws.length === 0 && (
        <EmptyState icon="⇄" title="No WebSockets found" description="No WebSocket endpoints were discovered in this scan." />
      )}
      {ws.length > 0 && (
        <div className="card overflow-x-auto">
          <table className="data-table">
            <thead><tr><th>Endpoint</th><th>Auth</th><th>Tags</th><th>Discovered</th></tr></thead>
            <tbody>
              {ws.map((r, i) => (
                <tr key={i}>
                  <td className="font-mono text-xs" style={{ color: 'var(--color-success)' }}>{r.url}</td>
                  <td>{r.authRequired ? '🔒 Auth' : '🌐 Public'}</td>
                  <td className="flex gap-1 flex-wrap">{(r.tags || []).map((t: string) => <span key={t} className="badge-info">{t}</span>)}</td>
                  <td className="text-xs" style={{ color: 'var(--color-text-muted)' }}>{r.discoverySource}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

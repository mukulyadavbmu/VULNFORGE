import React, { useEffect, useState } from 'react';
import { getScanIntelligence } from '../../api';
import { PageHeader, LoadingSpinner, EmptyState, ErrorBanner } from '../../components/ui';
import { ScanSelector } from '../../components/ScanSelector';

export const IntelligenceOverview: React.FC = () => {
  const [scanId, setScanId] = useState('');
  const [artifacts, setArtifacts] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = async (id: string) => {
    if (!id) { setArtifacts([]); return; }
    setLoading(true); setError(null);
    try { setArtifacts(await getScanIntelligence(id)); }
    catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(scanId); }, [scanId]);

  const CATEGORY_COLORS: Record<string, string> = {
    deduplication: 'badge-info',
    prioritization: 'badge-running',
    explanation: 'badge-completed',
    correlation: 'badge-medium',
  };

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="AI Intelligence" subtitle="Advisory AI-assisted analysis — deterministic results remain authoritative" />

      <div className="p-3 rounded text-sm" style={{ background: 'rgba(88,166,255,0.08)', border: '1px solid rgba(88,166,255,0.2)', color: 'var(--color-primary)' }}>
        ◇ AI outputs are advisory only. All findings are independently validated by the deterministic VulnForge runtime. AI never modifies offensive execution.
      </div>

      <ScanSelector value={scanId} onChange={setScanId} />
      {error && <ErrorBanner message={error} />}
      {loading && <LoadingSpinner />}
      {!scanId && !loading && <EmptyState icon="◇" title="Select a scan" description="Choose a scan to view AI intelligence artifacts." />}
      {scanId && !loading && artifacts.length === 0 && <EmptyState icon="◇" title="No intelligence artifacts" description="AI analysis artifacts are generated during and after scan completion." />}

      {artifacts.length > 0 && (
        <div className="flex flex-col gap-3">
          {artifacts.map((a: any) => (
            <div key={a.id} className="card p-4">
              <div className="flex items-center gap-2 mb-2">
                <span className={CATEGORY_COLORS[a.category] || 'badge-info'}>{a.category}</span>
                <span className="text-xs" style={{ color: 'var(--color-text-subtle)' }}>{new Date(a.createdAt).toLocaleString()}</span>
              </div>
              <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
                {expanded === a.id ? a.reasoning : `${(a.reasoning || '').slice(0, 200)}${(a.reasoning || '').length > 200 ? '...' : ''}`}
              </p>
              {(a.reasoning || '').length > 200 && (
                <button onClick={() => setExpanded(expanded === a.id ? null : a.id)} className="btn-ghost text-xs mt-2 px-2 py-1">
                  {expanded === a.id ? 'Show Less' : 'Read More'}
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

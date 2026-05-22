import React, { useEffect, useState } from 'react';
import { getScanDeduplication } from '../../api';
import { PageHeader, LoadingSpinner, EmptyState, ErrorBanner } from '../../components/ui';
import { ScanSelector } from '../../components/ScanSelector';

export const Deduplication: React.FC = () => {
  const [scanId, setScanId] = useState('');
  const [clusters, setClusters] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = async (id: string) => {
    if (!id) { setClusters([]); return; }
    setLoading(true); setError(null);
    try { setClusters(await getScanDeduplication(id)); }
    catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(scanId); }, [scanId]);

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="Deduplication Clusters" subtitle="AI-assisted finding grouping to eliminate duplicate reports" />
      <ScanSelector value={scanId} onChange={setScanId} />
      {error && <ErrorBanner message={error} />}
      {loading && <LoadingSpinner />}
      {!scanId && !loading && <EmptyState icon="≡" title="Select a scan" />}
      {scanId && !loading && clusters.length === 0 && <EmptyState icon="≡" title="No clusters" description="Deduplication clusters appear when similar findings are grouped by AI analysis." />}
      {clusters.map((c, i) => (
        <div key={i} className="card p-4">
          <div className="text-sm font-semibold mb-1" style={{ color: 'var(--color-text-main)' }}>Cluster {c.clusterId || i + 1}</div>
          <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>{c.reasoning}</p>
          {c.endpoints && <div className="mt-2 flex flex-wrap gap-1">{c.endpoints.map((ep: string) => <code key={ep} className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'var(--color-surface-2)', color: 'var(--color-text-muted)' }}>{ep}</code>)}</div>}
        </div>
      ))}
    </div>
  );
};

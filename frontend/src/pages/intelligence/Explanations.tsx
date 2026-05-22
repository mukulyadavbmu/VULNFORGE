import React, { useEffect, useState } from 'react';
import { getScanExplanations } from '../../api';
import { PageHeader, LoadingSpinner, EmptyState, ErrorBanner } from '../../components/ui';
import { ScanSelector } from '../../components/ScanSelector';

export const Explanations: React.FC = () => {
  const [scanId, setScanId] = useState('');
  const [explanations, setExplanations] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  const load = async (id: string) => {
    if (!id) { setExplanations([]); return; }
    setLoading(true); setError(null);
    try { setExplanations(await getScanExplanations(id)); }
    catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(scanId); }, [scanId]);

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="AI Explanations" subtitle="Natural language summaries of detected attack chains" />
      <ScanSelector value={scanId} onChange={setScanId} />
      {error && <ErrorBanner message={error} />}
      {loading && <LoadingSpinner />}
      {!scanId && !loading && <EmptyState icon="⊕" title="Select a scan" />}
      {scanId && !loading && explanations.length === 0 && <EmptyState icon="⊕" title="No explanations" description="AI chain explanations are generated for complex attack paths." />}
      {explanations.map((e, i) => (
        <div key={i} className="card p-4 cursor-pointer" onClick={() => setExpanded(expanded === i ? null : i)}>
          <div className="flex items-center justify-between mb-2">
            <div className="font-semibold text-sm" style={{ color: 'var(--color-text-main)' }}>Attack Chain {e.chainId || i + 1}</div>
            <span className="text-xs" style={{ color: 'var(--color-text-subtle)' }}>{expanded === i ? '▲' : '▼'}</span>
          </div>
          <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
            {expanded === i ? e.analystSummary : `${(e.analystSummary || '').slice(0, 200)}...`}
          </p>
        </div>
      ))}
    </div>
  );
};

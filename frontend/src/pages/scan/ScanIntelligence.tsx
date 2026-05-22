import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { getScanIntelligence, getScanDeduplication, getScanExplanations } from '../../api';
import { PageHeader, LoadingSpinner, EmptyState, ErrorBanner, SectionCard } from '../../components/ui';

type Tab = 'artifacts' | 'deduplication' | 'explanations';

export const ScanIntelligence: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [tab, setTab] = useState<Tab>('artifacts');
  const [artifacts, setArtifacts] = useState<any[]>([]);
  const [clusters, setClusters] = useState<any[]>([]);
  const [explanations, setExplanations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    Promise.all([getScanIntelligence(id), getScanDeduplication(id), getScanExplanations(id)])
      .then(([a, c, e]) => { setArtifacts(a); setClusters(c); setExplanations(e); })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return <LoadingSpinner fullHeight />;

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="AI Intelligence" subtitle="Advisory analysis — deterministic results remain authoritative" />

      <div className="p-3 rounded text-sm" style={{ background: 'rgba(88,166,255,0.08)', border: '1px solid rgba(88,166,255,0.2)', color: 'var(--color-primary)' }}>
        ◇ AI outputs are advisory only. All exploitable findings are validated by deterministic offline verification before being flagged.
      </div>

      {error && <ErrorBanner message={error} />}

      <div className="tab-bar">
        {(['artifacts', 'deduplication', 'explanations'] as Tab[]).map(t => (
          <button key={t} onClick={() => setTab(t)} className={`tab-item ${tab === t ? 'active' : ''}`}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
            <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'var(--color-surface-2)', color: 'var(--color-text-muted)' }}>
              {t === 'artifacts' ? artifacts.length : t === 'deduplication' ? clusters.length : explanations.length}
            </span>
          </button>
        ))}
      </div>

      {tab === 'artifacts' && (
        artifacts.length === 0 ? <EmptyState icon="◇" title="No intelligence artifacts" description="AI analysis artifacts appear after scan completion." /> :
        <div className="flex flex-col gap-3">
          {artifacts.map((a: any) => (
            <div key={a.id} className="card p-4">
              <div className="flex items-center gap-2 mb-2">
                <span className="badge-info">{a.category}</span>
                <span className="text-xs" style={{ color: 'var(--color-text-subtle)' }}>{new Date(a.createdAt).toLocaleString()}</span>
              </div>
              <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>{a.reasoning || 'No reasoning provided.'}</p>
            </div>
          ))}
        </div>
      )}

      {tab === 'deduplication' && (
        clusters.length === 0 ? <EmptyState icon="≡" title="No clusters" description="Deduplication clusters appear when similar findings are grouped." /> :
        <div className="flex flex-col gap-3">
          {clusters.map((c: any, i: number) => (
            <div key={i} className="card p-4">
              <div className="font-semibold text-sm mb-1" style={{ color: 'var(--color-text-main)' }}>Cluster {c.clusterId || i + 1}</div>
              <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>{c.reasoning}</p>
            </div>
          ))}
        </div>
      )}

      {tab === 'explanations' && (
        explanations.length === 0 ? <EmptyState icon="⊕" title="No explanations" description="AI chain explanations appear after scan completion." /> :
        <div className="flex flex-col gap-3">
          {explanations.map((e: any, i: number) => (
            <div key={i} className="card p-4">
              <div className="font-semibold text-sm mb-1" style={{ color: 'var(--color-text-main)' }}>Chain {e.chainId || i + 1}</div>
              <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>{e.analystSummary}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { getScanAttackPaths, getScan } from '../../api';
import { PageHeader, LoadingSpinner, EmptyState, ErrorBanner } from '../../components/ui';
import { AttackGraph } from '../../components/AttackGraph';

export const ScanAttackPaths: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<any>(null);
  const [chains, setChains] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedChain, setSelectedChain] = useState<any>(null);

  useEffect(() => {
    if (!id) return;
    Promise.all([getScan(id), getScanAttackPaths(id)])
      .then(([s, c]) => { setScan(s); setChains(c); if (c.length > 0) setSelectedChain(c[0]); })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return <LoadingSpinner fullHeight />;

  return (
    <div className="flex flex-col gap-4 animate-fadeInUp" style={{ height: 'calc(100vh - 100px)' }}>
      <PageHeader title="Attack Paths" subtitle="Correlated multi-step exploit chains" />
      {error && <ErrorBanner message={error} />}

      {chains.length > 0 && (
        <div className="flex gap-2 flex-wrap">
          {chains.map((chain, i) => (
            <button
              key={chain.id}
              onClick={() => setSelectedChain(chain)}
              className={`text-xs px-3 py-1.5 rounded transition-colors ${selectedChain?.id === chain.id ? 'btn-primary' : 'btn-ghost'}`}
            >
              Chain {i + 1}: {chain.name || 'Attack Chain'} ({Math.round((chain.confidence || 0) * 100)}%)
            </button>
          ))}
        </div>
      )}

      <div className="flex-1 card overflow-hidden">
        {!scan?.attackNodes || Object.keys(scan.attackNodes).length === 0 ? (
          <div className="card-body h-full flex items-center justify-center">
            <EmptyState icon="◉" title="No attack graph" description="Attack graph will appear after a scan completes." />
          </div>
        ) : (
          <AttackGraph nodes={scan.attackNodes} actions={scan.actions || []} />
        )}
      </div>
    </div>
  );
};

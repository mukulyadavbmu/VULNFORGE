import React, { useEffect, useState } from 'react';
import { getScanState } from '../../api';
import { PageHeader, LoadingSpinner, EmptyState, ErrorBanner } from '../../components/ui';
import { ScanSelector } from '../../components/ScanSelector';

export const Checkpoints: React.FC = () => {
  const [scanId, setScanId] = useState('');
  const [state, setState] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = async (id: string) => {
    if (!id) { setState(null); return; }
    setLoading(true); setError(null);
    try { setState(await getScanState(id)); }
    catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(scanId); }, [scanId]);

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="Checkpoints" subtitle="Crash recovery state — allows scan resumption without data loss" />

      <div className="p-3 rounded text-xs" style={{ background: 'rgba(88,166,255,0.08)', border: '1px solid rgba(88,166,255,0.2)', color: 'var(--color-primary)' }}>
        ◻ Checkpoints are automatically saved during scan execution. If a worker crashes, the scan resumes from the last checkpoint.
      </div>

      <ScanSelector value={scanId} onChange={setScanId} />
      {error && <ErrorBanner message={error} />}
      {loading && <LoadingSpinner />}
      {!scanId && !loading && <EmptyState icon="◻" title="Select a scan" description="Select a scan to view its checkpoint state." />}

      {state && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="card">
            <div className="card-header">Checkpoint Data</div>
            <div className="card-body">
              <div className="flex justify-between py-2 border-b text-sm" style={{ borderColor: 'var(--color-border)' }}>
                <span style={{ color: 'var(--color-text-muted)' }}>Visited Endpoints</span>
                <strong>{(state.visitedEndpoints || []).length}</strong>
              </div>
              <div className="flex justify-between py-2 border-b text-sm" style={{ borderColor: 'var(--color-border)' }}>
                <span style={{ color: 'var(--color-text-muted)' }}>Latest Token</span>
                <code className="text-xs">{state.latestToken ? '[captured]' : 'none'}</code>
              </div>
              <div className="flex justify-between py-2 text-sm">
                <span style={{ color: 'var(--color-text-muted)' }}>Object IDs</span>
                <strong>{(state.objectIds || []).length}</strong>
              </div>
            </div>
          </div>

          {state.budgetUsage && (
            <div className="card">
              <div className="card-header">Budget Usage</div>
              <div className="card-body">
                {Object.entries(state.budgetUsage || {}).map(([k, v]: [string, any]) => (
                  <div key={k} className="flex justify-between py-2 border-b text-sm" style={{ borderColor: 'var(--color-border)' }}>
                    <span style={{ color: 'var(--color-text-muted)' }}>{k}</span>
                    <strong>{String(v)}</strong>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

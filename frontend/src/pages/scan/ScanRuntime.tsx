import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { getScanState } from '../../api';
import { PageHeader, LoadingSpinner, EmptyState, ErrorBanner, InfoRow } from '../../components/ui';

const SENSITIVE_HEADER_NAMES = ['authorization', 'cookie', 'x-api-key', 'x-auth-token', 'token'];

function sanitizeHeaderValue(name: string, value: string): string {
  if (SENSITIVE_HEADER_NAMES.includes(name.toLowerCase())) return '[REDACTED]';
  return value;
}

export const ScanRuntime: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [state, setState] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    if (!id) return;
    getScanState(id).then(setState).catch(e => setError(e.message)).finally(() => setLoading(false));
  };

  useEffect(() => { load(); const iv = setInterval(load, 3000); return () => clearInterval(iv); }, [id]);

  if (loading) return <LoadingSpinner fullHeight />;

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="Runtime State" subtitle="Live execution context, checkpoints, and coverage metrics" />
      {error && <ErrorBanner message={error} />}

      {!state ? (
        <EmptyState icon="◍" title="No runtime state" description="Runtime state is captured during active scans." />
      ) : (
        <>
          {/* Auth Headers */}
          <div className="card">
            <div className="card-header">Authentication Context</div>
            <div className="card-body">
              {Object.entries(state.authHeaders || {}).map(([ctx, headers]: [string, any]) => (
                <div key={ctx} className="mb-4">
                  <div className="text-xs font-semibold uppercase mb-2" style={{ color: 'var(--color-text-muted)' }}>{ctx}</div>
                  {Object.keys(headers).length === 0 ? (
                    <span className="text-sm" style={{ color: 'var(--color-text-subtle)' }}>No headers configured</span>
                  ) : (
                    Object.entries(headers).map(([k, v]: [string, any]) => (
                      <InfoRow key={k} label={k} value={<code className="text-xs font-mono">{sanitizeHeaderValue(k, String(v))}</code>} />
                    ))
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Coverage */}
          {state.coverageMetrics && (
            <div className="card">
              <div className="card-header">Coverage Metrics</div>
              <div className="card-body">
                {Object.entries(state.coverageMetrics).map(([k, v]: [string, any]) => (
                  <InfoRow key={k} label={k} value={String(v)} />
                ))}
              </div>
            </div>
          )}

          {/* Visited Endpoints */}
          <div className="card">
            <div className="card-header">
              <span>Visited Endpoints</span>
              <span className="badge-info ml-2">{(state.visitedEndpoints || []).length}</span>
            </div>
            <div className="overflow-y-auto max-h-64 card-body">
              {(state.visitedEndpoints || []).map((ep: string, i: number) => (
                <div key={i} className="font-mono text-xs py-1 border-b" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}>{ep}</div>
              ))}
              {(state.visitedEndpoints || []).length === 0 && <div className="text-sm" style={{ color: 'var(--color-text-subtle)' }}>No endpoints visited yet.</div>}
            </div>
          </div>

          {/* Diagnostics */}
          {state.recentDiagnostics?.length > 0 && (
            <div className="card">
              <div className="card-header">Recent Diagnostics</div>
              <div className="card-body font-mono text-xs max-h-48 overflow-y-auto" style={{ color: 'var(--color-text-muted)' }}>
                {state.recentDiagnostics.map((d: any, i: number) => (
                  <div key={i} className="py-1 border-b" style={{ borderColor: 'var(--color-border)' }}>{JSON.stringify(d)}</div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};

import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getScan, ScanSessionDto } from '../api';
import { ScanProgressPanel } from '../components/ScanProgressPanel';
import { ExploitableIssuesPanel } from '../components/ExploitableIssuesPanel';
import { AttackGraph } from '../components/AttackGraph';
import { FindingsTable } from '../components/FindingsTable';

export const ScanDetails: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<ScanSessionDto | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'attack-path' | 'intelligence'>('overview');

  const fetchScan = async () => {
    if (!id) return;
    try {
      const data = await getScan(id);
      setScan(data);
      setError(null);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchScan();
    const interval = setInterval(fetchScan, 5000); // Polling for now; replace with SSE in RealtimeDashboard component if desired
    return () => clearInterval(interval);
  }, [id]);

  if (loading) return <div className="p-6">Loading scan...</div>;
  if (error || !scan) return <div className="p-6 text-danger">{error || 'Scan not found'}</div>;

  return (
    <div className="flex flex-col h-full gap-6">
      <header className="flex justify-between items-start">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Link to="/" className="text-primary hover:underline text-sm">&larr; Back to Scans</Link>
          </div>
          <h1 className="text-2xl font-bold truncate max-w-2xl">{scan.targetUrl}</h1>
          <div className="flex items-center gap-3 mt-2 text-sm">
            <span className={`px-2 py-1 rounded-full border ${
              scan.status === 'running' ? 'bg-warning/10 border-warning text-warning' :
              scan.status === 'completed' ? 'bg-success/10 border-success text-success' :
              'bg-surface border-border text-textMuted'
            }`}>
              {scan.status.toUpperCase()}
            </span>
            <span className="text-textMuted">Started: {new Date(scan.createdAt).toLocaleString()}</span>
          </div>
        </div>
      </header>

      {/* Tabs */}
      <div className="flex border-b border-border">
        {(['overview', 'findings', 'attack-path', 'intelligence'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab 
                ? 'border-primary text-primary' 
                : 'border-transparent text-textMuted hover:text-textMain hover:border-border'
            }`}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1).replace('-', ' ')}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="flex-1 overflow-auto">
        {activeTab === 'overview' && (
          <div className="flex flex-col gap-6">
            <ScanProgressPanel scanId={scan.id} />
            <ExploitableIssuesPanel scanId={scan.id} />
          </div>
        )}

        {activeTab === 'findings' && (
          <div className="h-full">
            <FindingsTable findings={scan.findings} />
          </div>
        )}

        {activeTab === 'attack-path' && (
          <div className="h-[600px] border border-border rounded-lg bg-surface/50 overflow-hidden">
            <AttackGraph nodes={scan.attackNodes} actions={scan.actions} />
          </div>
        )}

        {activeTab === 'intelligence' && (
          <div className="flex flex-col gap-4">
            <div className="panel p-6 bg-surface border border-border rounded-lg">
              <h2 className="text-lg font-semibold mb-4">AI Reasoning & Actions</h2>
              <ul className="space-y-4">
                {scan.actions?.map((a: any, i: number) => (
                  <li key={a.id || i} className="p-4 bg-[#0D1117] border border-border rounded">
                    <div className="flex justify-between items-start mb-2">
                      <span className="bg-primary/20 text-primary px-2 py-1 rounded text-xs font-mono">{a.actionType}</span>
                      <span className="text-xs text-textMuted">Risk: {a.riskScore}</span>
                    </div>
                    <p className="text-sm text-textMain">{a.explanation}</p>
                  </li>
                ))}
                {(!scan.actions || scan.actions.length === 0) && (
                  <p className="text-textMuted text-sm">No intelligence events recorded yet.</p>
                )}
              </ul>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

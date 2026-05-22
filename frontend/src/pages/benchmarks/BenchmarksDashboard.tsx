import React, { useEffect, useState } from 'react';
import { getBenchmarkProfiles, runBenchmark } from '../../api';
import { PageHeader, LoadingSpinner, EmptyState, ErrorBanner, StatCard } from '../../components/ui';

const PROFILE_META: Record<string, { name: string; desc: string; complexity: string; color: string }> = {
  'juice-shop': { name: 'OWASP Juice Shop', desc: 'An intentionally insecure web app with 75+ challenges covering all OWASP Top 10 categories.', complexity: 'Medium', color: 'var(--color-warning)' },
  'dvwa': { name: 'DVWA', desc: 'Damn Vulnerable Web Application — PHP/MySQL classic pentesting target.', complexity: 'Low', color: 'var(--color-success)' },
  'webgoat': { name: 'WebGoat', desc: 'OWASP WebGoat — deliberately insecure Java web app for security training.', complexity: 'High', color: 'var(--color-danger)' },
};

export const BenchmarksDashboard: React.FC = () => {
  const [profiles, setProfiles] = useState<string[]>([]);
  const [selectedProfile, setSelectedProfile] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getBenchmarkProfiles().then(data => {
      const p = Array.isArray(data) ? data : [];
      setProfiles(p);
      if (p.length > 0) setSelectedProfile(p[0]);
    }).catch(() => {});
  }, []);

  const handleRun = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProfile || !targetUrl) return;
    setRunning(true); setError(null); setResult(null);
    try {
      const r = await runBenchmark(selectedProfile, targetUrl);
      setResult(r);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="Benchmarks" subtitle="Validate VulnForge effectiveness against known-vulnerable applications" />

      {error && <ErrorBanner message={error} />}

      {/* Profile cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {Object.entries(PROFILE_META).map(([key, meta]) => (
          <div
            key={key}
            onClick={() => setSelectedProfile(key)}
            className={`card p-4 cursor-pointer transition-all duration-150 ${selectedProfile === key ? 'border-primary' : 'hover:border-primary/30'}`}
            style={{ borderColor: selectedProfile === key ? 'var(--color-primary)' : 'var(--color-border)' }}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="font-semibold text-sm" style={{ color: 'var(--color-text-main)' }}>{meta.name}</div>
              <span className="text-[10px] font-bold px-1.5 py-0.5 rounded" style={{ color: meta.color, background: meta.color + '20' }}>{meta.complexity}</span>
            </div>
            <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>{meta.desc}</p>
          </div>
        ))}
      </div>

      {/* Run benchmark */}
      <div className="card">
        <div className="card-header">Run Benchmark</div>
        <div className="card-body">
          <form onSubmit={handleRun} className="flex flex-col gap-4">
            <div className="flex gap-3">
              <select value={selectedProfile} onChange={e => setSelectedProfile(e.target.value)} className="input max-w-[200px]">
                {profiles.length === 0 && <option value="">No profiles available</option>}
                {profiles.map(p => <option key={p} value={p}>{PROFILE_META[p]?.name || p}</option>)}
              </select>
              <input type="url" placeholder="http://localhost:3000 (target URL)" value={targetUrl} onChange={e => setTargetUrl(e.target.value)} className="input flex-1" required />
              <button type="submit" disabled={running || !targetUrl || !selectedProfile} className="btn-primary">
                {running ? '⟳ Running...' : '▶ Run Benchmark'}
              </button>
            </div>
          </form>
        </div>
      </div>

      {running && <LoadingSpinner text="Running benchmark — this may take several minutes..." />}

      {result && (
        <div className="card">
          <div className="card-header">
            <span>Benchmark Results — {PROFILE_META[selectedProfile]?.name || selectedProfile}</span>
            <span className="badge-completed">Complete</span>
          </div>
          <div className="card-body">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
              <StatCard label="Findings" value={result.totalFindings || 0} color="danger" />
              <StatCard label="Confirmed" value={result.confirmedExploits || 0} color="danger" />
              <StatCard label="Coverage" value={`${result.coveragePercent || 0}%`} color="success" />
              <StatCard label="Duration" value={`${result.durationMs ? (result.durationMs / 1000).toFixed(1) : '—'}s`} />
            </div>
            {result.findings?.length > 0 && (
              <pre className="code-block text-[10px] max-h-60 overflow-auto">{JSON.stringify(result.findings, null, 2)}</pre>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

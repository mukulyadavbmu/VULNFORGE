import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { listScans, createScan, ScanSummary } from '../api';

export const ScanList: React.FC = () => {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [targetUrl, setTargetUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const fetchScans = async () => {
    try {
      const data = await listScans();
      setScans(data);
    } catch (err: any) {
      setError(err.message);
    }
  };

  useEffect(() => {
    void fetchScans();
    const interval = setInterval(fetchScans, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl) return;
    setLoading(true);
    setError(null);
    try {
      const { scanId } = await createScan(targetUrl);
      setTargetUrl('');
      navigate(`/scan/${scanId}`);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <header>
        <h1 className="text-2xl font-bold">Active Scans</h1>
        <p className="text-textMuted text-sm">Monitor and manage your organization's offensive security campaigns.</p>
      </header>

      {error && <div className="p-3 bg-danger/10 border-l-4 border-danger text-danger text-sm">{error}</div>}

      <div className="panel p-6 bg-surface border border-border rounded-lg shadow-sm">
        <h2 className="text-lg font-semibold mb-4">Start New Campaign</h2>
        <form onSubmit={handleStartScan} className="flex gap-3">
          <input
            type="url"
            placeholder="https://target-app.example.com"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="flex-1 bg-[#0D1117] border border-border rounded px-4 py-2 text-sm focus:border-primary focus:outline-none"
            required
          />
          <button 
            type="submit" 
            disabled={loading || !targetUrl}
            className="bg-primary text-background font-semibold px-6 py-2 rounded text-sm hover:bg-primary/90 disabled:opacity-50 transition-colors"
          >
            {loading ? 'Initializing...' : 'Start Scan'}
          </button>
        </form>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {scans.map(scan => (
          <div 
            key={scan.id} 
            onClick={() => navigate(`/scan/${scan.id}`)}
            className="panel p-5 bg-surface border border-border rounded-lg cursor-pointer hover:border-primary transition-colors group"
          >
            <div className="flex justify-between items-start mb-3">
              <h3 className="font-medium text-sm truncate pr-4 group-hover:text-primary transition-colors" title={scan.targetUrl}>
                {scan.targetUrl}
              </h3>
              <span className={`text-xs px-2 py-1 rounded-full whitespace-nowrap ${
                scan.status === 'running' ? 'bg-warning/20 text-warning' :
                scan.status === 'completed' ? 'bg-success/20 text-success' :
                'bg-border text-textMuted'
              }`}>
                {scan.status}
              </span>
            </div>
            <div className="flex justify-between items-center text-xs text-textMuted">
              <span>{new Date(scan.createdAt).toLocaleDateString()}</span>
              <span className="font-mono bg-[#0D1117] px-2 py-0.5 rounded">{scan.findingCount} findings</span>
            </div>
          </div>
        ))}
        
        {scans.length === 0 && !error && (
          <div className="col-span-full py-12 text-center text-textMuted border border-dashed border-border rounded-lg">
            No active scans. Start a new campaign above.
          </div>
        )}
      </div>
    </div>
  );
};

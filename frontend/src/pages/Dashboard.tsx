import React, { useEffect, useState } from 'react';
import { listScans, getSystemQueues, getSystemWorkers } from '../api';
import { PageHeader, StatCard, LoadingSpinner, EmptyState, ErrorBanner } from '../components/ui';
import { Link } from 'react-router-dom';

export const Dashboard: React.FC = () => {
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Realtime telemetry state
  const [activeWorkers, setActiveWorkers] = useState(0);
  const [queuedJobs, setQueuedJobs] = useState(0);
  const [activeScansCount, setActiveScansCount] = useState(0);
  const [apiLatency, setApiLatency] = useState(0);

  useEffect(() => {
    let mounted = true;
    const loadData = async () => {
      try {
        const start = Date.now();
        const data = await listScans();
        if (mounted) {
          setScans(data || []);
          setActiveScansCount((data || []).filter((s: any) => s.status === 'running' || s.status === 'crawling' || s.status === 'attacking').length);
          setApiLatency(Date.now() - start);
        }

        const queues = await getSystemQueues();
        if (mounted && queues.healthy) {
          setQueuedJobs(queues.totalActive + queues.totalWaiting);
        }

        const workers = await getSystemWorkers();
        if (mounted) {
          const count = Object.values(workers).reduce((acc: number, wList: any) => acc + (wList as any[]).length, 0);
          setActiveWorkers(count);
        }
      } catch (err: any) {
        if (mounted) setError(err.message);
      } finally {
        if (mounted) setLoading(false);
      }
    };
    
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const totalFindings = scans.reduce((acc, s) => acc + (s.findingCount || 0), 0);

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader 
        title="Dashboard" 
        subtitle="Operational overview of your active campaigns and system health" 
        actions={<Link to="/scans" className="btn-primary">New Scan</Link>}
      />

      {error && <ErrorBanner message={error} />}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Scans" value={scans.length} icon="⬢" />
        <StatCard label="Active Scans" value={activeScansCount} color="warning" icon="⟳" />
        <StatCard label="Total Findings" value={totalFindings} color="danger" icon="◈" />
        <StatCard label="Queue Depth" value={`${queuedJobs} jobs`} color="success" icon="⊞" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 flex flex-col gap-4">
          <div className="card">
            <div className="card-header flex justify-between items-center">
              <span>Recent Campaigns</span>
              <Link to="/scans" className="text-xs text-primary hover:underline">View All</Link>
            </div>
            
            {loading && scans.length === 0 ? <LoadingSpinner /> : scans.length === 0 ? (
              <EmptyState icon="⬢" title="No Scans" description="Start a new scan to see it here." />
            ) : (
              <table className="data-table">
                <thead><tr><th>Target</th><th>Status</th><th>Findings</th><th>Date</th></tr></thead>
                <tbody>
                  {scans.slice(0, 5).map(scan => (
                    <tr key={scan.id}>
                      <td className="font-mono text-xs"><Link to={`/scans/${scan.id}`} className="hover:text-primary transition-colors">{scan.targetUrl}</Link></td>
                      <td><span className={`badge-${scan.status === 'completed' ? 'completed' : scan.status === 'failed' ? 'failed' : 'running'}`}>{scan.status}</span></td>
                      <td className="font-semibold text-danger">{scan.findingCount}</td>
                      <td className="text-xs text-textMuted">{new Date(scan.createdAt).toLocaleDateString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
          
          <div className="grid grid-cols-2 gap-4">
            <div className="card">
              <div className="card-header">System Telemetry</div>
              <div className="card-body flex flex-col gap-3 justify-center text-sm">
                <div className="flex justify-between items-center py-2 border-b border-border">
                  <span className="text-textMuted">Active Workers</span>
                  <span className="font-mono text-primary font-bold">{activeWorkers}</span>
                </div>
                <div className="flex justify-between items-center py-2 border-b border-border">
                  <span className="text-textMuted">Queued Jobs</span>
                  <span className="font-mono text-warning font-bold">{queuedJobs}</span>
                </div>
                <div className="flex justify-between items-center py-2 border-b border-border">
                  <span className="text-textMuted">Live Campaigns</span>
                  <span className="font-mono text-danger font-bold">{activeScansCount}</span>
                </div>
                <div className="flex justify-between items-center py-2">
                  <span className="text-textMuted">API Latency</span>
                  <span className="font-mono text-success font-bold">{apiLatency}ms</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="flex flex-col gap-4">
          <div className="card h-full">
            <div className="card-header">Quick Actions</div>
            <div className="card-body flex flex-col gap-4">
               <Link to="/scans" className="btn-primary w-full text-center">Start Security Scan</Link>
               <Link to="/surface" className="btn-ghost w-full text-center border border-border">Explore Surface Inventory</Link>
               <Link to="/findings" className="btn-ghost w-full text-center border border-border">Global Findings</Link>
               <Link to="/activity" className="btn-ghost w-full text-center border border-border">Operational Timeline</Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

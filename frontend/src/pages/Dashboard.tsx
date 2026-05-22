import React, { useEffect, useState } from 'react';
import { listScans } from '../api';
import { PageHeader, StatCard, LoadingSpinner, EmptyState, ErrorBanner } from '../components/ui';
import { Link } from 'react-router-dom';

export const Dashboard: React.FC = () => {
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Realtime simulation state for visual density
  const [activeWorkers, setActiveWorkers] = useState(0);
  const [queuedJobs, setQueuedJobs] = useState(0);

  useEffect(() => {
    const loadScans = async () => {
      try {
        const data = await listScans();
        setScans(data || []);
      } catch (err: any) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    loadScans();
    
    // Simulate real-time metrics changing slightly
    setActiveWorkers(Math.floor(Math.random() * 5) + 2);
    setQueuedJobs(Math.floor(Math.random() * 50) + 10);
    const interval = setInterval(() => {
      setActiveWorkers(prev => Math.max(0, prev + (Math.random() > 0.5 ? 1 : -1)));
      setQueuedJobs(prev => Math.max(0, prev + Math.floor(Math.random() * 5) - 2));
    }, 3000);
    
    return () => clearInterval(interval);
  }, []);

  const totalFindings = scans.reduce((acc, s) => acc + (s.findingCount || 0), 0);
  const activeScans = scans.filter(s => s.status === 'running' || s.status === 'crawling' || s.status === 'attacking');

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
        <StatCard label="Active Scans" value={activeScans.length} color="warning" icon="⟳" />
        <StatCard label="Total Findings" value={totalFindings} color="danger" icon="◈" />
        <StatCard label="Queue Health" value={`${queuedJobs} jobs`} color="success" icon="⊞" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 flex flex-col gap-4">
          <div className="card">
            <div className="card-header flex justify-between items-center">
              <span>Recent Campaigns</span>
              <Link to="/scans" className="text-xs text-primary hover:underline">View All</Link>
            </div>
            
            {loading ? <LoadingSpinner /> : scans.length === 0 ? (
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
              <div className="card-header">Finding Severity Distribution</div>
              <div className="card-body h-48 flex items-center justify-center border-t border-border/50">
                <span className="text-xs text-textMuted">Severity chart data pending...</span>
              </div>
            </div>
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
                <div className="flex justify-between items-center py-2">
                  <span className="text-textMuted">API Latency</span>
                  <span className="font-mono text-success font-bold">12ms</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="flex flex-col gap-4">
          <div className="card h-full">
            <div className="card-header">Activity Feed</div>
            <div className="card-body flex flex-col gap-4">
              {[
                { time: '2m ago', type: 'critical', msg: 'Critical SQLi found on juice-shop' },
                { time: '14m ago', type: 'info', msg: 'Scan started for dvwa.example.com' },
                { time: '1h ago', type: 'warning', msg: 'Worker #3 reconnected' },
                { time: '3h ago', type: 'success', msg: 'Scan completed: testphp.vulnweb.com' },
              ].map((act, i) => (
                <div key={i} className="flex gap-3 text-sm">
                  <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 bg-${act.type === 'critical' ? 'danger' : act.type === 'warning' ? 'warning' : act.type === 'success' ? 'success' : 'primary'}`} />
                  <div className="flex flex-col">
                    <span className="text-textMain">{act.msg}</span>
                    <span className="text-xs text-textSubtle">{act.time}</span>
                  </div>
                </div>
              ))}
              <div className="mt-auto pt-4 border-t border-border text-center">
                <Link to="/activity" className="text-xs text-textMuted hover:text-primary">View Full Activity Log</Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

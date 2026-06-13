import React, { useEffect, useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { getSystemQueues, getSystemWorkers, listScans, getOrgAuditLogs } from '../api';

export const RealtimeDashboard: React.FC = () => {
  const { user } = useAuth();
  const [telemetry, setTelemetry] = useState<any>({
    activeScans: 0,
    queuedJobs: 0,
    activeWorkers: 0,
    events: []
  });

  useEffect(() => {
    let mounted = true;
    const loadTelemetry = async () => {
      try {
        const [scans, queues, workers] = await Promise.all([
          listScans().catch(() => []),
          getSystemQueues().catch(() => ({ totalActive: 0, totalWaiting: 0 })),
          getSystemWorkers().catch(() => ({}))
        ]);

        let events: any[] = [];
        const orgId = user?.memberships?.[0]?.orgId;
        if (orgId) {
          const auditLogs = await getOrgAuditLogs(orgId).catch(() => []);
          events = auditLogs.map(log => ({
            timestamp: new Date(log.createdAt).getTime(),
            message: `[${log.action}] ${log.details}`,
            level: 'info'
          })).slice(0, 50);
        }

        if (mounted) {
          setTelemetry({
            activeScans: scans.filter(s => ['running', 'crawling', 'attacking'].includes(s.status)).length,
            queuedJobs: (queues.totalActive || 0) + (queues.totalWaiting || 0),
            activeWorkers: Object.values(workers).reduce((acc: number, wList: any) => acc + (wList as any[]).length, 0),
            events: events
          });
        }
      } catch (err) {
        console.warn('Failed to load telemetry', err);
      }
    };

    loadTelemetry();
    const interval = setInterval(loadTelemetry, 3000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [user]);

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <header>
        <h1 className="text-2xl font-bold">Realtime Telemetry</h1>
        <p className="text-textMuted text-sm">System-wide performance and worker health.</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="panel p-6 bg-surface border border-border rounded-lg shadow-sm">
          <h3 className="text-sm font-semibold text-textMuted mb-2">Active Scans</h3>
          <div className="text-4xl font-bold text-primary">{telemetry.activeScans}</div>
        </div>
        <div className="panel p-6 bg-surface border border-border rounded-lg shadow-sm">
          <h3 className="text-sm font-semibold text-textMuted mb-2">Queued Jobs</h3>
          <div className="text-4xl font-bold text-warning">{telemetry.queuedJobs}</div>
        </div>
        <div className="panel p-6 bg-surface border border-border rounded-lg shadow-sm">
          <h3 className="text-sm font-semibold text-textMuted mb-2">Active Workers</h3>
          <div className="text-4xl font-bold text-success">{telemetry.activeWorkers}</div>
        </div>
      </div>

      <div className="panel p-0 bg-surface border border-border rounded-lg shadow-sm overflow-hidden flex flex-col h-[400px]">
        <div className="p-4 border-b border-border bg-surface-2 font-semibold text-sm">
          System Event Log
        </div>
        <div className="flex-1 overflow-auto p-4 font-mono text-xs">
          {telemetry.events.length === 0 ? (
            <div className="text-textMuted h-full flex items-center justify-center">Waiting for telemetry events...</div>
          ) : (
            telemetry.events.map((evt: any, i: number) => (
              <div key={i} className="mb-2 pb-2 border-b border-border/50 flex gap-4">
                <span className="text-textMuted shrink-0">{new Date(evt.timestamp || Date.now()).toLocaleTimeString()}</span>
                <span className={`${evt.level === 'error' ? 'text-danger' : evt.level === 'warn' ? 'text-warning' : 'text-textMain'}`}>
                  {evt.message}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

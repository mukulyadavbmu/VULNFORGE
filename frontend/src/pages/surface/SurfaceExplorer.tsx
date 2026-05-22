import React, { useEffect, useState } from 'react';
import { getScanSurfaceSummary, getScanSecurityFiles, listScans } from '../../api';
import { PageHeader, StatCard, LoadingSpinner, EmptyState, ErrorBanner } from '../../components/ui';

export const SurfaceExplorer: React.FC = () => {
  const [summary, setSummary] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadGlobalSurface = async () => {
      setLoading(true);
      setError(null);
      try {
        const scans = await listScans();
        if (scans.length === 0) {
          setSummary(null);
          return;
        }
        // For a true global surface, we aggregate the latest 5 scans
        const latestScans = scans.slice(0, 5);
        let agg = {
          totalRoutes: 0,
          publicRoutes: 0,
          authGatedRoutes: 0,
          sensitiveRoutes: 0,
          adminRoutes: 0,
          apiEndpoints: 0,
          websockets: 0,
          spaRoutes: 0,
          securityFiles: 0,
          coverageScore: 0
        };

        const summaries = await Promise.all(latestScans.map(s => getScanSurfaceSummary(s.id).catch(() => null)));
        
        let validSummaries = 0;
        summaries.forEach(s => {
          if (s) {
            validSummaries++;
            agg.totalRoutes += s.totalRoutes || 0;
            agg.publicRoutes += s.publicRoutes || 0;
            agg.authGatedRoutes += s.authGatedRoutes || 0;
            agg.sensitiveRoutes += s.sensitiveRoutes || 0;
            agg.adminRoutes += s.adminRoutes || 0;
            agg.apiEndpoints += s.apiEndpoints || 0;
            agg.websockets += s.websockets || 0;
            agg.spaRoutes += s.spaRoutes || 0;
            agg.securityFiles += s.securityFiles || 0;
            agg.coverageScore += s.coverageScore || 0;
          }
        });

        if (validSummaries > 0) {
          agg.coverageScore = Math.floor(agg.coverageScore / validSummaries);
          setSummary(agg);
        } else {
          setSummary(null);
        }
      } catch (err: any) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    void loadGlobalSurface();
  }, []);

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      {error && <ErrorBanner message={error} />}
      {loading && <LoadingSpinner fullHeight />}
      {!loading && !summary && <EmptyState icon="⊞" title="No Surface Data" description="Run a scan to generate attack surface telemetry." />}
      
      {!loading && summary && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard label="Total Discovered Routes" value={summary.totalRoutes} icon="⊞" />
            <StatCard label="Auth-Gated Routes" value={summary.authGatedRoutes} color="warning" />
            <StatCard label="Sensitive / Admin" value={summary.sensitiveRoutes + summary.adminRoutes} color="danger" />
            <StatCard label="API Endpoints" value={summary.apiEndpoints} color="primary" />
            <StatCard label="WebSockets" value={summary.websockets} color="primary" />
            <StatCard label="SPA Routes" value={summary.spaRoutes} />
            <StatCard label="Security Files" value={summary.securityFiles} />
            <StatCard label="Avg. Coverage Score" value={`${summary.coverageScore}%`} color="success" />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="card">
              <div className="card-header">Surface Distribution</div>
              <div className="card-body h-64 flex items-center justify-center border-t border-border/50">
                <span className="text-sm text-textMuted text-center">Graph rendering paused.<br/>Use 'Surface Routes' tab for details.</span>
              </div>
            </div>
            <div className="card">
              <div className="card-header">Sensitivity Heatmap</div>
              <div className="card-body h-64 flex items-center justify-center border-t border-border/50">
                <span className="text-sm text-textMuted text-center">Heatmap rendering paused.<br/>Use 'Surface Routes' tab for details.</span>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

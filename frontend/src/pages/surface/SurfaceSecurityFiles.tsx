import React, { useEffect, useState } from 'react';
import { getScanSecurityFiles, listScans } from '../../api';
import { PageHeader, LoadingSpinner, EmptyState, ErrorBanner } from '../../components/ui';

const TYPE_LABELS: Record<string, string> = {
  robots_txt: 'Robots.txt',
  sitemap_xml: 'Sitemap',
  security_txt: 'Security.txt',
  well_known: 'Well-Known',
  openapi: 'OpenAPI/Swagger',
  graphql: 'GraphQL',
  admin: 'Admin/Config',
  backup: 'Backup File',
};

const statusColor = (status: number) => {
  if (status < 300) return 'var(--color-success)';
  if (status < 400) return 'var(--color-warning)';
  return 'var(--color-danger)';
};

export const SurfaceSecurityFiles: React.FC = () => {
  const [files, setFiles] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedFile, setExpandedFile] = useState<string | null>(null);

  useEffect(() => {
    const loadAll = async () => {
      setLoading(true);
      setError(null);
      try {
        const scans = await listScans();
        const allFiles = [];
        const detailedScans = await Promise.all(
          scans.slice(0, 5).map(s => getScanSecurityFiles(s.id).catch(() => []))
        );
        for (let i = 0; i < detailedScans.length; i++) {
          const scanFiles = detailedScans[i];
          if (Array.isArray(scanFiles)) {
            allFiles.push(...scanFiles.map(f => ({ ...f, scanTarget: scans[i].targetUrl })));
          }
        }
        setFiles(allFiles.sort((a, b) => b.discoveredAt - a.discoveredAt));
      } catch (e: any) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    };
    loadAll();
  }, []);

  const renderParsedData = (f: any) => {
    if (!f.parsedData) return null;

    if (f.type === 'robots_txt') {
      return (
        <div className="flex flex-col gap-4">
          {f.parsedData.sensitivePathCount > 0 && (
            <div className="text-danger text-sm font-semibold flex items-center gap-2">
              <span className="badge-critical">⚠ CRITICAL</span>
              {f.parsedData.sensitivePathCount} sensitive paths exposed in robots.txt
            </div>
          )}
          <div className="grid grid-cols-2 gap-4">
            <div className="card p-2 border-danger/30 bg-danger/5">
              <div className="text-xs font-semibold mb-2 text-danger">Disallowed Paths ({f.parsedData.disallowed?.length || 0})</div>
              <ul className="text-xs font-mono text-textMuted max-h-40 overflow-y-auto pl-4 list-disc">
                {(f.parsedData.disallowed || []).map((p: string, i: number) => <li key={i}>{p}</li>)}
              </ul>
            </div>
            <div className="card p-2 border-success/30 bg-success/5">
              <div className="text-xs font-semibold mb-2 text-success">Allowed Paths ({f.parsedData.allowed?.length || 0})</div>
              <ul className="text-xs font-mono text-textMuted max-h-40 overflow-y-auto pl-4 list-disc">
                {(f.parsedData.allowed || []).map((p: string, i: number) => <li key={i}>{p}</li>)}
              </ul>
            </div>
          </div>
        </div>
      );
    }

    if (f.type === 'sitemap_xml') {
      return (
        <div className="card p-2 border-primary/30">
          <div className="text-xs font-semibold mb-2 text-primary">Sitemap Locations ({f.parsedData.urlCount} total)</div>
          <ul className="text-xs font-mono text-textMuted max-h-60 overflow-y-auto pl-4 list-decimal">
            {(f.parsedData.urls || []).map((url: string, i: number) => (
              <li key={i} className="py-0.5 truncate max-w-full" title={url}>{url}</li>
            ))}
          </ul>
          {f.parsedData.urlCount > 50 && <div className="text-[10px] text-textSubtle mt-2 italic">... showing first 50 entries</div>}
        </div>
      );
    }

    if (f.type === 'openapi') {
      return (
        <div className="card p-2 border-info/30">
          <div className="text-xs font-semibold mb-2 text-info">API Schema Details</div>
          <div className="text-sm font-mono text-textMuted">
            <div>Title: {f.parsedData.title || 'Unknown'}</div>
            <div>Version: {f.parsedData.version || 'Unknown'}</div>
            <div>Endpoints: {f.parsedData.pathCount || 0}</div>
          </div>
        </div>
      );
    }

    return (
      <pre className="text-[10px] font-mono p-2 bg-black/20 rounded max-h-60 overflow-auto">
        {JSON.stringify(f.parsedData, null, 2)}
      </pre>
    );
  };

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      {error && <ErrorBanner message={error} />}
      
      {loading ? (
        <LoadingSpinner fullHeight />
      ) : files.length === 0 ? (
        <EmptyState icon="📄" title="No security files" description="The crawler has not discovered any security-relevant files yet." />
      ) : (
        <div className="flex flex-col gap-4">
          {files.map((f, i) => {
            const isExpanded = expandedFile === `${i}-${f.url}`;
            return (
              <div key={i} className="card overflow-hidden">
                <div 
                  className="card-header cursor-pointer hover:bg-white/5 transition-colors flex items-center justify-between"
                  onClick={() => setExpandedFile(isExpanded ? null : `${i}-${f.url}`)}
                >
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-xs font-bold truncate max-w-sm" style={{ color: 'var(--color-primary)' }}>{f.url}</span>
                    <span className="badge-info">{TYPE_LABELS[f.type] || f.type}</span>
                    <span className="text-xs font-bold" style={{ color: statusColor(f.status) }}>HTTP {f.status}</span>
                    {f.type === 'robots_txt' && (f.parsedData?.sensitivePathCount ?? 0) > 0 && (
                      <span className="badge-high">⚠ {f.parsedData?.sensitivePathCount} sensitive</span>
                    )}
                  </div>
                  <div className="text-xs text-textSubtle">
                    {new Date(f.discoveredAt).toLocaleTimeString()}
                    <span className="ml-3 opacity-50">{isExpanded ? '▲' : '▼'}</span>
                  </div>
                </div>
                
                {isExpanded && (
                  <div className="card-body bg-black/10 border-t border-border/30 flex flex-col gap-4">
                    <div className="text-sm font-semibold">Parsed Information</div>
                    {renderParsedData(f)}
                    
                    <div className="text-sm font-semibold mt-2">Raw Content Preview</div>
                    <pre className="text-[10px] font-mono text-textMuted bg-surface border border-border p-3 rounded max-h-48 overflow-y-auto whitespace-pre-wrap">
                      {f.content ? f.content.slice(0, 2000) + (f.content.length > 2000 ? '\n... [truncated]' : '') : 'No content'}
                    </pre>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

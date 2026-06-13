import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { getExploitableIssues, ExploitableIssueDto } from '../../api';
import { PageHeader, LoadingSpinner, EmptyState, ErrorBanner, SeverityBadge } from '../../components/ui';
import { ReplayViewer } from '../../components/ReplayViewer';

export const ScanReplays: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [issues, setIssues] = useState<ExploitableIssueDto[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<ExploitableIssueDto | null>(null);

  useEffect(() => {
    const fetchIssues = async () => {
      setLoading(true);
      try {
        if (id) {
          const data = await getExploitableIssues(id);
          setIssues(data);
          if (data.length > 0) setSelected(data[0]);
        } else {
          // Global mode: fetch all scans and aggregate issues
          const { listScans } = await import('../../api');
          const scans = await listScans();
          const allIssues: ExploitableIssueDto[] = [];
          for (const scan of scans.slice(0, 5)) { // Limit to recent 5 scans to avoid abuse
            try {
              const data = await getExploitableIssues(scan.id);
              allIssues.push(...data);
            } catch (err) {
              console.warn(`Failed to fetch issues for scan ${scan.id}`, err);
            }
          }
          setIssues(allIssues);
          if (allIssues.length > 0) setSelected(allIssues[0]);
        }
      } catch (err: any) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    
    fetchIssues();
  }, [id]);

  if (loading) return <LoadingSpinner fullHeight />;

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="Replay Traces" subtitle="HTTP request/response evidence for discovered vulnerabilities" />
      {error && <ErrorBanner message={error} />}

      {issues.length === 0 ? (
        <EmptyState icon="▶" title="No replay traces" description="Exploitable issues with captured traces will appear here." />
      ) : (
        <div className="flex gap-4" style={{ height: 'calc(100vh - 200px)' }}>
          {/* Issue list */}
          <div className="w-72 flex-shrink-0 card overflow-y-auto">
            <div className="card-header">Issues with Traces ({issues.length})</div>
            <div className="divide-y" style={{ borderColor: 'var(--color-border)' }}>
              {issues.map(issue => (
                <div
                  key={issue.id}
                  onClick={() => setSelected(issue)}
                  className={`p-3 cursor-pointer transition-colors ${selected?.id === issue.id ? 'bg-primary/10' : 'hover:bg-surface-2/50'}`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <SeverityBadge severity={issue.severity} />
                    <span className="text-xs font-semibold" style={{ color: 'var(--color-text-main)' }}>{issue.type}</span>
                  </div>
                  <div className="text-xs font-mono truncate" style={{ color: 'var(--color-text-muted)' }}>{issue.endpoint}</div>
                  {!issue.trace && <div className="text-[10px] mt-1" style={{ color: 'var(--color-text-subtle)' }}>No trace captured</div>}
                </div>
              ))}
            </div>
          </div>

          {/* Replay viewer */}
          <div className="flex-1 overflow-y-auto">
            {selected ? (
              selected.trace ? (
                <ReplayViewer trace={selected.trace} />
              ) : (
                <EmptyState icon="▶" title="No trace for this issue" description="The replay trace was not captured for this vulnerability." />
              )
            ) : (
              <EmptyState icon="▶" title="Select an issue" description="Choose an issue from the list to view its replay trace." />
            )}
          </div>
        </div>
      )}
    </div>
  );
};

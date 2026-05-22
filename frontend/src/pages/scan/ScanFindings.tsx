import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getScan } from '../../api';
import { PageHeader, LoadingSpinner, EmptyState, SeverityBadge, ErrorBanner } from '../../components/ui';
import { FindingsTable } from '../../components/FindingsTable';
import { ExploitDetailsPanel } from '../../components/ExploitDetailsPanel';

export const ScanFindings: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<any>(null);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [search, setSearch] = useState('');

  useEffect(() => {
    if (!id) return;
    getScan(id).then(setScan).catch(e => setError(e.message)).finally(() => setLoading(false));
  }, [id]);

  if (loading) return <LoadingSpinner fullHeight />;
  if (error) return <ErrorBanner message={error} />;

  const findings = (scan?.findings || []).filter((f: any) => {
    const sevOk = severityFilter === 'all' || f.severity?.toLowerCase() === severityFilter;
    const searchOk = !search || f.url?.includes(search) || f.type?.includes(search);
    return sevOk && searchOk;
  });

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <div className="flex items-start justify-between">
        <PageHeader
          title="Findings"
          subtitle={`${findings.length} vulnerabilities discovered in ${scan?.targetUrl}`}
        />
        <Link to={`/scans/${id}`} className="btn-ghost text-sm">← Scan Overview</Link>
      </div>

      <div className="flex gap-3 flex-wrap">
        <input
          type="text"
          placeholder="Search by URL or type..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="input max-w-xs"
        />
        <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)} className="input max-w-[140px]">
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {findings.length === 0 ? (
        <EmptyState icon="◈" title="No findings" description="No vulnerabilities match your filters." />
      ) : (
        <FindingsTable findings={findings} />
      )}

      {selected && <ExploitDetailsPanel issue={selected} onClose={() => setSelected(null)} />}
    </div>
  );
};

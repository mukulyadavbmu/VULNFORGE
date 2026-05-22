import React, { useEffect, useState } from 'react';
import { listScans, getScan } from '../../api';
import { PageHeader, LoadingSpinner, EmptyState, ErrorBanner } from '../../components/ui';
import { FindingsTable } from '../../components/FindingsTable';

export const FindingsGlobal: React.FC = () => {
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadAll = async () => {
      setLoading(true);
      setError(null);
      try {
        const scans = await listScans();
        const allFindings = [];
        // Concurrently fetch all scan findings (in a real app, backend would have a dedicated endpoint)
        const detailedScans = await Promise.all(
          scans.slice(0, 10).map(s => getScan(s.id).catch(() => null)) // Limit to 10 for safety
        );
        for (const s of detailedScans) {
          if (s && s.findings) {
            allFindings.push(...s.findings.map((f: any) => ({ ...f, scanTarget: s.targetUrl, scanId: s.id })));
          }
        }
        setFindings(allFindings);
      } catch (e: any) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    };
    loadAll();
  }, []);

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="All Findings" subtitle="Review vulnerabilities across all recent campaigns" />

      {error && <ErrorBanner message={error} />}

      {loading ? (
        <LoadingSpinner fullHeight />
      ) : findings.length === 0 ? (
        <EmptyState icon="◈" title="No findings" description="No vulnerabilities have been discovered across your active scans." />
      ) : (
        <div className="card overflow-x-auto">
          <FindingsTable findings={findings} />
        </div>
      )}
    </div>
  );
};

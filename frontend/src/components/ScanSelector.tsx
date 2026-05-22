import React, { useEffect, useState } from 'react';
import { listScans, ScanSummary } from '../api';

interface Props {
  value: string;
  onChange: (id: string) => void;
  className?: string;
}

export const ScanSelector: React.FC<Props> = ({ value, onChange, className = '' }) => {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listScans()
      .then(data => {
        setScans(data);
        if (!value && data.length > 0) onChange(data[0].id);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <span className="text-sm" style={{ color: 'var(--color-text-muted)' }}>Loading scans...</span>;

  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      className={`input text-sm max-w-sm ${className}`}
    >
      <option value="">Select a scan...</option>
      {scans.map(s => (
        <option key={s.id} value={s.id}>
          {new URL(s.targetUrl).hostname} — {s.status} ({new Date(s.createdAt).toLocaleDateString()})
        </option>
      ))}
    </select>
  );
};

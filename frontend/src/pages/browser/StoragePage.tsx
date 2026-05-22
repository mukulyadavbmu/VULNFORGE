import React, { useState } from 'react';
import { PageHeader, EmptyState } from '../../components/ui';
import { ScanSelector } from '../../components/ScanSelector';

type StorageTab = 'local' | 'session' | 'cookies';

const SENSITIVE = ['token', 'jwt', 'session', 'auth', 'password', 'secret', 'key', 'credential'];
const isSensitive = (key: string) => SENSITIVE.some(s => key.toLowerCase().includes(s));

const SAMPLE_STORAGE: Record<StorageTab, { key: string; value: string }[]> = {
  local: [
    { key: 'authToken', value: 'eyJhbGci...' },
    { key: 'userPreferences', value: '{"theme":"dark","lang":"en"}' },
    { key: 'lastRoute', value: '/dashboard' },
  ],
  session: [
    { key: 'sessionId', value: 'abc123-session' },
    { key: 'csrfToken', value: 'f8a2c...' },
  ],
  cookies: [
    { key: 'remember_me', value: 'true' },
    { key: 'analytics_id', value: 'ga-123456' },
  ],
};

export const StoragePage: React.FC = () => {
  const [tab, setTab] = useState<StorageTab>('local');

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="Frontend Storage" subtitle="localStorage, sessionStorage, and cookies captured during browser crawl" />
      <ScanSelector value="" onChange={() => {}} />

      <div className="p-3 rounded text-sm" style={{ background: 'rgba(248,81,73,0.08)', border: '1px solid rgba(248,81,73,0.2)', color: 'var(--color-danger)' }}>
        🔒 Sensitive keys (tokens, JWTs, credentials) are automatically redacted in display. Values marked [REDACTED] contain secrets.
      </div>

      <div className="tab-bar">
        {(['local', 'session', 'cookies'] as StorageTab[]).map(t => (
          <button key={t} onClick={() => setTab(t)} className={`tab-item ${tab === t ? 'active' : ''}`}>
            {t === 'local' ? 'LocalStorage' : t === 'session' ? 'SessionStorage' : 'Cookies'}
            <span className="ml-1.5 badge-info">{SAMPLE_STORAGE[t].length}</span>
          </button>
        ))}
      </div>

      <div className="card overflow-x-auto">
        <div className="card-header">
          <span>{tab === 'local' ? 'LocalStorage' : tab === 'session' ? 'SessionStorage' : 'Cookies'} ({SAMPLE_STORAGE[tab].length})</span>
          <span className="text-xs" style={{ color: 'var(--color-text-subtle)' }}>Sample data — select a scan</span>
        </div>
        <table className="data-table">
          <thead><tr><th>Key</th><th>Value</th><th>Sensitive</th></tr></thead>
          <tbody>
            {SAMPLE_STORAGE[tab].map((item, i) => (
              <tr key={i}>
                <td className="font-mono text-xs" style={{ color: 'var(--color-primary)' }}>{item.key}</td>
                <td className="font-mono text-xs max-w-xs truncate" style={{ color: isSensitive(item.key) ? 'var(--color-danger)' : 'var(--color-text-muted)' }}>
                  {isSensitive(item.key) ? '[REDACTED]' : item.value}
                </td>
                <td>
                  {isSensitive(item.key)
                    ? <span className="badge-high">Sensitive</span>
                    : <span className="badge-info">Safe</span>
                  }
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

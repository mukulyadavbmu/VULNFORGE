import React from 'react';
import { PageHeader } from '../../components/ui';

export const ApiSettings: React.FC = () => {
  const apiKey = (import.meta as any).env.VITE_VULNFORGE_API_KEY ? '**** [configured]' : '[not configured]';

  const curlExample = `curl -H "Authorization: Bearer <JWT_TOKEN>" \\
     -H "x-vulnforge-api-key: <API_KEY>" \\
     http://localhost:4000/scan`;

  return (
    <div className="flex flex-col gap-6 animate-fadeInUp">
      <PageHeader title="API Settings" subtitle="Configure API access and integration tokens" />

      <div className="card">
        <div className="card-header">API Key</div>
        <div className="card-body">
          <div className="flex items-center gap-3 mb-3">
            <code className="input text-sm flex-1 cursor-not-allowed opacity-75">{apiKey}</code>
          </div>
          <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
            The API key is configured via the <code className="text-xs font-mono px-1 rounded" style={{ background: 'var(--color-surface-2)' }}>VITE_VULNFORGE_API_KEY</code> environment variable.
            JWT tokens are automatically managed by the platform session.
          </p>
        </div>
      </div>

      <div className="card">
        <div className="card-header">Usage Example</div>
        <div className="card-body">
          <p className="text-sm mb-3" style={{ color: 'var(--color-text-muted)' }}>Authenticate with Bearer JWT (preferred) or API Key:</p>
          <pre className="code-block">{curlExample}</pre>
        </div>
      </div>

      <div className="card">
        <div className="card-header">Authentication Methods</div>
        <div className="card-body flex flex-col gap-3 text-sm" style={{ color: 'var(--color-text-muted)' }}>
          {[
            { method: 'JWT Bearer Token', desc: 'Obtained via /auth/login. Expires in 24h. Preferred for SaaS usage.', status: 'Recommended' },
            { method: 'API Key Header', desc: 'x-vulnforge-api-key header. For automation and CI/CD pipelines.', status: 'Supported' },
          ].map(item => (
            <div key={item.method} className="flex items-start gap-3 py-2 border-b" style={{ borderColor: 'var(--color-border)' }}>
              <div className="flex-1">
                <div className="font-semibold text-sm mb-0.5" style={{ color: 'var(--color-text-main)' }}>{item.method}</div>
                <div>{item.desc}</div>
              </div>
              <span className="badge-completed">{item.status}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

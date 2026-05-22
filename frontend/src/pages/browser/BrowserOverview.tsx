import React from 'react';
import { Link } from 'react-router-dom';
import { PageHeader, StatCard } from '../../components/ui';

export const BrowserOverview: React.FC = () => (
  <div className="flex flex-col gap-6 animate-fadeInUp">
    <PageHeader title="Browser Recon" subtitle="Frontend instrumentation and browser artifact analysis" />

    <div className="p-3 rounded text-sm" style={{ background: 'rgba(63,185,80,0.08)', border: '1px solid rgba(63,185,80,0.2)', color: 'var(--color-success)' }}>
      ◐ Browser instrumentation captures API calls, storage access, WebSocket messages, and DOM sink invocations during active scans.
    </div>

    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <StatCard label="API Calls Intercepted" value="—" icon="⊡" />
      <StatCard label="DOM Sinks" value="—" icon="⊛" color="warning" />
      <StatCard label="Storage Entries" value="—" icon="⊚" />
      <StatCard label="WS Messages" value="—" icon="⇄" color="success" />
    </div>

    <div className="card">
      <div className="card-header">What Browser Instrumentation Captures</div>
      <div className="card-body flex flex-col gap-4 text-sm" style={{ color: 'var(--color-text-muted)' }}>
        {[
          { icon: '⊡', title: 'API Calls', desc: 'All XHR/fetch requests made by the SPA are intercepted and correlated to routes and auth contexts.' },
          { icon: '⊛', title: 'DOM Sinks', desc: 'Dangerous JavaScript sinks (innerHTML, eval, document.write) are tracked to identify XSS attack vectors.' },
          { icon: '⊚', title: 'Frontend Storage', desc: 'localStorage, sessionStorage, and cookie values are captured and analyzed for sensitive data exposure.' },
          { icon: '⇄', title: 'WebSocket Traffic', desc: 'WebSocket handshakes and messages are recorded during crawling for protocol analysis.' },
          { icon: '◉', title: 'SPA Routes', desc: 'Client-side navigation events (pushState, hashchange) are tracked to discover hidden SPA routes.' },
        ].map(item => (
          <div key={item.title} className="flex gap-3">
            <span className="text-xl opacity-50 flex-shrink-0">{item.icon}</span>
            <div>
              <div className="font-semibold mb-0.5" style={{ color: 'var(--color-text-main)' }}>{item.title}</div>
              <div>{item.desc}</div>
            </div>
          </div>
        ))}
      </div>
    </div>

    <div className="grid grid-cols-2 gap-3">
      <Link to="/browser/dom-sinks" className="card p-4 no-underline group hover:border-primary/40 transition-colors" style={{ textDecoration: 'none' }}>
        <div className="text-2xl mb-2 opacity-50 group-hover:opacity-100">⊛</div>
        <div className="font-semibold text-sm" style={{ color: 'var(--color-text-main)' }}>DOM Sinks</div>
        <div className="text-xs mt-0.5" style={{ color: 'var(--color-text-subtle)' }}>XSS and injection vectors</div>
      </Link>
      <Link to="/browser/storage" className="card p-4 no-underline group hover:border-primary/40 transition-colors" style={{ textDecoration: 'none' }}>
        <div className="text-2xl mb-2 opacity-50 group-hover:opacity-100">⊚</div>
        <div className="font-semibold text-sm" style={{ color: 'var(--color-text-main)' }}>Frontend Storage</div>
        <div className="text-xs mt-0.5" style={{ color: 'var(--color-text-subtle)' }}>Stored tokens and session data</div>
      </Link>
    </div>
  </div>
);

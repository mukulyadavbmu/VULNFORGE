import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

interface NavItem {
  label: string;
  path: string;
  icon: string;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Overview',
    items: [
      { label: 'Dashboard', path: '/dashboard', icon: '⬡' },
      { label: 'Activity', path: '/activity', icon: '◎' },
    ],
  },
  {
    label: 'Scans',
    items: [
      { label: 'All Scans', path: '/scans', icon: '⬢' },
      { label: 'Findings', path: '/findings', icon: '◈' },
      { label: 'Replays', path: '/findings/replays', icon: '▶' },
    ],
  },
  {
    label: 'Surface',
    items: [
      { label: 'Explorer', path: '/surface', icon: '◉' },
      { label: 'Routes', path: '/surface/routes', icon: '⊞' },
      { label: 'APIs', path: '/surface/apis', icon: '⊡' },
      { label: 'Security Files', path: '/surface/security-files', icon: '⛨' },
      { label: 'WebSockets', path: '/surface/websockets', icon: '⇄' },
    ],
  },
  {
    label: 'Browser & Recon',
    items: [
      { label: 'Browser Recon', path: '/browser', icon: '◐' },
      { label: 'DOM Sinks', path: '/browser/dom-sinks', icon: '⊛' },
      { label: 'Storage', path: '/browser/storage', icon: '⊚' },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { label: 'AI Analysis', path: '/intelligence', icon: '◇' },
      { label: 'Deduplication', path: '/intelligence/deduplication', icon: '≡' },
      { label: 'Explanations', path: '/intelligence/explanations', icon: '⊕' },
    ],
  },
  {
    label: 'Runtime',
    items: [
      { label: 'Overview', path: '/runtime', icon: '◍' },
      { label: 'Workers', path: '/runtime/workers', icon: '▣' },
      { label: 'Queues', path: '/runtime/queues', icon: '⊞' },
      { label: 'Checkpoints', path: '/runtime/checkpoints', icon: '◻' },
    ],
  },
  {
    label: 'Benchmarks',
    items: [
      { label: 'Benchmarks', path: '/benchmarks', icon: '⊡' },
    ],
  },
  {
    label: 'Organization',
    items: [
      { label: 'Overview', path: '/org', icon: '◑' },
      { label: 'Members', path: '/org/members', icon: '◎' },
      { label: 'Audit Logs', path: '/org/audit', icon: '⊠' },
      { label: 'Settings', path: '/org/settings', icon: '⊡' },
    ],
  },
  {
    label: 'Settings',
    items: [
      { label: 'Settings', path: '/settings', icon: '⊕' },
      { label: 'API Keys', path: '/settings/api', icon: '⊞' },
    ],
  },
];

export const Sidebar: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  return (
    <aside className="app-sidebar">
      {/* Brand */}
      <div
        className="px-4 py-4 cursor-pointer flex items-center gap-3 border-b"
        style={{ borderColor: 'var(--color-border)' }}
        onClick={() => navigate('/dashboard')}
      >
        <div
          className="w-7 h-7 rounded flex items-center justify-center text-xs font-black"
          style={{ background: 'var(--color-primary)', color: '#000' }}
        >
          VF
        </div>
        <div>
          <div className="font-bold text-sm" style={{ color: 'var(--color-text-main)' }}>VulnForge</div>
          <div className="text-[10px]" style={{ color: 'var(--color-text-subtle)' }}>Offensive Platform</div>
        </div>
      </div>

      {/* Nav Groups */}
      <nav className="flex-1 py-2 overflow-y-auto">
        {NAV_GROUPS.map((group) => (
          <div key={group.label}>
            <div className="nav-group-label">{group.label}</div>
            {group.items.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `nav-item ${isActive ? 'active' : ''}`
                }
              >
                <span className="nav-icon text-sm w-4 text-center">{item.icon}</span>
                <span>{item.label}</span>
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* User / Logout */}
      <div className="px-3 py-3 border-t" style={{ borderColor: 'var(--color-border)' }}>
        <div className="flex items-center gap-2.5 mb-2">
          <div
            className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0"
            style={{ background: 'var(--color-primary-dim)', color: 'var(--color-primary)' }}
          >
            {user?.name?.[0]?.toUpperCase() || user?.email?.[0]?.toUpperCase() || '?'}
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-xs font-semibold truncate" style={{ color: 'var(--color-text-main)' }}>
              {user?.name || 'Unknown'}
            </div>
            <div className="text-[10px] truncate" style={{ color: 'var(--color-text-subtle)' }}>
              {user?.email}
            </div>
          </div>
        </div>
        <button
          onClick={logout}
          className="btn-danger w-full text-xs py-1.5"
        >
          Sign Out
        </button>
      </div>
    </aside>
  );
};

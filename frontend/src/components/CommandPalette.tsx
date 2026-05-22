import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const ROUTES = [
  { name: 'Dashboard', path: '/dashboard', type: 'page' },
  { name: 'All Scans', path: '/scans', type: 'page' },
  { name: 'Global Findings', path: '/findings', type: 'page' },
  { name: 'Surface Explorer', path: '/surface', type: 'page' },
  { name: 'Security Files', path: '/surface/security-files', type: 'page' },
  { name: 'Browser Artifacts', path: '/browser', type: 'page' },
  { name: 'Intelligence Overview', path: '/intelligence', type: 'page' },
  { name: 'Runtime Telemetry', path: '/runtime', type: 'page' },
  { name: 'Organization', path: '/org', type: 'page' },
  { name: 'Settings', path: '/settings', type: 'page' },
];

export const CommandPalette: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setIsOpen(prev => !prev);
      }
      if (e.key === 'Escape') {
        setIsOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  if (!isOpen) return null;

  const results = ROUTES.filter(r => r.name.toLowerCase().includes(query.toLowerCase()));

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 bg-black/50 backdrop-blur-sm" onClick={() => setIsOpen(false)}>
      <div 
        className="w-full max-w-lg rounded-xl shadow-2xl overflow-hidden flex flex-col" 
        style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)' }}
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center px-4 border-b" style={{ borderColor: 'var(--color-border)' }}>
          <span style={{ color: 'var(--color-text-muted)' }}>🔍</span>
          <input 
            autoFocus
            className="w-full bg-transparent border-none outline-none p-4 text-sm"
            placeholder="Type a command or search..."
            value={query}
            onChange={e => setQuery(e.target.value)}
          />
          <div className="text-[10px] font-mono px-2 py-1 rounded" style={{ background: 'var(--color-surface-2)', color: 'var(--color-text-subtle)' }}>
            ESC
          </div>
        </div>
        <div className="max-h-80 overflow-y-auto p-2">
          {results.length === 0 && (
            <div className="p-4 text-center text-sm" style={{ color: 'var(--color-text-muted)' }}>
              No results found.
            </div>
          )}
          {results.map((route, i) => (
            <div 
              key={i}
              className="flex items-center justify-between p-3 rounded cursor-pointer hover:bg-white/5"
              onClick={() => {
                navigate(route.path);
                setIsOpen(false);
                setQuery('');
              }}
            >
              <div className="flex flex-col">
                <span className="text-sm font-medium">{route.name}</span>
                <span className="text-xs" style={{ color: 'var(--color-text-muted)' }}>{route.path}</span>
              </div>
              <span className="badge-info capitalize">{route.type}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

import React from 'react';

// ── PageHeader ──
interface PageHeaderProps {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
}

export const PageHeader: React.FC<PageHeaderProps> = ({ title, subtitle, actions }) => (
  <div className="page-header flex items-start justify-between">
    <div>
      <h1 className="page-title">{title}</h1>
      {subtitle && <p className="page-subtitle">{subtitle}</p>}
    </div>
    {actions && <div className="flex items-center gap-2 mt-1">{actions}</div>}
  </div>
);

// ── StatCard ──
interface StatCardProps {
  label: string;
  value: string | number;
  color?: 'primary' | 'success' | 'warning' | 'danger' | 'default';
  icon?: string;
  trend?: string;
}

export const StatCard: React.FC<StatCardProps> = ({ label, value, color = 'default', icon, trend }) => {
  const colorMap = {
    primary: 'var(--color-primary)',
    success: 'var(--color-success)',
    warning: 'var(--color-warning)',
    danger: 'var(--color-danger)',
    default: 'var(--color-text-main)',
  };

  return (
    <div className="stat-card">
      <div className="flex items-center justify-between mb-2">
        <span className="stat-label">{label}</span>
        {icon && <span className="text-xl opacity-40">{icon}</span>}
      </div>
      <div className="stat-value" style={{ color: colorMap[color] }}>{value}</div>
      {trend && <div className="text-xs mt-1" style={{ color: 'var(--color-text-subtle)' }}>{trend}</div>}
    </div>
  );
};

// ── EmptyState ──
interface EmptyStateProps {
  icon?: string;
  title: string;
  description?: string;
  action?: React.ReactNode;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ icon, title, description, action }) => (
  <div className="empty-state">
    {icon && <div className="empty-state-icon">{icon}</div>}
    <div className="empty-state-title">{title}</div>
    {description && <div className="empty-state-desc mt-1">{description}</div>}
    {action && <div className="mt-4">{action}</div>}
  </div>
);

// ── LoadingSpinner ──
interface LoadingSpinnerProps {
  text?: string;
  fullHeight?: boolean;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ text = 'Loading...', fullHeight = false }) => (
  <div className={`flex flex-col items-center justify-center gap-3 ${fullHeight ? 'h-64' : 'py-12'}`}>
    <div
      className="w-6 h-6 rounded-full animate-spin border-2 border-t-transparent"
      style={{ borderColor: 'var(--color-border)', borderTopColor: 'var(--color-primary)' }}
    />
    <span className="text-sm" style={{ color: 'var(--color-text-muted)' }}>{text}</span>
  </div>
);

// ── ErrorBanner ──
interface ErrorBannerProps {
  message: string;
  onDismiss?: () => void;
}

export const ErrorBanner: React.FC<ErrorBannerProps> = ({ message, onDismiss }) => (
  <div
    className="flex items-start gap-3 px-4 py-3 rounded-lg mb-4 border"
    style={{
      background: 'rgba(248,81,73,0.08)',
      borderColor: 'rgba(248,81,73,0.3)',
      color: 'var(--color-danger)',
    }}
  >
    <span className="mt-0.5 flex-shrink-0">⚠</span>
    <span className="text-sm flex-1">{message}</span>
    {onDismiss && (
      <button
        onClick={onDismiss}
        className="text-sm opacity-70 hover:opacity-100"
        style={{ background: 'none', border: 'none', color: 'inherit', padding: 0 }}
      >
        ✕
      </button>
    )}
  </div>
);

// ── SeverityBadge ──
export const SeverityBadge: React.FC<{ severity: string }> = ({ severity }) => {
  const classMap: Record<string, string> = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
  };
  return (
    <span className={classMap[severity?.toLowerCase()] || 'badge-info'}>
      {severity}
    </span>
  );
};

// ── StatusBadge ──
export const StatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const classMap: Record<string, string> = {
    running: 'badge-running',
    completed: 'badge-completed',
    failed: 'badge-failed',
    pending: 'badge-pending',
    queued: 'badge-pending',
  };
  return (
    <span className={classMap[status?.toLowerCase()] || 'badge-info'}>
      {status}
    </span>
  );
};

// ── SectionCard ──
interface SectionCardProps {
  title?: string;
  children: React.ReactNode;
  className?: string;
  headerRight?: React.ReactNode;
}

export const SectionCard: React.FC<SectionCardProps> = ({ title, children, className = '', headerRight }) => (
  <div className={`card ${className}`}>
    {title && (
      <div className="card-header">
        <span>{title}</span>
        {headerRight}
      </div>
    )}
    {children}
  </div>
);

// ── InfoRow ──
interface InfoRowProps {
  label: string;
  value: React.ReactNode;
}

export const InfoRow: React.FC<InfoRowProps> = ({ label, value }) => (
  <div className="flex items-center justify-between py-2 border-b" style={{ borderColor: 'var(--color-border)' }}>
    <span className="text-xs" style={{ color: 'var(--color-text-muted)' }}>{label}</span>
    <span className="text-sm font-medium" style={{ color: 'var(--color-text-main)' }}>{value}</span>
  </div>
);

// ── TypeTag ──
type RouteType = 'page' | 'api' | 'websocket' | 'security_file' | 'admin' | 'spa_route' | string;
export const RouteTypeBadge: React.FC<{ type: RouteType }> = ({ type }) => {
  const styles: Record<string, { bg: string; color: string }> = {
    api: { bg: 'rgba(88,166,255,0.1)', color: 'var(--color-primary)' },
    websocket: { bg: 'rgba(63,185,80,0.1)', color: 'var(--color-success)' },
    admin: { bg: 'rgba(248,81,73,0.1)', color: 'var(--color-danger)' },
    security_file: { bg: 'rgba(210,153,34,0.1)', color: 'var(--color-warning)' },
    spa_route: { bg: 'rgba(88,166,255,0.08)', color: 'var(--color-primary)' },
    page: { bg: 'rgba(255,255,255,0.04)', color: 'var(--color-text-muted)' },
  };
  const style = styles[type] || styles.page;
  return (
    <span
      className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide"
      style={{ background: style.bg, color: style.color }}
    >
      {type.replace('_', ' ')}
    </span>
  );
};

import React, { Suspense } from 'react';
import { Routes, Route } from 'react-router-dom';
import { Sidebar } from './components/Sidebar';
import { CommandPalette } from './components/CommandPalette';
import { LoadingSpinner } from './components/ui';

// Layouts
import { ScanLayout } from './layouts/ScanLayout';
import { OrgLayout } from './layouts/OrgLayout';
import { RuntimeLayout } from './layouts/RuntimeLayout';
import { SurfaceLayout } from './layouts/SurfaceLayout';

// Core pages (immediate load for perceived performance)
import { Dashboard } from './pages/Dashboard';
import { ScanList } from './pages/ScanList';

// Lazy loaded pages
const ActivityPage = React.lazy(() => import('./pages/ActivityPage').then(m => ({ default: m.ActivityPage })));
const FindingsGlobal = React.lazy(() => import('./pages/findings/FindingsGlobal').then(m => ({ default: m.FindingsGlobal })));

// Scan pages
const ScanDetails = React.lazy(() => import('./pages/ScanDetails').then(m => ({ default: m.ScanDetails })));
const ScanFindings = React.lazy(() => import('./pages/scan/ScanFindings').then(m => ({ default: m.ScanFindings })));
const ScanReplays = React.lazy(() => import('./pages/scan/ScanReplays').then(m => ({ default: m.ScanReplays })));
const ScanAttackPaths = React.lazy(() => import('./pages/scan/ScanAttackPaths').then(m => ({ default: m.ScanAttackPaths })));
const ScanIntelligence = React.lazy(() => import('./pages/scan/ScanIntelligence').then(m => ({ default: m.ScanIntelligence })));
const ScanRoutes = React.lazy(() => import('./pages/scan/ScanRoutes').then(m => ({ default: m.ScanRoutes })));
const ScanRuntime = React.lazy(() => import('./pages/scan/ScanRuntime').then(m => ({ default: m.ScanRuntime })));

// Surface pages
const SurfaceExplorer = React.lazy(() => import('./pages/surface/SurfaceExplorer').then(m => ({ default: m.SurfaceExplorer })));
const SurfaceRoutes = React.lazy(() => import('./pages/surface/SurfaceRoutes').then(m => ({ default: m.SurfaceRoutes })));
const SurfaceApis = React.lazy(() => import('./pages/surface/SurfaceApis').then(m => ({ default: m.SurfaceApis })));
const SurfaceSecurityFiles = React.lazy(() => import('./pages/surface/SurfaceSecurityFiles').then(m => ({ default: m.SurfaceSecurityFiles })));
const SurfaceWebSockets = React.lazy(() => import('./pages/surface/SurfaceWebSockets').then(m => ({ default: m.SurfaceWebSockets })));

// Browser pages
const BrowserOverview = React.lazy(() => import('./pages/browser/BrowserOverview').then(m => ({ default: m.BrowserOverview })));
const DomSinks = React.lazy(() => import('./pages/browser/DomSinks').then(m => ({ default: m.DomSinks })));
const StoragePage = React.lazy(() => import('./pages/browser/StoragePage').then(m => ({ default: m.StoragePage })));

// Intelligence pages
const IntelligenceOverview = React.lazy(() => import('./pages/intelligence/IntelligenceOverview').then(m => ({ default: m.IntelligenceOverview })));
const Deduplication = React.lazy(() => import('./pages/intelligence/Deduplication').then(m => ({ default: m.Deduplication })));
const Explanations = React.lazy(() => import('./pages/intelligence/Explanations').then(m => ({ default: m.Explanations })));

// Runtime pages
const RuntimeOverview = React.lazy(() => import('./pages/runtime/RuntimeOverview').then(m => ({ default: m.RuntimeOverview })));
const Workers = React.lazy(() => import('./pages/runtime/Workers').then(m => ({ default: m.Workers })));
const Queues = React.lazy(() => import('./pages/runtime/Queues').then(m => ({ default: m.Queues })));
const Checkpoints = React.lazy(() => import('./pages/runtime/Checkpoints').then(m => ({ default: m.Checkpoints })));
const RealtimeDashboard = React.lazy(() => import('./pages/RealtimeDashboard').then(m => ({ default: m.RealtimeDashboard })));

// Org pages
const OrgDashboard = React.lazy(() => import('./pages/OrgDashboard').then(m => ({ default: m.OrgDashboard })));
const OrgMembers = React.lazy(() => import('./pages/org/OrgMembers').then(m => ({ default: m.OrgMembers })));
const OrgAuditLogs = React.lazy(() => import('./pages/org/OrgAuditLogs').then(m => ({ default: m.OrgAuditLogs })));
const OrgSettings = React.lazy(() => import('./pages/org/OrgSettings').then(m => ({ default: m.OrgSettings })));

// Benchmarks & Settings
const BenchmarksDashboard = React.lazy(() => import('./pages/benchmarks/BenchmarksDashboard').then(m => ({ default: m.BenchmarksDashboard })));
const Settings = React.lazy(() => import('./pages/settings/Settings').then(m => ({ default: m.Settings })));
const ApiSettings = React.lazy(() => import('./pages/settings/ApiSettings').then(m => ({ default: m.ApiSettings })));

// Fallback loader for suspense boundaries
const PageLoader = () => (
  <div className="flex-1 flex items-center justify-center">
    <div className="flex flex-col items-center gap-3 text-textMuted">
      <div className="w-6 h-6 rounded-full border-2 border-primary border-t-transparent animate-spin" />
      <span className="text-xs">Loading module...</span>
    </div>
  </div>
);

// Fallback for not-yet-implemented routes
const Placeholder = ({ title }: { title: string }) => (
  <div className="flex flex-col h-full items-center justify-center text-textMuted gap-2">
    <span className="text-2xl opacity-50">🚧</span>
    <h3 className="font-semibold text-textMain">{title}</h3>
    <p className="text-sm">This operational view is under construction.</p>
  </div>
);

export const App: React.FC = () => {
  return (
    <div className="app-shell">
      <Sidebar />
      <CommandPalette />

      <main className="app-main">
        <div className="app-content">
          <Suspense fallback={<PageLoader />}>
            <Routes>
              {/* Dashboard & Core */}
              <Route path="/" element={<Dashboard />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/overview" element={<Dashboard />} />
              <Route path="/activity" element={<ActivityPage />} />
              <Route path="/notifications" element={<Placeholder title="Notifications" />} />

              {/* Scan Management - Uses ScanLayout */}
              <Route path="/scans" element={<ScanList />} />
              <Route path="/scans/:id" element={<ScanLayout />}>
                <Route index element={<ScanDetails />} />
                <Route path="findings" element={<ScanFindings />} />
                <Route path="replays" element={<ScanReplays />} />
                <Route path="attack-paths" element={<ScanAttackPaths />} />
                <Route path="routes" element={<ScanRoutes />} />
                <Route path="browser" element={<Placeholder title="Scan Browser Context" />} />
                <Route path="intelligence" element={<ScanIntelligence />} />
                <Route path="runtime" element={<ScanRuntime />} />
                <Route path="websockets" element={<Placeholder title="Scan WebSockets Context" />} />
                <Route path="storage" element={<Placeholder title="Scan Storage Context" />} />
                <Route path="correlation" element={<Placeholder title="Frontend/Backend Correlation" />} />
              </Route>
              {/* Legacy fallback */}
              <Route path="/scan/:id" element={<ScanDetails />} />

              {/* Findings */}
              <Route path="/findings" element={<FindingsGlobal />} />
              <Route path="/findings/:id" element={<Placeholder title="Finding Details" />} />
              <Route path="/findings/reliability" element={<Placeholder title="Reliability Analysis" />} />
              <Route path="/findings/replays" element={<ScanReplays />} />
              <Route path="/findings/explanations" element={<Explanations />} />

              {/* Surface Inventory - Uses SurfaceLayout */}
              <Route path="/surface" element={<SurfaceLayout />}>
                <Route index element={<SurfaceExplorer />} />
                <Route path="routes" element={<SurfaceRoutes />} />
                <Route path="apis" element={<SurfaceApis />} />
                <Route path="security-files" element={<SurfaceSecurityFiles />} />
                <Route path="websockets" element={<SurfaceWebSockets />} />
                <Route path="spa-routes" element={<Placeholder title="SPA Route Inference" />} />
              </Route>

              {/* Browser Recon */}
              <Route path="/browser" element={<BrowserOverview />} />
              <Route path="/browser/routes" element={<Placeholder title="Global Browser Routes" />} />
              <Route path="/browser/dom-sinks" element={<DomSinks />} />
              <Route path="/browser/storage" element={<StoragePage />} />
              <Route path="/browser/apis" element={<Placeholder title="Global Browser APIs" />} />

              {/* AI / Intelligence */}
              <Route path="/intelligence" element={<IntelligenceOverview />} />
              <Route path="/intelligence/deduplication" element={<Deduplication />} />
              <Route path="/intelligence/prioritization" element={<Placeholder title="Prioritization Engine" />} />
              <Route path="/intelligence/explanations" element={<Explanations />} />

              {/* Queue & Runtime - Uses RuntimeLayout */}
              <Route path="/runtime" element={<RuntimeLayout />}>
                <Route index element={<RuntimeOverview />} />
                <Route path="workers" element={<Workers />} />
                <Route path="queues" element={<Queues />} />
                <Route path="checkpoints" element={<Checkpoints />} />
                <Route path="telemetry" element={<RealtimeDashboard />} />
              </Route>

              {/* Organization - Uses OrgLayout */}
              <Route path="/org" element={<OrgLayout />}>
                <Route index element={<OrgDashboard />} />
                <Route path="members" element={<OrgMembers />} />
                <Route path="quotas" element={<Placeholder title="Quotas & Usage" />} />
                <Route path="audit" element={<OrgAuditLogs />} />
                <Route path="settings" element={<OrgSettings />} />
              </Route>

              {/* Benchmarks */}
              <Route path="/benchmarks" element={<BenchmarksDashboard />} />
              <Route path="/benchmarks/juice-shop" element={<BenchmarksDashboard />} />
              <Route path="/benchmarks/dvwa" element={<BenchmarksDashboard />} />
              <Route path="/benchmarks/webgoat" element={<BenchmarksDashboard />} />

              {/* Settings */}
              <Route path="/settings" element={<Settings />} />
              <Route path="/settings/profile" element={<Placeholder title="User Profile" />} />
              <Route path="/settings/security" element={<Placeholder title="Personal Security" />} />
              <Route path="/settings/api" element={<ApiSettings />} />
              <Route path="/settings/preferences" element={<Placeholder title="App Preferences" />} />
            </Routes>
          </Suspense>
        </div>
      </main>
    </div>
  );
};

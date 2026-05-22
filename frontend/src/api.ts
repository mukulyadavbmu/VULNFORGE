const API_BASE_URL =
  (import.meta as any).env.VITE_API_BASE_URL || 'http://localhost:4000';
const API_KEY = (import.meta as any).env.VITE_VULNFORGE_API_KEY || 'change_me_for_prod';

async function request<T = unknown>(path: string, options: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem('vulnforge_token');
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'x-vulnforge-api-key': API_KEY,
    ...(options.headers as Record<string, string> || {}),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  });

  // Auto-logout on 401 (expired session)
  if (res.status === 401) {
    localStorage.removeItem('vulnforge_token');
    localStorage.removeItem('vulnforge_user');
    if (!window.location.pathname.includes('/login')) {
      window.location.href = '/login';
    }
    throw new Error('Session expired. Please log in again.');
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

// ─────────────────────────────────────────
// Scan DTOs
// ─────────────────────────────────────────

export interface ScanSummary {
  id: string;
  targetUrl: string;
  status: string;
  createdAt: number;
  findingCount: number;
}

export interface ScanSessionDto {
  id: string;
  targetUrl: string;
  status: string;
  createdAt: number;
  findings: any[];
  actions: any[];
  attackNodes: Record<string, any>;
  hypotheses?: any[];
}

export interface ScanEventDto {
  timestamp: number;
  message: string;
  type: 'info' | 'success' | 'warning' | 'attack' | 'recon';
}

export interface ProgressData {
  currentPhase: string;
  currentAction: string;
  events: ScanEventDto[];
}

export interface SummaryData {
  endpoints: number;
  sensitivePaths: number;
  vulnerabilities: number;
  criticalFindings: number;
  highFindings: number;
  confirmedExploits: number;
}

export interface ExploitExplanationDto {
  title: string;
  description: string;
  attackSteps: string[];
  examplePayload: string;
  impact: string;
}

export interface ExploitableIssueDto {
  id: string;
  type: string;
  severity: string;
  endpoint: string;
  explanation: ExploitExplanationDto;
  exploitSteps: string[];
  reliabilityScore: number;
  trace?: any; // ReplayTrace from ReplayViewer
}

// ─────────────────────────────────────────
// Surface Inventory DTOs
// ─────────────────────────────────────────

export interface DiscoveredRoute {
  id: string;
  url: string;
  method?: string;
  type: 'page' | 'api' | 'websocket' | 'static' | 'security_file' | 'admin' | 'spa_route';
  authRequired: boolean;
  sensitivity: 'public' | 'sensitive' | 'admin' | 'unknown';
  discoverySource: 'crawl' | 'js_analysis' | 'network' | 'probe' | 'robots' | 'sitemap';
  statusCode?: number;
  tags: string[];
  crawlDepth: number;
  discoveredAt: number;
}

export interface SecurityFile {
  url: string;
  type: 'robots_txt' | 'sitemap_xml' | 'security_txt' | 'well_known' | 'openapi' | 'graphql' | 'admin' | 'backup';
  status: number;
  exists: boolean;
  content?: string;
  parsedData?: Record<string, any>;
  discoveredAt: number;
}

export interface SurfaceSummary {
  totalRoutes: number;
  publicRoutes: number;
  authGatedRoutes: number;
  sensitiveRoutes: number;
  adminRoutes: number;
  apiEndpoints: number;
  websockets: number;
  spaRoutes: number;
  securityFiles: number;
  crawlDepth: number;
  coverageScore: number;
}

// ─────────────────────────────────────────
// Scan Management APIs
// ─────────────────────────────────────────

export async function createScan(targetUrl: string) {
  return request<{ scanId: string }>('/scan', {
    method: 'POST',
    body: JSON.stringify({ targetUrl }),
  });
}

export async function listScans() {
  return request<ScanSummary[]>('/scan');
}

export async function getScan(id: string) {
  return request<ScanSessionDto>(`/scan/${id}`);
}

export async function planScan(id: string) {
  return request<{ actions: any[] }>(`/scan/${id}/plan`, { method: 'POST' });
}

export async function executeActionApi(id: string, actionId: string) {
  return request<{ ok: boolean }>(`/scan/${id}/execute`, {
    method: 'POST',
    body: JSON.stringify({ actionId }),
  });
}

export async function setAuthHeaders(
  id: string,
  context: 'guest' | 'userA' | 'userB',
  headers: Record<string, string>,
) {
  return request<{ ok: boolean }>(`/scan/${id}/auth`, {
    method: 'POST',
    body: JSON.stringify({ context, headers }),
  });
}

// ─────────────────────────────────────────
// Real-Time Progress APIs
// ─────────────────────────────────────────

export async function getScanProgress(id: string) {
  return request<ProgressData>(`/scan/${id}/progress`);
}

export async function getScanSummary(id: string) {
  return request<SummaryData>(`/scan/${id}/summary`);
}

// ─────────────────────────────────────────
// Exploitable Issues API
// ─────────────────────────────────────────

export async function getExploitableIssues(id: string) {
  return request<ExploitableIssueDto[]>(`/scan/${id}/exploitable-issues`);
}

// ─────────────────────────────────────────
// Surface Inventory APIs
// ─────────────────────────────────────────

export async function getScanSurface(id: string) {
  return request<DiscoveredRoute[]>(`/scan/${id}/surface`);
}

export async function getScanSurfaceSummary(id: string) {
  return request<SurfaceSummary>(`/scan/${id}/surface/summary`);
}

export async function getScanSecurityFiles(id: string) {
  return request<SecurityFile[]>(`/scan/${id}/security-files`);
}

export async function getScanAttackPaths(id: string) {
  return request<any[]>(`/scan/${id}/attack-paths`);
}

export async function getScanIntelligence(id: string) {
  return request<any[]>(`/scan/${id}/intelligence`);
}

export async function getScanDeduplication(id: string) {
  return request<any[]>(`/scan/${id}/deduplication`);
}

export async function getScanExplanations(id: string) {
  return request<any[]>(`/scan/${id}/explanations`);
}

export async function getScanState(id: string) {
  return request<any>(`/scan/${id}/state`);
}

// ─────────────────────────────────────────
// Auth & SaaS APIs
// ─────────────────────────────────────────

export async function login(email: string, passwordRaw: string) {
  return request<{ token: string; user: any }>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password: passwordRaw }),
  });
}

export async function register(email: string, passwordRaw: string, name?: string) {
  return request<{ message: string; userId: string }>('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, password: passwordRaw, name }),
  });
}

// ─────────────────────────────────────────
// Organization APIs
// ─────────────────────────────────────────

export async function getOrgMetrics(orgId: string) {
  return request<any>(`/org/${orgId}/metrics`);
}

export async function getOrgAuditLogs(orgId: string) {
  return request<any[]>(`/org/${orgId}/audit`);
}

export async function getOrgMembers(orgId: string) {
  return request<any[]>(`/org/${orgId}/members`);
}

// ─────────────────────────────────────────
// Benchmark APIs
// ─────────────────────────────────────────

export async function getBenchmarkProfiles() {
  return request<any[]>('/benchmark/profiles');
}

export async function runBenchmark(profile: string, targetUrl: string) {
  return request<any>(`/benchmark/run/${profile}`, {
    method: 'POST',
    body: JSON.stringify({ targetUrl }),
  });
}

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || 'http://localhost:4000';
const API_KEY = import.meta.env.VITE_VULNFORGE_API_KEY || 'change_me_for_prod';

async function request(path: string, options: RequestInit = {}) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'x-vulnforge-api-key': API_KEY,
      ...(options.headers || {}),
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json();
}

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
}

export async function createScan(targetUrl: string) {
  return request('/scan', {
    method: 'POST',
    body: JSON.stringify({ targetUrl }),
  }) as Promise<{ scanId: string }>;
}

export async function listScans() {
  return request('/scan') as Promise<ScanSummary[]>;
}

export async function getScan(id: string) {
  return request(`/scan/${id}`) as Promise<ScanSessionDto>;
}

export async function planScan(id: string) {
  return request(`/scan/${id}/plan`, { method: 'POST' }) as Promise<{
    actions: any[];
  }>;
}

export async function executeActionApi(id: string, actionId: string) {
  return request(`/scan/${id}/execute`, {
    method: 'POST',
    body: JSON.stringify({ actionId }),
  }) as Promise<{ ok: boolean }>;
}

export async function setAuthHeaders(
  id: string,
  context: 'guest' | 'userA' | 'userB',
  headers: Record<string, string>,
) {
  return request(`/scan/${id}/auth`, {
    method: 'POST',
    body: JSON.stringify({ context, headers }),
  }) as Promise<{ ok: boolean }>;
}

